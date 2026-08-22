"""Adapter .NET: `dotnet build` (G1.static) i odnajdywanie projektów.

`dotnet build` pełni dla C# podwójną rolę ruff+mypy naraz — sam kompilator
Roslyna jest kontrolą typów w trybie ścisłym, więc nie ma osobnego narzędzia
do wywołania. Format diagnostyk jest ten sam co u tsc (MSBuild i tsc dzielą
konwencję `plik(linia,kolumna): poziom KODxxxx: treść`), z dopisanym na końcu
projektem źródłowym w nawiasach kwadratowych — stąd wspólny parser w
`adapters/base.py::parse_compiler_diagnostics`.

Zakłada się, że `dotnet restore` już się odbył (tak samo jak G2.cross_verify
zakłada zainstalowane zależności testowe Pythona) — bramka nie ma prawa
sama ściągać pakietów, bo to jedyne miejsce w G1 z dostępem do sieci, którego
tu świadomie nie chcemy.

**Sandbox musi dostać `memory_mb=None`.** CoreCLR (runtime .NET-a) rezerwuje
kilka GB przestrzeni adresowej na starcie niezależnie od realnego zużycia —
dokładnie ten sam kwirk co silnik OCaml semgrepa (`gates/g3_sast.py`).
Twardy `RLIMIT_AS` z domyślnej `SandboxPolicy` zabija `dotnet` kodem 137
(`GC heap initialization failed`) zamiast czytelnego błędu, zweryfikowane
na żywym SDK, nie z dokumentacji.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..core.finding import Finding, Severity
from ..core.runner import Sandbox
from .base import parse_compiler_diagnostics, relative_to_repo, run_tool

DOTNET = "dotnet"


def find_project_for(repo: Path, file_path: str) -> str | None:
    """Najbliższy przodkowy `.csproj`/`.fsproj` zmienionego pliku `.cs`.

    Szuka w górę od katalogu pliku do korzenia repo — tak jak MSBuild sam
    dopasowuje plik źródłowy do projektu, który go kompiluje. Zwraca ścieżkę
    względną wobec repo, albo `None`, gdy żaden projekt go nie obejmuje.
    """
    current = (repo / file_path).resolve().parent
    root = repo.resolve()
    while True:
        matches = sorted(current.glob("*.csproj")) + sorted(current.glob("*.fsproj"))
        if matches:
            try:
                return matches[0].relative_to(root).as_posix()
            except ValueError:
                return None
        if current == root or current.parent == current:
            return None
        current = current.parent


def projects_for(repo: Path, file_paths: list[str]) -> list[str]:
    """Unikalny, posortowany zestaw projektów dotkniętych zmienionymi plikami."""
    found = {find_project_for(repo, path) for path in file_paths}
    return sorted(p for p in found if p is not None)


def dotnet_build_scenario(level: str, code: str, message: str) -> str:
    return (
        f"Kompilator C# zgłasza `{code}`: {message}. W kodzie od agenta ta klasa błędów "
        "zwykle oznacza wywołanie API, którego nie ma, albo argument o innym typie — czyli "
        "kod, który nie da się nawet zbudować, nie mówiąc o uruchomieniu."
    )


def parse_dotnet_build(payload: str, repo: Path, gate: str) -> list[Finding]:
    def severity_of(level: str, code: str) -> Severity:
        return Severity.HIGH if level == "error" else Severity.MEDIUM

    return parse_compiler_diagnostics(
        payload, repo, gate, "dotnet", dotnet_build_scenario, severity_of
    )


def run_dotnet_build(
    repo: Path,
    sandbox: Sandbox,
    gate: str,
    project: str,
    timeout_s: float = 180.0,
    args: list[str] | None = None,
) -> list[Finding]:
    command = [
        DOTNET,
        "build",
        project,
        "--no-restore",
        "-v",
        "quiet",
        "/clp:NoSummary",
        *(args or []),
    ]
    # dotnet build: 0 = czysto (mogą być ostrzeżenia), 1 = błędy kompilacji
    result = run_tool(command, repo, sandbox, timeout_s, ok_returncodes=(0, 1))
    return parse_dotnet_build(result.stdout, repo, gate)


# --------------------------------------------------------------------------
# `dotnet list package --vulnerable` — G3.sca
# --------------------------------------------------------------------------


def parse_dotnet_list_vulnerable(
    payload: str, repo: Path, new_packages: set[str], gate: str
) -> list[Finding]:
    """`dotnet list package --vulnerable --format json` → `Finding`.

    Filtrowane do `new_packages` (znormalizowane, małe litery id-y NuGet) —
    tak samo jak `parse_pip_audit`: dług w zastanych zależnościach to osobny
    raport, nie blokada tego PR-a. Format obejmuje zarówno pakiety
    bezpośrednie (`topLevelPackages`), jak i tranzytywne (`transitivePackages`)
    — oba mają ten sam kształt wpisu.
    """
    try:
        data = json.loads(payload or "{}")
    except json.JSONDecodeError:
        return []
    findings: list[Finding] = []
    for project in data.get("projects") or []:
        project_path = relative_to_repo(str(project.get("path") or ""), repo)
        for framework in project.get("frameworks") or []:
            packages = (framework.get("topLevelPackages") or []) + (
                framework.get("transitivePackages") or []
            )
            for pkg in packages:
                name = str(pkg.get("id") or "")
                if name.lower() not in new_packages:
                    continue
                version = str(pkg.get("resolvedVersion") or pkg.get("requestedVersion") or "?")
                for vuln in pkg.get("vulnerabilities") or []:
                    url = str(vuln.get("advisoryurl") or "")
                    advisory_id = url.rsplit("/", 1)[-1] or "unknown"
                    severity = str(vuln.get("severity") or "High")
                    findings.append(
                        Finding(
                            gate=gate,
                            rule_id=f"sca.{advisory_id}",
                            severity=Severity.HIGH,
                            title=f"{name}=={version}: {advisory_id}",
                            failure_scenario=(
                                f"Nowo dodany pakiet NuGet `{name}` w wersji `{version}` ma "
                                f"znaną podatność {severity.lower()} ({url or 'brak URL-a'}). "
                                "To dług wnoszony do repozytorium w tym PR-ze, nie coś, co już "
                                "w nim było — instalacja tej wersji naraża produkcję na lukę, "
                                "która ma już publiczny identyfikator."
                            ),
                            file=project_path,
                            evidence={
                                "snippet": f"{name}=={version}:{advisory_id}",
                                "package": name,
                                "version": version,
                                "advisory_severity": severity,
                                "url": url,
                            },
                        )
                    )
    return findings


def run_dotnet_list_vulnerable(
    repo: Path,
    sandbox: Sandbox,
    gate: str,
    project: str,
    new_packages: set[str],
    timeout_s: float = 180.0,
) -> list[Finding]:
    command = [
        DOTNET,
        "list",
        project,
        "package",
        "--vulnerable",
        "--include-transitive",
        "--format",
        "json",
    ]
    # `dotnet list package`: 0 zawsze, niezależnie od tego, czy znalazł
    # podatności — trzeba czytać JSON, nie kod wyjścia.
    result = run_tool(command, repo, sandbox, timeout_s, network=True, ok_returncodes=(0,))
    return parse_dotnet_list_vulnerable(result.stdout, repo, new_packages, gate)
