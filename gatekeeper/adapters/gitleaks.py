"""Adapter gitleaksa.

Dwie rzeczy, na które trzeba uważać w adapterze skanera sekretów:

* **Raport nigdy nie może zawierać sekretu w jawnej postaci.** Trafia do
  komentarza w PR, czyli do miejsca dostępnego dla większej liczby osób niż
  plik, z którego pochodzi. Redakcja jest tu funkcją bezpieczeństwa, nie
  kosmetyką.
* Parsowanie jest czystą funkcją (`parse_report`), żeby dało się je testować
  na zapisanej próbce wyjścia — adaptery psują się przy zmianie wersji
  narzędzia i tylko golden file to wychwyci (TOOLS.md §9).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from ..core.finding import Finding, Severity

BINARY = "gitleaks"
INSTALL_HINT = (
    "zainstaluj gitleaks (https://github.com/gitleaks/gitleaks/releases) "
    "albo ustaw `gates: {G3.secrets: {require_tool: false}}` w polityce"
)


class ToolMissing(RuntimeError):
    pass


class ToolFailed(RuntimeError):
    pass


@dataclass(frozen=True)
class Leak:
    rule_id: str
    description: str
    file: str
    line: int
    redacted: str
    entropy: float | None
    tool_fingerprint: str


def redact(secret: str) -> str:
    """`ghp_abcdef123456` → `ghp_…(20 znaków)`."""
    secret = (secret or "").strip()
    if not secret:
        return "—"
    head = secret[:4]
    return f"{head}…({len(secret)} znaków)"


def is_available() -> bool:
    return shutil.which(BINARY) is not None


def version() -> str | None:
    if not is_available():
        return None
    proc = subprocess.run([BINARY, "version"], capture_output=True, text=True, check=False)
    return proc.stdout.strip() or None


def parse_report(payload: str, root: Path | str | None = None) -> list[Leak]:
    """`root` jest obowiązkowy przy skanie po ścieżce bezwzględnej.

    gitleaks zwraca ścieżki w takiej postaci, w jakiej dostał `--source`.
    Bez sprowadzenia ich do ścieżek względnych repozytorium porównanie
    z listą zmienionych plików zawsze zwraca „brak trafienia" — a wtedy sekret
    wprowadzony w tym PR wygląda jak zastany i nie blokuje niczego.
    """
    if not payload.strip():
        return []
    data = json.loads(payload)
    if isinstance(data, dict):  # niektóre wersje pakują listę w obiekt
        data = data.get("findings") or data.get("Findings") or []
    leaks: list[Leak] = []
    for item in data:
        leaks.append(
            Leak(
                rule_id=str(item.get("RuleID") or item.get("rule_id") or "unknown"),
                description=str(item.get("Description") or "").strip(),
                file=_normalize_path(str(item.get("File") or ""), root),
                line=int(item.get("StartLine") or 0),
                redacted=redact(str(item.get("Secret") or item.get("Match") or "")),
                entropy=_maybe_float(item.get("Entropy")),
                tool_fingerprint=str(item.get("Fingerprint") or ""),
            )
        )
    return leaks


def scan(
    source: Path,
    config_path: Path | None = None,
    extra_args: list[str] | None = None,
    timeout_s: float = 300.0,
) -> list[Leak]:
    """Skan katalogu roboczego (bez historii gita — tę pokrywa osobny job)."""
    if not is_available():
        raise ToolMissing(INSTALL_HINT)
    with tempfile.TemporaryDirectory(prefix="gitleaks-") as tmp:
        report = Path(tmp) / "report.json"
        cmd = [
            BINARY,
            "detect",
            "--source",
            str(source),
            "--no-git",
            "--no-banner",
            "--redact",  # dodatkowy pas bezpieczeństwa po stronie narzędzia
            "--report-format",
            "json",
            "--report-path",
            str(report),
            "--exit-code",
            "0",  # znalezione sekrety to nie awaria narzędzia
        ]
        if config_path:
            cmd += ["--config", str(config_path)]
        cmd += extra_args or []
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout_s, check=False
            )
        except subprocess.TimeoutExpired as exc:
            raise ToolFailed(f"gitleaks przekroczył limit {timeout_s:g}s") from exc
        if proc.returncode != 0:
            raise ToolFailed(
                f"gitleaks zakończył się kodem {proc.returncode}: {proc.stderr[-500:]}"
            )
        if not report.exists():
            return []
        return parse_report(report.read_text(encoding="utf-8"), root=source)


def to_finding(leak: Leak, gate_id: str, in_diff: bool) -> Finding:
    """Sekret w zmienionych plikach blokuje; zastany idzie do długu."""
    if in_diff:
        scenario = (
            "Sekret trafia do historii gita w tym PR. Od momentu merge'a jest dostępny dla "
            "każdego z dostępem do repozytorium i dla każdego klona — rotacja klucza jest "
            "jedynym skutecznym środkiem zaradczym, samo usunięcie linii nie wystarczy."
        )
        severity = Severity.CRITICAL
    else:
        scenario = (
            "Sekret istniał w repozytorium przed tą zmianą. Nie blokuje tego PR-a, ale "
            "dopóki nie zostanie zrotowany, jest ważnym poświadczeniem w rękach każdego, "
            "kto ma dostęp do historii."
        )
        severity = Severity.MEDIUM
    return Finding(
        gate=gate_id,
        rule_id="secrets.found_in_diff" if in_diff else "secrets.preexisting",
        severity=severity,
        title=f"{leak.description or leak.rule_id} w `{leak.file}`",
        failure_scenario=scenario,
        file=leak.file,
        line=leak.line or None,
        evidence={
            "snippet": f"{leak.rule_id}:{leak.redacted}",
            "gitleaks_rule": leak.rule_id,
            "redacted": leak.redacted,
            "entropy": leak.entropy,
            "tool_fingerprint": leak.tool_fingerprint,
        },
    )


def _normalize_path(path: str, root: Path | str | None = None) -> str:
    if not path:
        return ""
    candidate = Path(path)
    if root is not None:
        try:
            return candidate.resolve().relative_to(Path(root).resolve()).as_posix()
        except ValueError:
            pass  # znalezisko spoza katalogu skanowania — zostawiamy jak jest
    if candidate.is_absolute():
        return candidate.as_posix()
    return PurePosixPath(path.removeprefix("./")).as_posix()


def _maybe_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
