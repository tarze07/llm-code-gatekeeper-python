"""G1 — poprawność statyczna: ruff+mypy (Python), tsc+eslint (TS/JS),
`dotnet build` (C#) na zmienionych plikach.

Typy w trybie strict wyłapują dużą część halucynacji API agenta — wywołanie
metody, której nie ma, albo argumentu o innej nazwie (TOOLS.md §3). To tania
bramka o wysokiej trafności, więc wchodzi w kamieniu 3, a nie później.
`tsc`/`dotnet build` pełnią dla TS/C# dokładnie tę samą rolę, co `mypy` dla
Pythona — kompilator w trybie strict *jest* kontrolą typów.

Jedyna nietrywialna decyzja (TOOLS.md §3.1): raportujemy tylko znaleziska
w zmienionych liniach (+3 linie kontekstu, `only_changed_lines`) — inaczej
pierwszy przebieg na starszym repo daje tysiące błędów mypy i projekt
umiera w dniu wdrożenia. Dług istniejącego kodu to osobny raport.

Jedna bramka, jeden `GateResult`, niezależnie od tego, ile języków dotyka
diff — polityka i `warn_only` nie muszą znać podziału na język. Każde
narzędzie ma jednak własny przełącznik `require_*`: ruff jest uniwersalny
i szybki, więc jego brak jest błędem bramki (`error`) domyślnie; reszta
(mypy, tsc, eslint, dotnet build) bywa nieskonfigurowana w wielu repo —
domyślnie jej brak jest tylko brakiem dowodu z tego narzędzia, nie blokadą.
"""

from __future__ import annotations

import time
from typing import Any

from ..adapters import dotnet
from ..adapters.base import ToolFailed, ToolMissing, only_changed_lines
from ..adapters.linters import run_eslint, run_mypy, run_ruff, run_tsc
from ..core.change import ChangeContext
from ..core.finding import Finding, GateResult, Severity
from ..core.runner import Sandbox, SandboxPolicy
from . import Gate, register

_ESLINT_CONFIG_NAMES = (
    ".eslintrc.js",
    ".eslintrc.cjs",
    ".eslintrc.json",
    ".eslintrc.yaml",
    ".eslintrc.yml",
    "eslint.config.js",
    "eslint.config.mjs",
    "eslint.config.cjs",
    "eslint.config.ts",
)


@register
class StaticGuard(Gate):
    id = "G1.static"
    name = "Poprawność statyczna (ruff/mypy, tsc/eslint, dotnet build)"
    budget_s = 180.0
    facts = (
        "static.python_files_checked",
        "static.ruff_available",
        "static.mypy_available",
        "static.ts_files_checked",
        "static.tsconfig_found",
        "static.tsc_available",
        "static.js_files_checked",
        "static.eslint_config_found",
        "static.eslint_available",
        "static.csharp_files_checked",
        "static.csproj_found",
        "static.dotnet_available",
        "static.finding_count",
        "static.high_severity_count",
    )

    def run(self, change: ChangeContext) -> GateResult:
        started = time.monotonic()
        facts = _empty_facts()
        findings: list[Finding] = []

        outcome = self._run_python(change, facts, findings)
        if outcome is not None:
            return self._error(change, started, facts, findings, outcome)

        outcome = self._run_ts_js(change, facts, findings)
        if outcome is not None:
            return self._error(change, started, facts, findings, outcome)

        outcome = self._run_csharp(change, facts, findings)
        if outcome is not None:
            return self._error(change, started, facts, findings, outcome)

        findings = only_changed_lines(findings, change)
        high = [f for f in findings if f.severity >= Severity.HIGH]
        facts["static.finding_count"] = len(findings)
        facts["static.high_severity_count"] = len(high)

        return self.result(
            status="fail" if high else "pass",
            duration_s=time.monotonic() - started,
            facts=facts,
            findings=findings,
            message=f"{len(findings)} znalezisk w zmienionych liniach ({len(high)} wysokiej wagi)",
        )

    # ------------------------------------------------------------------ python

    def _run_python(
        self, change: ChangeContext, facts: dict[str, Any], findings: list[Finding]
    ) -> str | None:
        python_files = [
            f.path for f in change.effective_files if f.language == "python" and f.status != "D"
        ]
        facts["static.python_files_checked"] = len(python_files)
        if not python_files:
            return None

        require_ruff = bool(self.config.get("require_ruff", True))
        require_mypy = bool(self.config.get("require_mypy", False))
        sandbox = self._sandbox()

        try:
            findings.extend(run_ruff(change.repo, sandbox, self.id, timeout_s=self.budget_s / 4))
        except ToolMissing as exc:
            facts["static.ruff_available"] = False
            if require_ruff:
                # Brak narzędzia nie jest zieloną bramką — to brak dowodu.
                return str(exc)
        except ToolFailed as exc:
            return str(exc)

        try:
            findings.extend(
                run_mypy(
                    change.repo,
                    sandbox,
                    self.id,
                    targets=python_files,
                    timeout_s=self.budget_s / 4,
                    args=list(self.config.get("mypy_args", [])),
                )
            )
        except ToolMissing as exc:
            facts["static.mypy_available"] = False
            if require_mypy:
                return str(exc)
        except ToolFailed as exc:
            if require_mypy:
                return str(exc)
            # mypy potrafi się wywrócić na błędzie konfiguracji (target spoza
            # pakietu, brak stubów) — bez `require_mypy` to brak dowodu z tego
            # narzędzia, nie defekt w kodzie PR-a.
            facts["static.mypy_available"] = False
        return None

    # ---------------------------------------------------------------- ts/js

    def _run_ts_js(
        self, change: ChangeContext, facts: dict[str, Any], findings: list[Finding]
    ) -> str | None:
        ts_files = [
            f.path for f in change.effective_files if f.language == "typescript" and f.status != "D"
        ]
        js_files = [
            f.path for f in change.effective_files if f.language == "javascript" and f.status != "D"
        ]
        facts["static.ts_files_checked"] = len(ts_files)
        facts["static.js_files_checked"] = len(js_files)

        require_tsc = bool(self.config.get("require_tsc", False))
        require_eslint = bool(self.config.get("require_eslint", False))
        sandbox = self._sandbox()

        if ts_files:
            tsconfig = change.repo / str(self.config.get("tsconfig_path", "tsconfig.json"))
            facts["static.tsconfig_found"] = tsconfig.is_file()
            if facts["static.tsconfig_found"]:
                try:
                    findings.extend(
                        run_tsc(
                            change.repo,
                            sandbox,
                            self.id,
                            timeout_s=self.budget_s / 4,
                            args=list(self.config.get("tsc_args", [])),
                        )
                    )
                except ToolMissing as exc:
                    facts["static.tsc_available"] = False
                    if require_tsc:
                        return str(exc)
                except ToolFailed as exc:
                    if require_tsc:
                        return str(exc)
                    facts["static.tsc_available"] = False

        if ts_files or js_files:
            has_config = any((change.repo / name).is_file() for name in _ESLINT_CONFIG_NAMES)
            facts["static.eslint_config_found"] = has_config
            if has_config:
                try:
                    findings.extend(
                        run_eslint(
                            change.repo,
                            sandbox,
                            self.id,
                            timeout_s=self.budget_s / 4,
                            args=list(self.config.get("eslint_args", [])),
                        )
                    )
                except ToolMissing as exc:
                    facts["static.eslint_available"] = False
                    if require_eslint:
                        return str(exc)
                except ToolFailed as exc:
                    if require_eslint:
                        return str(exc)
                    facts["static.eslint_available"] = False
        return None

    # ----------------------------------------------------------------- c#

    def _run_csharp(
        self, change: ChangeContext, facts: dict[str, Any], findings: list[Finding]
    ) -> str | None:
        cs_files = [
            f.path for f in change.effective_files if f.language == "csharp" and f.status != "D"
        ]
        facts["static.csharp_files_checked"] = len(cs_files)
        if not cs_files:
            return None

        projects = dotnet.projects_for(change.repo, cs_files)
        facts["static.csproj_found"] = bool(projects)
        if not projects:
            return None

        require_dotnet = bool(self.config.get("require_dotnet_build", False))
        # CoreCLR rezerwuje kilka GB przestrzeni adresowej na starcie
        # niezależnie od realnego zużycia — jak silnik OCaml semgrepa
        # (gates/g3_sast.py). Twardy RLIMIT_AS zabija `dotnet` kodem 137
        # zamiast czytelnym błędem; zweryfikowane na żywym SDK.
        sandbox = Sandbox(
            SandboxPolicy(
                network=False,
                timeout_s=self.budget_s,
                memory_mb=None,
                keep_env=tuple(self.config.get("keep_env", ())),
            )
        )

        for project in projects:
            try:
                findings.extend(
                    dotnet.run_dotnet_build(
                        change.repo,
                        sandbox,
                        self.id,
                        project=project,
                        timeout_s=self.budget_s / max(len(projects), 1),
                        args=list(self.config.get("dotnet_args", [])),
                    )
                )
            except ToolMissing as exc:
                facts["static.dotnet_available"] = False
                if require_dotnet:
                    return str(exc)
                break  # brak `dotnet` raz = brak dla wszystkich projektów
            except ToolFailed as exc:
                if require_dotnet:
                    return str(exc)
                facts["static.dotnet_available"] = False
        return None

    # ------------------------------------------------------------------

    def _sandbox(self) -> Sandbox:
        return Sandbox(
            SandboxPolicy(
                network=False,
                timeout_s=self.budget_s,
                keep_env=tuple(self.config.get("keep_env", ())),
            )
        )

    def _error(
        self,
        change: ChangeContext,
        started: float,
        facts: dict[str, Any],
        findings: list[Finding],
        message: str,
    ) -> GateResult:
        # `findings` zebrane przed awarią zostają w raporcie (np. ruff zdążył
        # przejść, zanim wymagany mypy padł) — status `error` już mówi, że
        # dowód jest niekompletny, więc nie ma powodu chować tego, co
        # faktycznie zweryfikowano.
        return self.result(
            status="error",
            duration_s=time.monotonic() - started,
            facts=facts,
            findings=only_changed_lines(findings, change),
            message=message,
        )


def _empty_facts() -> dict[str, Any]:
    return {
        "static.python_files_checked": 0,
        "static.ruff_available": True,
        "static.mypy_available": True,
        "static.ts_files_checked": 0,
        "static.tsconfig_found": False,
        "static.tsc_available": True,
        "static.js_files_checked": 0,
        "static.eslint_config_found": False,
        "static.eslint_available": True,
        "static.csharp_files_checked": 0,
        "static.csproj_found": False,
        "static.dotnet_available": True,
        "static.finding_count": 0,
        "static.high_severity_count": 0,
    }
