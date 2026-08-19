"""G1 — poprawność statyczna: ruff + mypy na zmienionych plikach Pythona.

Typy w trybie strict wyłapują dużą część halucynacji API agenta — wywołanie
metody, której nie ma, albo argumentu o innej nazwie (TOOLS.md §3). To tania
bramka o wysokiej trafności, więc wchodzi w kamieniu 3, a nie później.

Jedyna nietrywialna decyzja (TOOLS.md §3.1): raportujemy tylko znaleziska
w zmienionych liniach (+3 linie kontekstu, `only_changed_lines`) — inaczej
pierwszy przebieg na starszym repo daje tysiące błędów mypy i projekt
umiera w dniu wdrożenia. Dług istniejącego kodu to osobny raport.

ruff jest uniwersalny i szybki — jego brak jest błędem bramki (`error`).
mypy bywa w wielu repo nieskonfigurowany (brak `py.typed`, brak sekcji
`[mypy]`) — domyślnie jego brak albo awaria konfiguracji jest tylko brakiem
dowodu z tego narzędzia, nie blokadą; `require_mypy: true` w polityce
włącza twarde wymaganie, gdy zespół już go skonfigurował.
"""

from __future__ import annotations

import time

from ..adapters.base import ToolFailed, ToolMissing, only_changed_lines
from ..adapters.linters import run_mypy, run_ruff
from ..core.change import ChangeContext
from ..core.finding import GateResult, Severity
from ..core.runner import Sandbox, SandboxPolicy
from . import Gate, register


@register
class StaticGuard(Gate):
    id = "G1.static"
    name = "Poprawność statyczna (ruff, mypy)"
    budget_s = 120.0
    facts = (
        "static.python_files_checked",
        "static.ruff_available",
        "static.mypy_available",
        "static.finding_count",
        "static.high_severity_count",
    )

    def run(self, change: ChangeContext) -> GateResult:
        started = time.monotonic()
        python_files = [
            f.path for f in change.effective_files if f.language == "python" and f.status != "D"
        ]
        facts = {
            "static.python_files_checked": len(python_files),
            "static.ruff_available": True,
            "static.mypy_available": True,
            "static.finding_count": 0,
            "static.high_severity_count": 0,
        }
        if not python_files:
            return self.result(
                status="pass",
                duration_s=time.monotonic() - started,
                facts=facts,
                message="brak zmienionych plików Pythona",
            )

        require_ruff = bool(self.config.get("require_ruff", True))
        require_mypy = bool(self.config.get("require_mypy", False))
        sandbox = Sandbox(
            SandboxPolicy(
                network=False,
                timeout_s=self.budget_s,
                keep_env=tuple(self.config.get("keep_env", ())),
            )
        )

        findings = []
        try:
            findings.extend(run_ruff(change.repo, sandbox, self.id, timeout_s=self.budget_s / 2))
        except ToolMissing as exc:
            facts["static.ruff_available"] = False
            if require_ruff:
                # Brak narzędzia nie jest zieloną bramką — to brak dowodu.
                return self.result(
                    status="error",
                    duration_s=time.monotonic() - started,
                    facts=facts,
                    message=str(exc),
                )
        except ToolFailed as exc:
            return self.result(
                status="error",
                duration_s=time.monotonic() - started,
                facts=facts,
                message=str(exc),
            )

        try:
            findings.extend(
                run_mypy(
                    change.repo,
                    sandbox,
                    self.id,
                    targets=python_files,
                    timeout_s=self.budget_s / 2,
                    args=list(self.config.get("mypy_args", [])),
                )
            )
        except ToolMissing as exc:
            facts["static.mypy_available"] = False
            if require_mypy:
                return self.result(
                    status="error",
                    duration_s=time.monotonic() - started,
                    facts=facts,
                    message=str(exc),
                )
        except ToolFailed as exc:
            if require_mypy:
                return self.result(
                    status="error",
                    duration_s=time.monotonic() - started,
                    facts=facts,
                    message=str(exc),
                )
            # mypy potrafi się wywrócić na błędzie konfiguracji (target spoza
            # pakietu, brak stubów) — bez `require_mypy` to brak dowodu z tego
            # narzędzia, nie defekt w kodzie PR-a.
            facts["static.mypy_available"] = False

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
