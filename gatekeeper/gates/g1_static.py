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
diff — polityka i `warn_only` nie muszą znać podziału na język. Ta bramka
sama nie ma żadnej logiki językowej: jest agregatorem poziomu 1
(`core/plugins.py`), który enumeruje zainstalowanych dostawców pod
`gatekeeper.static_checkers` (`StaticChecker` — jeden per język, patrz
`adapters/linters.py::PythonStaticChecker`/`TsJsStaticChecker`,
`adapters/dotnet.py::CsharpStaticChecker`) i sumuje ich wyniki. Nowy język
nie wymaga dotykania tego pliku — tylko rejestracji kolejnego checkera.
"""

from __future__ import annotations

import time
from importlib.metadata import entry_points
from typing import Any

from ..adapters.base import only_changed_lines
from ..core.change import ChangeContext
from ..core.finding import Finding, GateResult, Severity
from ..core.plugins import StaticChecker
from . import Gate, register

STATIC_CHECKER_GROUP = "gatekeeper.static_checkers"


def _installed_checkers() -> list[StaticChecker]:
    return [ep.load()() for ep in entry_points(group=STATIC_CHECKER_GROUP)]


@register
class StaticGuard(Gate):
    id = "G1.static"
    name = "Poprawność statyczna (ruff/mypy, tsc/eslint, dotnet build)"
    budget_s = 180.0

    @classmethod
    def declared_facts(cls) -> tuple[str, ...]:
        facts: set[str] = {"static.finding_count", "static.high_severity_count"}
        for checker in _installed_checkers():
            facts.update(checker.empty_facts())
        return tuple(sorted(facts))

    def run(self, change: ChangeContext) -> GateResult:
        started = time.monotonic()
        checkers = _installed_checkers()
        facts: dict[str, Any] = {"static.finding_count": 0, "static.high_severity_count": 0}
        for checker in checkers:
            facts.update(checker.empty_facts())
        findings: list[Finding] = []

        for checker in checkers:
            outcome = checker.check(change, self.config, self.id, self.budget_s)
            findings.extend(outcome.findings)
            facts.update(outcome.facts)
            if outcome.error is not None:
                return self._error(change, started, facts, findings, outcome.error)

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
