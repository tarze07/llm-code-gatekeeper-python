"""G2 — weryfikacja krzyżowa: nowe testy przeciw kodowi **sprzed** zmiany.

Najlepszy stosunek wartości do kosztu w całym systemie. Zasada jest banalna:

    test dla nowej funkcjonalności *musi* polec na starym kodzie.

Jeżeli przechodzi, to nie testuje tego, co deklaruje — a to najczęstszy defekt
kodu z agenta: zielony zestaw testów, który niczego nie dowodzi.

Ta bramka sama nie ma żadnej logiki językowej — jest agregatorem poziomu 1
(`core/plugins.py`): pętla po zainstalowanych `TestToolchain` (grupa
`gatekeeper.test_toolchains`; dziś tylko `testing.toolchain.PythonTestToolchain`
— TS/JS i C# nie mają jeszcze odpowiednika, patrz README/PLAN.md). Brak
zainstalowanego toolchaina to `skipped`, nie błąd — bramka nie ma czego
dowodzić, jeśli żaden dostawca nie umie uruchomić testów danego języka.

Trzy rzeczy decydują o tym, czy ta bramka przeżyje w zespole:

1. **Obsługa legalnych wyjątków.** Czysty refaktor, dopisanie testów do
   istniejącego kodu i test regresyjny do buga naprawionego wcześniej to
   przypadki, w których test *powinien* przejść na starym kodzie. Autor
   deklaruje je markerem, a bramka liczy te deklaracje i raportuje ich użycie
   — nadużywanie staje się widoczne w liczbach zamiast po cichu drążyć system.
2. **Kontrola izolacji.** Jeżeli pakiet jest zainstalowany w trybie
   edytowalnym, `import` sięgnie po kod z katalogu roboczego zamiast z worktree
   i cała bramka mierzyłaby nowy kod przeciw nowemu. Sprawdzamy to jawnie
   i przy wykryciu przerywamy z błędem zamiast produkować bezwartościowy wynik.
3. **Rozróżnienie porażki od błędu importu.** Test, który poległ na asercji,
   dowodzi czegoś o zachowaniu. Test, który nie zaimportował nieistniejącego
   jeszcze modułu, dowodzi znacznie mniej — i jest liczony osobno.
"""

from __future__ import annotations

import time
from importlib.metadata import entry_points
from typing import Any

from ..core.change import ChangeContext
from ..core.finding import Finding, GateResult, Severity
from ..core.plugins import DiscoveryResult, TestToolchain
from ..testing.discovery import ESCAPE_MARKERS
from ..testing.pytest_runner import PytestUnavailable
from ..testing.toolchain import IsolationBroken
from . import Gate, register

TOOLCHAIN_GROUP = "gatekeeper.test_toolchains"


def _installed_toolchains() -> list[TestToolchain]:
    return [ep.load()() for ep in entry_points(group=TOOLCHAIN_GROUP)]


@register
class CrossVerify(Gate):
    id = "G2.cross_verify"
    name = "Nowe testy przeciw kodowi sprzed zmiany"
    budget_s = 600.0
    facts = (
        "tests.new_count",
        "tests.checked",
        "tests.pass_on_pre_change_code",
        "tests.passing_on_old_code",
        "tests.weak_evidence",
        "tests.proved",
        "tests.characterization_used",
        "tests.isolation_broken",
    )

    def run(self, change: ChangeContext) -> GateResult:
        started = time.monotonic()
        facts = _empty_facts()

        toolchains = _installed_toolchains()
        if not toolchains:
            return self.result(
                status="skipped",
                duration_s=time.monotonic() - started,
                facts=facts,
                message="brak zainstalowanego toolchaina testowego "
                f"(entry points `{TOOLCHAIN_GROUP}`)",
            )

        findings: list[Finding] = []
        ran_messages: list[str] = []
        touched_production = False

        for toolchain in toolchains:
            language = getattr(toolchain, "language", None)
            production = [
                f
                for f in change.files
                if not f.test and not f.generated and f.status != "D" and f.language == language
            ]
            if not production:
                # Zmiana bez kodu produkcyjnego w tym języku: stary i nowy kod
                # są identyczne, więc każdy test przeszedłby na „starym" —
                # blokowanie tutaj oznaczałoby blokowanie każdego PR-a
                # dokładającego testy.
                continue
            touched_production = True

            candidates = toolchain.discover_tests(change)
            facts["tests.new_count"] += len(candidates)
            if not candidates:
                continue

            checked = [t for t in candidates if not t.declared_escape]
            declared = [t for t in candidates if t.declared_escape]
            facts["tests.characterization_used"] += len(declared)
            facts["tests.checked"] += len(checked)
            if declared:
                findings.append(_declaration_notice(self.id, declared))
            if not checked:
                continue

            try:
                outcomes, message = toolchain.run_cross_verify(change, checked, self.config)
            except IsolationBroken as exc:
                facts["tests.isolation_broken"] = True
                return self.result(
                    status="error",
                    duration_s=time.monotonic() - started,
                    facts=facts,
                    findings=findings,
                    message=str(exc),
                )
            except PytestUnavailable as exc:
                return self.result(
                    status="error",
                    duration_s=time.monotonic() - started,
                    facts=facts,
                    findings=findings,
                    message=str(exc),
                )

            ran_messages.append(message)
            passing: list[str] = []
            for item in checked:
                outcome = outcomes.get(item.nodeid)
                if outcome is None or outcome.outcome in ("missing", "error", "skipped"):
                    facts["tests.weak_evidence"] += 1
                    continue
                if outcome.outcome == "failed":
                    facts["tests.proved"] += 1
                    continue
                passing.append(item.nodeid)
                findings.append(_useless_test_finding(self.id, item))
            if passing:
                facts["tests.passing_on_old_code"] = facts["tests.passing_on_old_code"] + passing

        facts["tests.pass_on_pre_change_code"] = bool(facts["tests.passing_on_old_code"])

        if not touched_production:
            return self.result(
                status="skipped",
                duration_s=time.monotonic() - started,
                facts=facts,
                message="zmiana nie dotyka kodu produkcyjnego — nie ma czego dowodzić",
            )
        if facts["tests.new_count"] == 0:
            return self.result(
                status="skipped",
                duration_s=time.monotonic() - started,
                facts=facts,
                message="zmiana w kodzie produkcyjnym bez nowych testów",
            )
        if facts["tests.checked"] == 0:
            return self.result(
                status="pass",
                duration_s=time.monotonic() - started,
                facts=facts,
                findings=findings,
                message=f"wszystkie {facts['tests.characterization_used']} nowych testów "
                "zadeklarowano jako charakteryzujące",
            )

        return self.result(
            status="fail" if facts["tests.pass_on_pre_change_code"] else "pass",
            duration_s=time.monotonic() - started,
            facts=facts,
            findings=findings,
            message=(
                f"{facts['tests.proved']} testów dowodzi zmiany, "
                f"{len(facts['tests.passing_on_old_code'])} przechodzi na starym kodzie, "
                f"{facts['tests.weak_evidence']} bez rozstrzygnięcia · {' · '.join(ran_messages)}"
            ),
        )


def _useless_test_finding(gate_id: str, item: DiscoveryResult) -> Finding:
    return Finding(
        gate=gate_id,
        rule_id="tests.pass_on_pre_change_code",
        severity=Severity.HIGH,
        title=f"Test `{item.name}` przechodzi na kodzie sprzed zmiany",
        failure_scenario=(
            f"Test `{item.nodeid}` daje wynik zielony również bez tej zmiany, więc nie "
            f"odróżnia kodu przed od kodu po. Gdyby implementacja została jutro cofnięta "
            f"albo napisana błędnie, ten test nadal by przechodził — czyli nie chroni "
            f"niczego. Jeżeli to celowo test charakteryzujący istniejące zachowanie, "
            f"oznacz go `@pytest.mark.characterization`."
        ),
        file=item.file,
        line=item.lineno,
        evidence={"snippet": item.nodeid, "body_hash": item.body_hash},
    )


def _declaration_notice(gate_id: str, declared: list[DiscoveryResult]) -> Finding:
    names = ", ".join(f"`{i.name}`" for i in declared[:5])
    return Finding(
        gate=gate_id,
        rule_id="tests.characterization_declared",
        severity=Severity.INFO,
        title=f"{len(declared)} testów wyłączono z weryfikacji krzyżowej deklaracją autora",
        failure_scenario=(
            f"Testy {names} są oznaczone markerem zwalniającym z dowodu "
            f"({', '.join(sorted(ESCAPE_MARKERS))}). "
            "To dopuszczalne przy refaktorze i dopisywaniu testów do istniejącego kodu, ale "
            "rosnąca liczba takich deklaracji oznacza, że bramka przestaje cokolwiek sprawdzać "
            "— liczba jest raportowana w metrykach miesięcznych."
        ),
        file=declared[0].file,
        line=declared[0].lineno,
        confidence=1.0,
        evidence={"snippet": ",".join(i.nodeid for i in declared)},
    )


def _empty_facts() -> dict[str, Any]:
    return {
        "tests.new_count": 0,
        "tests.checked": 0,
        "tests.pass_on_pre_change_code": False,
        "tests.passing_on_old_code": [],
        "tests.weak_evidence": 0,
        "tests.proved": 0,
        "tests.characterization_used": 0,
        "tests.isolation_broken": False,
    }
