"""G2 — jakość nowych testów: testy-atrapy wykrywane przez AST (TOOLS.md §4.2).

Dopełnienie `G2.cross_verify`: tamta bramka dowodzi, że test *odróżnia*
kod przed zmiany od kodu po. Ta sprawdza coś bardziej podstawowego —
czy test w ogóle ma szansę czegoś dowieść, niezależnie od tego, jaki kod
sprawdza: brak asercji, asercja na stałą, mock porównywany z samym sobą,
asercja wyłącznie `is not None`, połknięty wyjątek.

Ta bramka sama nie ma logiki językowej — jak `G2.cross_verify`, jest
agregatorem poziomu 1 (`core/plugins.py`) po zainstalowanych `TestToolchain`
(`gatekeeper.test_toolchains`). Zakres: wyłącznie nowe/zmodyfikowane testy
w diffie — stary dług testowy repo to osobna sprawa, tu chodzi o to, co
dokłada ta konkretna zmiana.
"""

from __future__ import annotations

import time
from importlib.metadata import entry_points
from typing import Any

from ..core.change import ChangeContext
from ..core.finding import Finding, GateResult, Severity
from ..core.plugins import DiscoveryResult, QualityIssue, TestToolchain
from . import Gate, register

TOOLCHAIN_GROUP = "gatekeeper.test_toolchains"


def _installed_toolchains() -> list[TestToolchain]:
    return [ep.load()() for ep in entry_points(group=TOOLCHAIN_GROUP)]


@register
class TestSanity(Gate):
    __test__ = False  # nazwa zaczyna się od „Test” — to bramka, nie przypadek testowy pytesta
    id = "G2.test_sanity"
    name = "Jakość nowych testów"
    budget_s = 30.0
    facts = (
        "sanity.checked_count",
        "sanity.finding_count",
        "sanity.blocking_count",
        "sanity.rule_ids",
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

        items: list[DiscoveryResult] = []
        findings: list[Finding] = []
        for toolchain in toolchains:
            tests = toolchain.discover_tests(change)
            if not tests:
                continue
            items.extend(tests)
            for item, issue in toolchain.lint_quality(change, tests):
                findings.append(_to_finding(self.id, item, issue))

        facts["sanity.checked_count"] = len(items)
        if not items:
            return self.result(
                status="skipped",
                duration_s=time.monotonic() - started,
                facts=facts,
                message="brak nowych/zmodyfikowanych testów w diffie",
            )

        blocking = [f for f in findings if f.severity >= Severity.HIGH]
        facts["sanity.finding_count"] = len(findings)
        facts["sanity.blocking_count"] = len(blocking)
        facts["sanity.rule_ids"] = sorted({f.rule_id for f in findings})

        return self.result(
            status="fail" if blocking else "pass",
            duration_s=time.monotonic() - started,
            facts=facts,
            findings=findings,
            message=f"{len(findings)} znalezisk jakości w {len(items)} nowych/zmienionych "
            f"testach ({len(blocking)} blokujących)",
        )


def _empty_facts() -> dict[str, Any]:
    return {
        "sanity.checked_count": 0,
        "sanity.finding_count": 0,
        "sanity.blocking_count": 0,
        "sanity.rule_ids": [],
    }


def _to_finding(gate_id: str, item: DiscoveryResult, issue: QualityIssue) -> Finding:
    return Finding(
        gate=gate_id,
        rule_id=issue.rule_id,
        severity=issue.severity,
        title=issue.title,
        failure_scenario=issue.failure_scenario,
        file=item.file,
        line=issue.evidence.get("line", item.lineno),
        evidence={**issue.evidence, "test": item.nodeid},
    )
