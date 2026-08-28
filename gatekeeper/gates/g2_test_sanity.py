"""G2 — jakość nowych testów: testy-atrapy wykrywane przez AST (TOOLS.md §4.2).

Dopełnienie `G2.cross_verify`: tamta bramka dowodzi, że test *odróżnia*
kod przed zmiany od kodu po. Ta sprawdza coś bardziej podstawowego —
czy test w ogóle ma szansę czegoś dowieść, niezależnie od tego, jaki kod
sprawdza: brak asercji, asercja na stałą, mock porównywany z samym sobą,
asercja wyłącznie `is not None`, połknięty wyjątek.

Zakres: wyłącznie nowe/zmodyfikowane testy w diffie (`testing.discovery`,
to samo źródło co `G2.cross_verify`) — stary dług testowy repo to osobna
sprawa, tu chodzi o to, co dokłada ta konkretna zmiana.
"""

from __future__ import annotations

import ast
import time
from typing import Any

from ..core.change import ChangeContext
from ..core.finding import Finding, GateResult, Severity
from ..testing import discovery, quality
from . import Gate, register


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

        items: list[discovery.TestItem] = []
        findings: list[Finding] = []

        for file in change.files:
            if not file.test or file.status == "D" or not file.path.endswith(".py"):
                continue
            head_source = change.file_at(change.head_sha, file.path)
            if head_source is None:
                continue
            base_source = change.file_at(change.base_sha, file.path) or ""
            file_items = discovery.changed_tests(base_source, head_source, file.path)
            if not file_items:
                continue
            items.extend(file_items)

            # `changed_tests` już sparsowało `head_source` bez błędu (inaczej
            # zwróciłoby pustą listę) — tu parsujemy drugi raz tylko po to,
            # żeby wyłowić funkcje pomocnicze zdefiniowane obok testów.
            helpers = quality.module_helpers_of(ast.parse(head_source))
            for item in file_items:
                if item.node is None:  # pragma: no cover - zawsze ustawione przez collect_tests
                    continue
                for issue in quality.check_test(item.node, helpers):
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


def _to_finding(gate_id: str, item: discovery.TestItem, issue: quality.QualityIssue) -> Finding:
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
