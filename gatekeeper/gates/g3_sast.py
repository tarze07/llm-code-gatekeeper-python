"""G3 — SAST: reguły „nigdy" z `rules/semgrep/` na zmienionych liniach.

Reguły same są opisane w `rules/semgrep/never.yaml`: wzorce, które nie mają
poprawnego zastosowania w tym repo, więc trafienie oznacza błąd albo
świadome obejście zabezpieczenia „żeby przeszło" — a to drugie jest w kodzie
od agenta częstsze, niż się wydaje (PLAN.md §G3).

Filtrujemy do zmienionych linii z tego samego powodu co w G1.static: bez
tego pierwszy przebieg na starszym repo tonie w istniejącym długu i zespół
przestaje czytać raport. Semgrep jest tu obowiązkowy — bez niego cały zestaw
reguł „nigdy" milczy, więc jego brak jest błędem bramki, nie ostrzeżeniem.
"""

from __future__ import annotations

import time

from ..adapters.base import ToolFailed, ToolMissing, only_changed_lines
from ..adapters.semgrep import run_semgrep
from ..core.change import ChangeContext
from ..core.finding import GateResult, Severity
from ..core.runner import Sandbox, SandboxPolicy
from . import Gate, register


@register
class SastGuard(Gate):
    id = "G3.sast"
    name = "Reguły „nigdy” (semgrep)"
    budget_s = 180.0
    facts = (
        "sast.finding_count",
        "sast.critical_count",
        "sast.rule_ids",
    )

    def run(self, change: ChangeContext) -> GateResult:
        started = time.monotonic()
        facts = {
            "sast.finding_count": 0,
            "sast.critical_count": 0,
            "sast.rule_ids": [],
        }

        sandbox = Sandbox(
            SandboxPolicy(
                network=False,
                timeout_s=self.budget_s,
                # `memory_mb=None`: silnik semgrepa (OCaml) rezerwuje kilka GB
                # przestrzeni adresowej na starcie niezależnie od realnego
                # zużycia, więc `RLIMIT_AS` z sandboksa zabija go segfaultem
                # zamiast czytelnym błędem — limit narzędzie egzekwuje samo
                # przez `--max-memory` (patrz `adapters/semgrep.py`).
                memory_mb=None,
                keep_env=tuple(self.config.get("keep_env", ())),
            )
        )
        try:
            findings = run_semgrep(
                change.repo,
                sandbox,
                self.id,
                timeout_s=self.budget_s,
                max_memory_mb=int(self.config.get("max_memory_mb", 2000)),
            )
        except (ToolMissing, ToolFailed) as exc:
            return self.result(
                status="error",
                duration_s=time.monotonic() - started,
                facts=facts,
                message=str(exc),
            )

        findings = only_changed_lines(findings, change)
        critical = [f for f in findings if f.severity >= Severity.CRITICAL]
        facts["sast.finding_count"] = len(findings)
        facts["sast.critical_count"] = len(critical)
        facts["sast.rule_ids"] = sorted({f.rule_id for f in findings})

        return self.result(
            status="fail" if critical else "pass",
            duration_s=time.monotonic() - started,
            facts=facts,
            findings=findings,
            message=f"{len(findings)} znalezisk reguł „nigdy” w zmienionych liniach "
            f"({len(critical)} krytycznych)",
        )
