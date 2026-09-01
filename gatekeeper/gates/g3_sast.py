"""G3 — SAST: reguły „nigdy" z zainstalowanych `SemgrepRulePackProvider` na
zmienionych liniach.

Reguły same są opisane w `rules/semgrep/*.yaml` per pack: wzorce, które nie
mają poprawnego zastosowania w danym języku, więc trafienie oznacza błąd
albo świadome obejście zabezpieczenia „żeby przeszło" — a to drugie jest w
kodzie od agenta częstsze, niż się wydaje (PLAN.md §G3).

Ta bramka sama nie ma żadnej logiki językowej — jest agregatorem poziomu 1
(`core/plugins.py`): enumeruje dostawców zarejestrowanych pod
`gatekeeper.semgrep_rule_packs`, przekazuje wszystkie ich katalogi reguł
semgrepowi jednym wywołaniem (semgrep sam scala wiele `--config`) i tak
zebrany wynik filtruje do zmienionych linii — jak w G1.static, inaczej
pierwszy przebieg na starszym repo tonie w istniejącym długu. Brak choćby
jednego zainstalowanego pack'a reguł to `error`, nie cichy brak dowodu —
semgrep bez `--config` w ogóle się nie uruchamia sensownie.
"""

from __future__ import annotations

import time

from ..adapters.base import ToolFailed, ToolMissing, only_changed_lines
from ..adapters.semgrep import run_semgrep
from ..core.change import ChangeContext
from ..core.finding import GateResult, Severity
from ..core.plugins import SemgrepRulePackProvider
from ..core.runner import Sandbox, SandboxPolicy
from . import Gate, register

RULE_PACK_GROUP = "gatekeeper.semgrep_rule_packs"


def _installed_rule_packs() -> list[SemgrepRulePackProvider]:
    from importlib.metadata import entry_points

    return [ep.load()() for ep in entry_points(group=RULE_PACK_GROUP)]


@register
class SastGuard(Gate):
    id = "G3.sast"
    name = "Reguły „nigdy” (semgrep)"
    budget_s = 180.0
    facts = (
        "sast.finding_count",
        "sast.critical_count",
        "sast.rule_ids",
        "sast.rule_packs",
    )

    def run(self, change: ChangeContext) -> GateResult:
        started = time.monotonic()
        facts = {
            "sast.finding_count": 0,
            "sast.critical_count": 0,
            "sast.rule_ids": [],
            "sast.rule_packs": [],
        }

        packs = _installed_rule_packs()
        facts["sast.rule_packs"] = sorted(p.pack_id for p in packs)
        if not packs:
            return self.result(
                status="error",
                duration_s=time.monotonic() - started,
                facts=facts,
                message="brak zainstalowanego pack'a reguł semgrep "
                f"(entry points `{RULE_PACK_GROUP}`) — bramka nie ma czego wołać",
            )

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
                config=[p.rules_dir() for p in packs],
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
