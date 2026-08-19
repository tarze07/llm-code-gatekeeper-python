"""G0 — higiena zakresu zmiany (`scope-guard`).

Bramka wystawia wyłącznie **fakty** (i, dla zakresu ticketu, znaleziska
informacyjne); progi i decyzja należą do polityki. Dublowanie limitu w
kodzie bramki oznaczałoby dwa źródła prawdy o tym, co jest „za duże" —
a limit ma być zmieniany w `gates.yaml`, nie w Pythonie.

Kluczowa część to nie liczenie linii, tylko **wykluczenie plików
generowanych**: bez tego pierwszy PR odświeżający lockfile przekracza próg
i zespół w tydzień wyłącza bramkę.

Druga część, `scope_map` (TOOLS.md §2.2): mapowanie `prefiks ticketu →
dozwolone globy` z `policy/scope_map.yaml`. Ticket bez wpisu w mapowaniu
(albo brak mapowania w ogóle) nie blokuje niczego — dopóki mapa nie pokrywa
całego repo, egzekwowanie zakresu byłoby zgadywanką.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import yaml

from ..core.change import ChangeContext, matches_any
from ..core.finding import Finding, GateResult, Severity
from . import Gate, register

DEFAULT_SCOPE_MAP_PATH = "policy/scope_map.yaml"


@register
class ScopeGuard(Gate):
    id = "G0.scope"
    name = "Rozmiar i higiena zakresu zmiany"
    budget_s = 10.0
    facts = (
        "diff.total_lines",
        "diff.total_files",
        "diff.effective_lines",
        "diff.effective_files",
        "diff.generated_files",
        "diff.test_files",
        "diff.docs_only",
        "diff.largest_file_lines",
        "diff.binary_files",
        "diff.has_ticket",
        "diff.scope_map_matched",
        "diff.out_of_scope_files",
    )

    def run(self, change: ChangeContext) -> GateResult:
        started = time.monotonic()
        effective = change.effective_files
        largest = max((f.churn for f in effective), default=0)

        out_of_scope, matched = self._check_scope_map(change)

        facts: dict[str, Any] = {
            "diff.total_lines": change.total_lines,
            "diff.total_files": len(change.files),
            "diff.effective_lines": change.effective_lines,
            "diff.effective_files": len(effective),
            "diff.generated_files": len([f for f in change.files if f.generated]),
            "diff.test_files": len([f for f in change.files if f.test]),
            "diff.docs_only": change.is_docs_only,
            "diff.largest_file_lines": largest,
            "diff.binary_files": len([f for f in change.files if f.binary]),
            "diff.has_ticket": change.ticket is not None,
            "diff.scope_map_matched": matched,
            "diff.out_of_scope_files": len(out_of_scope),
        }

        findings: list[Finding] = []
        if out_of_scope:
            assert change.ticket is not None  # matched=True implikuje ticket
            shown = ", ".join(f"`{p}`" for p in out_of_scope[:5])
            more = f" (+{len(out_of_scope) - 5})" if len(out_of_scope) > 5 else ""
            findings.append(
                Finding(
                    gate=self.id,
                    rule_id="diff.out_of_scope_files",
                    severity=Severity.LOW,
                    title=(
                        f"{len(out_of_scope)} plików poza zakresem ticketu {change.ticket.id}"
                    ),
                    failure_scenario=(
                        f"Ticket {change.ticket.id} ma zadeklarowany zakres w "
                        f"`{DEFAULT_SCOPE_MAP_PATH}`, a ta zmiana dotyka plików spoza niego: "
                        f"{shown}{more}. Może to być zamierzona zmiana współdzielona, albo "
                        "PR robiący więcej, niż mówi jego opis — recenzent nie zgadnie, które."
                    ),
                    file=out_of_scope[0],
                    evidence={
                        "snippet": ", ".join(out_of_scope[:10]),
                        "ticket": change.ticket.id,
                    },
                )
            )

        return self.result(
            status="pass",
            duration_s=time.monotonic() - started,
            facts=facts,
            findings=findings,
            message=(
                f"{facts['diff.effective_lines']} linii w {facts['diff.effective_files']} plikach "
                f"(pominięto {facts['diff.generated_files']} plików generowanych)"
            ),
        )

    # ------------------------------------------------------------------

    def _check_scope_map(self, change: ChangeContext) -> tuple[list[str], bool]:
        if change.ticket is None:
            return [], False
        scope_map = self._load_scope_map(change.repo)
        prefix = change.ticket.id.split("-", 1)[0]
        allowed = scope_map.get(prefix)
        if not allowed:
            return [], False

        out_of_scope = [
            f.path
            for f in change.effective_files
            if not f.test and not matches_any(f.path, allowed)
        ]
        return out_of_scope, True

    def _load_scope_map(self, repo: Path) -> dict[str, list[str]]:
        path_str = self.config.get("scope_map_path", DEFAULT_SCOPE_MAP_PATH)
        path = Path(path_str)
        if not path.is_absolute():
            path = repo / path
        if not path.exists():
            return {}
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return {str(k): list(v or []) for k, v in (data.get("components") or {}).items()}
