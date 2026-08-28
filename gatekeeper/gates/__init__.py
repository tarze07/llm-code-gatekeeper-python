"""Rejestr bramek.

Kontrakt jest jeden i celowo wąski: `Gate.run(ChangeContext) -> GateResult`.
Nowa bramka nie wymaga dotykania rdzenia (TOOLS.md §9).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ..core.change import ChangeContext
from ..core.finding import GateResult


class Gate:
    id: str = ""
    name: str = ""
    budget_s: float = 60.0
    #: Fakty, które ta bramka może wystawić. Służą do walidacji polityki —
    #: literówka w `gates.yaml` ma być błędem, nie regułą, która nigdy nie
    #: zadziała.
    facts: tuple[str, ...] = ()

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}

    def run(self, change: ChangeContext) -> GateResult:  # pragma: no cover - interfejs
        raise NotImplementedError

    # pomocnicze
    def result(self, **kwargs: Any) -> GateResult:
        return GateResult(gate=self.id, **kwargs)


REGISTRY: dict[str, type[Gate]] = {}


def register(cls: type[Gate]) -> type[Gate]:
    if not cls.id:
        raise ValueError(f"{cls.__name__} nie ma identyfikatora")
    REGISTRY[cls.id] = cls
    return cls


def all_gates() -> list[type[Gate]]:
    from . import (  # noqa: F401  (rejestracja)
        g0_provenance,
        g0_scope,
        g1_deps,
        g1_static,
        g2_crossverify,
        g2_diff_coverage,
        g2_test_sanity,
        g3_sast,
        g3_sca,
        g3_secrets,
    )

    return [REGISTRY[k] for k in sorted(REGISTRY)]


def known_facts() -> set[str]:
    return {fact for gate in all_gates() for fact in gate.facts}


def known_gate_ids() -> set[str]:
    return {gate.id for gate in all_gates()}


def build_gates(policy: Any, only: Iterable[str] | None = None) -> list[Gate]:
    selected = set(only) if only else None
    gates: list[Gate] = []
    for cls in all_gates():
        if selected and cls.id not in selected:
            continue
        gates.append(cls(policy.gate_config(cls.id)))
    return gates
