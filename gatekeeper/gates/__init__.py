"""Rejestr bramek.

Kontrakt jest jeden i celowo wąski: `Gate.run(ChangeContext) -> GateResult`.
Nowa bramka nie wymaga dotykania rdzenia (TOOLS.md §9) — dosłownie: bramki
rejestrują się przez entry points (grupa `gatekeeper.gates`), nie przez
wpisanie do listy importów tutaj. Ten pakiet (`gatekeeper`) rejestruje przez
ten sam mechanizm swoje własne dziesięć bramek (`pyproject.toml`) — rdzeń
je swój własny dogfood, więc mechanizm jest udowodniony niezależnie od tego,
czy jakikolwiek zewnętrzny pakiet z bramkami jest w ogóle zainstalowany.
"""

from __future__ import annotations

from collections.abc import Iterable
from importlib.metadata import entry_points
from typing import Any

from ..core.change import ChangeContext
from ..core.finding import GateResult

GATE_GROUP = "gatekeeper.gates"


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

    @classmethod
    def declared_facts(cls) -> tuple[str, ...]:
        """Domyślnie `cls.facts`. Bramki-agregatory (`G1.static`, `G1.deps`,
        `G2.*`, `G3.sca`, `G3.sast`) nadpisują to, żeby dorzucić fakty ze
        WSZYSTKICH zainstalowanych dostawców poziomu 2 (patrz `core/plugins.py`)
        — inaczej `gatekeeper policy facts`/`policy lint` nie znałyby faktu
        pluginu, którego akurat nie ma w danym środowisku."""
        return cls.facts

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
    for ep in entry_points(group=GATE_GROUP):
        cls = ep.load()
        if cls.id not in REGISTRY:
            register(cls)
    return [REGISTRY[k] for k in sorted(REGISTRY)]


def known_facts() -> set[str]:
    return {fact for gate in all_gates() for fact in gate.declared_facts()}


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
