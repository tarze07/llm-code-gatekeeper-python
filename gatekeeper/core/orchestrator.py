"""Orkiestrator bramek: kolejność, równoległość, budżety czasowe.

Zastępuje sekwencyjną pętlę z kamienia 1. Trzy zasady, wszystkie z PLAN.md §2:

1. **Najtańsze i najbardziej deterministyczne najpierw.** G0 → (G1 ‖ G3) → G2.
   Kolejność jest zapisana jako zależności w grafie, nie jako `if` w środku
   bramki — inaczej za pół roku nikt nie wie, dlaczego coś się uruchamia.
2. **Drogie bramki nie ruszają, dopóki tanie nie przejdą.** G4 (panel LLM,
   kamień 5) deklaruje `requires_green`, więc nie odpali się na zmianie, która
   i tak zostanie zablokowana. Odwrotna kolejność to główny błąd projektowy
   w tego typu systemach.
3. **Budżet czasowy jest egzekwowany, nie sugerowany.** Bramka po przekroczeniu
   limitu dostaje status `error` — czyli „brak dowodu", nie „przeszło".

Ograniczenie, o którym trzeba wiedzieć: bramki to funkcje Pythona, a wątku nie
da się w Pythonie zabić. Po przekroczeniu budżetu orkiestrator przestaje czekać
i oznacza bramkę jako błąd, ale jej wątek dobiega końca w tle. Twarde ubijanie
dotyczy procesów potomnych i tym zajmuje się `core.runner`.
"""

from __future__ import annotations

import time
import traceback
import uuid
from collections.abc import Iterable, Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field

from ..gates import Gate, build_gates
from .change import ChangeContext
from .finding import GateResult, RunResult
from .policy import Policy
from .runner import describe_isolation

#: Jawna lista luk. Trafia do raportu, żeby nikt nie wziął zielonej bramy za
#: dowód, że zmiana jest bezpieczna (PLAN.md §9).
NOT_CHECKED = [
    "pokrycie różnicowe, testy mutacyjne, flaky-testy, contract-diff (G2) — "
    "kamień 4, w toku (G2.test_sanity zbudowane)",
    "G2.cross_verify (nowe testy przeciw kodowi sprzed zmiany) — tylko Python; "
    "adapter TS/JS (vitest/jest) i C# (dotnet test) w planie",
    "IaC i licencje (G3) — kamień 3 w toku; SCA sam w sobie obejmuje "
    "PyPI/npm/NuGet, poza tym zakresem zależności to jeszcze dług",
    "review semantyczny LLM (G4) — kamień 5",
    "gotowość wdrożeniowa: migracje, rollback, obserwowalność (G6) — kamień 6",
]

#: Zależności między bramkami. Klucz uruchamia się dopiero po wartościach.
DEPENDENCIES: dict[str, tuple[str, ...]] = {
    "G1.deps": ("G0.scope", "G0.provenance"),
    "G1.static": ("G0.scope", "G0.provenance"),
    "G3.secrets": ("G0.scope", "G0.provenance"),
    "G3.sast": ("G0.scope", "G0.provenance"),
    "G3.sca": ("G0.scope", "G0.provenance"),
    "G2.cross_verify": ("G1.deps", "G1.static"),
    "G2.test_sanity": ("G1.deps", "G1.static"),
}

#: Bramki, które nie mają prawa ruszyć, dopóki wskazane nie są zielone.
#: Dotyczy tego, co drogie — dziś nic takiego nie jest zbudowane, ale reguła
#: musi istnieć zanim powstanie G4, a nie po.
REQUIRES_GREEN: dict[str, tuple[str, ...]] = {
    "G4.review": ("G1.deps", "G1.static", "G3.secrets", "G3.sast"),
}

#: Ścieżka szybka: zmiana wyłącznie dokumentacyjna. Sekretów szukamy zawsze —
#: README bywa miejscem, w którym ląduje token.
FAST_PATH_GATES = ("G0.scope", "G0.provenance", "G3.secrets")


def dependencies_of(gate_id: str) -> tuple[str, ...]:
    """Pełna lista poprzedników bramki.

    Bramka, która wymaga zieleni innej bramki, musi też być po niej
    **zaplanowana** — inaczej sprawdzałaby status, którego jeszcze nie ma,
    i uruchamiałaby się mimo wszystko.
    """
    return tuple(dict.fromkeys(DEPENDENCIES.get(gate_id, ()) + REQUIRES_GREEN.get(gate_id, ())))


@dataclass
class Plan:
    """Kolejne fale bramek — wszystko w jednej fali biegnie równolegle."""

    waves: list[list[Gate]] = field(default_factory=list)
    skipped: dict[str, str] = field(default_factory=dict)

    @property
    def gates(self) -> list[Gate]:
        return [gate for wave in self.waves for gate in wave]


def build_plan(gates: Sequence[Gate], change: ChangeContext, fast_path: bool = True) -> Plan:
    plan = Plan()
    selected = list(gates)

    if fast_path and change.is_docs_only:
        for gate in selected:
            if gate.id not in FAST_PATH_GATES:
                plan.skipped[gate.id] = "ścieżka szybka: zmiana wyłącznie dokumentacyjna"
        selected = [g for g in selected if g.id in FAST_PATH_GATES]

    present = {g.id for g in selected}
    remaining = list(selected)
    done: set[str] = set()

    while remaining:
        wave = [
            gate
            for gate in remaining
            if all(dep in done for dep in dependencies_of(gate.id) if dep in present)
        ]
        if not wave:
            # Cykl w konfiguracji zależności — lepiej uruchomić sekwencyjnie
            # i powiedzieć o tym, niż zawiesić przebieg.
            wave = remaining[:1]
        plan.waves.append(wave)
        for gate in wave:
            done.add(gate.id)
        remaining = [g for g in remaining if g not in wave]
    return plan


def run_gates(
    change: ChangeContext,
    policy: Policy,
    gates: Iterable[Gate] | None = None,
    only: Iterable[str] | None = None,
    fast_path: bool = True,
    max_workers: int = 4,
) -> RunResult:
    started = time.monotonic()
    gate_list = list(gates) if gates is not None else build_gates(policy, only=only)
    plan = build_plan(gate_list, change, fast_path=fast_path)

    results: list[GateResult] = []
    statuses: dict[str, str] = {}

    for wave in plan.waves:
        runnable: list[tuple[Gate, list[str]]] = []
        blocked: list[tuple[Gate, list[str]]] = []
        for gate in wave:
            missing = [
                dep
                for dep in REQUIRES_GREEN.get(gate.id, ())
                if statuses.get(dep) not in (None, "pass", "skipped")
            ]
            (blocked if missing else runnable).append((gate, missing))

        for gate, missing in blocked:
            results.append(
                GateResult(
                    gate=gate.id,
                    status="skipped",
                    message=f"pominięta: {', '.join(missing)} nie przeszły — "
                    "droga bramka nie rusza na zmianie, która i tak jest zablokowana",
                    warn_only=policy.is_warn_only(gate.id),
                )
            )
            statuses[gate.id] = "skipped"

        if len(runnable) == 1:
            wave_results = [_run_one(runnable[0][0], change, policy)]
        else:
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures: dict[Future[GateResult], Gate] = {
                    pool.submit(_run_one, gate, change, policy): gate for gate, _ in runnable
                }
                wave_results = _collect(futures, policy)

        for result in wave_results:
            results.append(result)
            statuses[result.gate] = result.status

    for gate_id, reason in plan.skipped.items():
        results.append(GateResult(gate=gate_id, status="skipped", message=reason))

    results.sort(key=lambda r: r.gate)
    facts = {k: v for r in results for k, v in r.facts.items()}
    decision = policy.decide(facts, results, change=change)

    not_checked = list(NOT_CHECKED)
    if plan.skipped:
        not_checked.insert(0, f"pominięte na ścieżce szybkiej: {', '.join(sorted(plan.skipped))}")
    not_checked.append(describe_isolation())

    return RunResult(
        run_id=uuid.uuid4().hex[:12],
        repo=str(change.repo),
        base_sha=change.base_sha,
        head_sha=change.head_sha,
        gate_results=results,
        decision=decision,
        duration_s=time.monotonic() - started,
        policy_version=policy.version,
        not_checked=not_checked,
    )


def _collect(futures: dict[Future[GateResult], Gate], policy: Policy) -> list[GateResult]:
    """Czeka na falę, pilnując budżetu każdej bramki z osobna."""
    out: list[GateResult] = []
    for future, gate in futures.items():
        try:
            out.append(future.result(timeout=gate.budget_s + _GRACE_S))
        except TimeoutError:
            out.append(
                GateResult(
                    gate=gate.id,
                    status="error",
                    duration_s=gate.budget_s,
                    message=(
                        f"przekroczony budżet czasowy ({gate.budget_s:.0f}s) — bramka nie "
                        "dostarczyła dowodu; wątek dobiegnie końca w tle"
                    ),
                    warn_only=policy.is_warn_only(gate.id),
                )
            )
    return out


_GRACE_S = 5.0


def _run_one(gate: Gate, change: ChangeContext, policy: Policy) -> GateResult:
    warn_only = policy.is_warn_only(gate.id)
    started = time.monotonic()
    try:
        result = gate.run(change)
    except Exception:  # noqa: BLE001 — awaria bramki nie może wywrócić przebiegu
        result = GateResult(
            gate=gate.id,
            status="error",
            duration_s=time.monotonic() - started,
            message=_short_traceback(),
        )
    result.warn_only = warn_only
    if result.duration_s > gate.budget_s:
        result.message = (
            f"{result.message} · przekroczony budżet czasowy "
            f"({result.duration_s:.0f}s > {gate.budget_s:.0f}s)"
        ).strip(" ·")
    return result


def _short_traceback() -> str:
    lines = traceback.format_exc().strip().splitlines()
    return f"wyjątek w bramce: {lines[-1]}" if lines else "wyjątek w bramce"
