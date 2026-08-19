from __future__ import annotations

import time

from gatekeeper.core.change import ChangeContext
from gatekeeper.core.finding import GateResult, Verdict
from gatekeeper.core.orchestrator import build_plan, run_gates
from gatekeeper.core.policy import Policy
from gatekeeper.gates import Gate
from gatekeeper.gates.g0_scope import ScopeGuard


class Stub(Gate):
    """Bramka-atrapa: kontrolujemy czas trwania i wynik."""

    def __init__(self, gate_id: str, status="pass", sleep_s=0.0, budget_s=60.0, facts=None):
        super().__init__({})
        self.id = gate_id
        self.name = gate_id
        self.budget_s = budget_s
        self.status = status
        self.sleep_s = sleep_s
        self._facts = facts or {}
        self.started_at: float | None = None
        self.finished_at: float | None = None

    def run(self, change) -> GateResult:
        self.started_at = time.monotonic()
        if self.sleep_s:
            time.sleep(self.sleep_s)
        self.finished_at = time.monotonic()
        return GateResult(gate=self.id, status=self.status, facts=self._facts)


def policy(**overrides) -> Policy:
    return Policy.from_dict({"version": 1, **overrides})


def context(repo) -> ChangeContext:
    repo.checkout("feature", create=True)
    repo.write("src/app.py", "x = 1\n")
    repo.commit("zmiana")
    return ChangeContext.from_git(repo.path, "main", "HEAD")


def test_plan_uklada_bramki_w_fale_wedlug_zaleznosci(repo):
    change = context(repo)
    gates = [Stub("G2.cross_verify"), Stub("G1.deps"), Stub("G0.scope"), Stub("G3.secrets")]

    plan = build_plan(gates, change)
    waves = [sorted(g.id for g in wave) for wave in plan.waves]

    assert waves[0] == ["G0.scope"]
    assert waves[1] == ["G1.deps", "G3.secrets"]  # tanie i niezależne — równolegle
    assert waves[2] == ["G2.cross_verify"]  # dopiero po G1


def test_bramki_w_jednej_fali_biegna_rownolegle(repo):
    change = context(repo)
    a, b = Stub("G1.deps", sleep_s=0.4), Stub("G3.secrets", sleep_s=0.4)

    started = time.monotonic()
    run_gates(change, policy(), gates=[Stub("G0.scope"), a, b])
    elapsed = time.monotonic() - started

    assert elapsed < 0.7, "0.4s + 0.4s sekwencyjnie zajęłoby ponad 0.8s"
    assert a.started_at is not None and b.started_at is not None


def test_przekroczony_budzet_to_blad_a_nie_przeszlo(repo):
    change = context(repo)
    wolna = Stub("G1.deps", sleep_s=30, budget_s=0.2)

    result = run_gates(change, policy(), gates=[Stub("G0.scope"), wolna, Stub("G3.secrets")])

    gate = next(g for g in result.gate_results if g.gate == "G1.deps")
    assert gate.status == "error"
    assert "budżet" in gate.message
    # brak dowodu kieruje zmianę do człowieka, nie przepuszcza jej
    assert result.decision.verdict is Verdict.PASS_WITH_REVIEW


def test_droga_bramka_nie_rusza_gdy_tania_nie_przeszla(repo):
    """G4 (panel LLM) jest drogi — nie uruchamiamy go na zmianie i tak zablokowanej."""
    change = context(repo)
    gates = [
        Stub("G0.scope"),
        Stub("G1.deps", status="fail"),
        Stub("G1.static"),
        Stub("G3.secrets"),
        Stub("G3.sast"),
        Stub("G4.review"),
    ]

    result = run_gates(change, policy(), gates=gates)

    review = next(g for g in result.gate_results if g.gate == "G4.review")
    assert review.status == "skipped"
    assert "G1.deps" in review.message


def test_droga_bramka_rusza_gdy_tanie_sa_zielone(repo):
    change = context(repo)
    review = Stub("G4.review")
    gates = [
        Stub("G0.scope"),
        Stub("G1.deps"),
        Stub("G1.static"),
        Stub("G3.secrets"),
        Stub("G3.sast"),
        review,
    ]

    run_gates(change, policy(), gates=gates)

    assert review.started_at is not None


def test_awaria_jednej_bramki_nie_zatrzymuje_pozostalych(repo):
    class Wybuchowa(Stub):
        def run(self, change):
            raise RuntimeError("bum")

    change = context(repo)
    zdrowa = Stub("G3.secrets")

    result = run_gates(change, policy(), gates=[Wybuchowa("G1.deps"), zdrowa])

    assert zdrowa.started_at is not None
    assert next(g for g in result.gate_results if g.gate == "G1.deps").status == "error"


def test_raport_mowi_o_poziomie_izolacji(repo):
    change = context(repo)
    result = run_gates(change, policy(), gates=[ScopeGuard({})])

    assert any("izolacj" in item or "sieci" in item for item in result.not_checked)
