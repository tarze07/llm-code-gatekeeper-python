"""Przebieg całości: od diffa do decyzji.

Te testy pełnią funkcję zalążka zestawu kalibracyjnego z PLAN.md §6 — celowo
zepsute PR-y, na których brama musi zadziałać. W kamieniu 3 przenoszą się do
`calibration/` i uruchamiają co tydzień.
"""

from __future__ import annotations

import json

from gatekeeper_core.core.change import ChangeContext
from gatekeeper_core.core.finding import Verdict
from gatekeeper_core.core.policy import Policy
from gatekeeper_core.core.report import MARKER, render_check_runs, render_json, render_markdown
from gatekeeper_core.core.sequence import run_gates
from gatekeeper_core.core.store import Store
from gatekeeper_core.deps.manifests import PYPI
from gatekeeper_core.gates.g0_scope import ScopeGuard
from gatekeeper_core.gates.g1_deps import DepGuard
from gatekeeper_core.gates.g2_crossverify import CrossVerify

from tests.conftest import FakeRegistry

POLICY_PATH = "policy/gates.yaml"


def gates(packages: dict | None = None) -> list:
    return [
        ScopeGuard({}),
        DepGuard({}, registries={PYPI: FakeRegistry(PYPI, packages or {"requests": {}})}),
    ]


def manifest(*deps: str) -> str:
    body = ", ".join(f'"{d}"' for d in deps)
    return f'[project]\nname = "demo"\ndependencies = [{body}]\n'


def policy() -> Policy:
    return Policy.load(POLICY_PATH, "policy/exceptions.yaml")


def test_polityka_w_repo_jest_poprawna():
    from gatekeeper_core.gates import known_facts, known_gate_ids

    assert policy().lint(known_facts(), known_gate_ids()) == []


def test_pr_z_halucynowanym_pakietem_jest_blokowany(repo):
    repo.write("pyproject.toml", manifest("requests"))
    repo.commit("baza")
    repo.checkout("feature", create=True)
    repo.write("pyproject.toml", manifest("requests", "fastapi-turbo-utils"))
    repo.write("src/app.py", "import fastapi_turbo_utils\n")
    repo.commit("feat: przyspiesz API")

    change = ChangeContext.from_git(repo.path, "main", "HEAD")
    result = run_gates(change, policy(), gates=gates())

    assert result.decision.verdict is Verdict.BLOCK
    assert any(r.rule == "deps.unknown_package" for r in result.decision.reasons)

    markdown = render_markdown(result)
    assert MARKER in markdown
    assert "fastapi-turbo-utils" in markdown
    assert "BLOCK" in markdown


def test_pr_zbyt_duzy_jest_blokowany_ale_lockfile_sie_nie_liczy(repo):
    repo.checkout("feature", create=True)
    for i in range(20):
        repo.write(f"src/mod_{i}.py", "\n".join(f"line_{j} = {j}" for j in range(30)))
    repo.write("poetry.lock", "\n".join(f"entry {i}" for i in range(2000)))
    repo.commit("feat: wielkie przepisanie")

    change = ChangeContext.from_git(repo.path, "main", "HEAD")
    result = run_gates(change, policy(), gates=gates())

    assert result.decision.verdict is Verdict.BLOCK
    rules = {r.rule for r in result.decision.reasons}
    assert "diff.effective_lines" in rules
    assert result.facts["diff.effective_lines"] == 600  # 20 × 30, bez lockfile'a
    assert result.facts["diff.total_lines"] > 2000


def test_maly_czysty_pr_przechodzi(repo):
    repo.checkout("feature", create=True)
    repo.write("src/app.py", "def hello():\n    return 'siema'\n")
    repo.commit("fix: literówka")

    change = ChangeContext.from_git(repo.path, "main", "HEAD")
    result = run_gates(change, policy(), gates=gates())

    assert result.decision.verdict is Verdict.PASS
    assert result.decision.reasons == []


def test_nowa_zaleznosc_kieruje_do_czlowieka(repo):
    repo.write("pyproject.toml", manifest("requests"))
    repo.commit("baza")
    repo.checkout("feature", create=True)
    repo.write("pyproject.toml", manifest("requests", "httpx"))
    repo.commit("feat: klient http")

    change = ChangeContext.from_git(repo.path, "main", "HEAD")
    result = run_gates(change, policy(), gates=gates({"requests": {}, "httpx": {"age_days": 2000}}))

    assert result.decision.verdict is Verdict.PASS_WITH_REVIEW
    assert any(r.rule == "deps.new_external_package" for r in result.decision.reasons)


def test_zmiana_w_auth_kieruje_do_czlowieka(repo):
    repo.checkout("feature", create=True)
    repo.write("src/auth/session.py", "def refresh():\n    return None\n")
    repo.commit("feat: odświeżanie sesji")

    change = ChangeContext.from_git(repo.path, "main", "HEAD")
    result = run_gates(change, policy(), gates=gates())

    assert result.decision.verdict is Verdict.PASS_WITH_REVIEW
    assert "src/auth/session.py" in result.decision.reasons[0].detail


def test_sciezka_szybka_dla_zmiany_dokumentacyjnej(repo):
    repo.checkout("docs", create=True)
    repo.write("README.md", "# projekt\n" + "opis\n" * 500)
    repo.commit("docs: rozbudowany opis")

    change = ChangeContext.from_git(repo.path, "main", "HEAD")
    result = run_gates(change, policy(), gates=gates())

    # Duży diff dokumentacyjny nie ma być blokowany, ale ma być jawnie oznaczony.
    assert result.decision.verdict is Verdict.BLOCK  # limit linii nadal działa
    assert any("ścieżce szybkiej" in item for item in result.not_checked)

    # Pominięte bramki są w raporcie z powodem, nie znikają po cichu.
    pominiete = {g.gate: g.message for g in result.gate_results if g.status == "skipped"}
    assert "G1.deps" in pominiete
    assert "ścieżka szybka" in pominiete["G1.deps"]


def test_awaria_bramki_nie_wywraca_przebiegu(repo):
    class Broken(ScopeGuard):
        id = "G0.scope"

        def run(self, change):
            raise RuntimeError("bum")

    repo.checkout("feature", create=True)
    repo.write("src/app.py", "x = 1\n")
    repo.commit("zmiana")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = run_gates(change, policy(), gates=[Broken({})])

    assert result.gate_results[0].status == "error"
    assert "bum" in result.gate_results[0].message
    assert result.decision.verdict is Verdict.PASS_WITH_REVIEW  # on_gate_error: review


def test_raport_json_i_check_runy_sa_serializowalne(repo):
    repo.checkout("feature", create=True)
    repo.write("src/app.py", "x = 1\n")
    repo.commit("zmiana")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")
    result = run_gates(change, policy(), gates=gates())

    payload = json.loads(render_json(result))
    assert payload["decision"]["verdict"] == "PASS"
    assert {g["gate"] for g in payload["gates"]} == {"G0.scope", "G1.deps"}

    checks = render_check_runs(result)
    assert [c["name"] for c in checks][-1] == "gatekeeper / decyzja"
    assert all(c["head_sha"] == change.head_sha for c in checks)
    json.dumps(checks)  # payload musi przejść przez API GitHuba


def test_bezwartosciowy_test_na_razie_tylko_ostrzega(repo):
    """G2.cross_verify wchodzi przez `warn_only` — tydzień obserwacji przed blokowaniem."""
    repo.write("calc.py", "def cena(x):\n    return x * 1.23\n")
    repo.commit("baza")
    repo.checkout("feature", create=True)
    repo.write("calc.py", "def cena(x, rabat=0.0):\n    return x * 1.23 * (1 - rabat)\n")
    repo.write(
        "tests/test_calc.py",
        "from calc import cena\n\n\ndef test_cena():\n    assert cena(100) == 123.0\n",
    )
    repo.commit("feat: rabaty")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = run_gates(change, policy(), gates=[ScopeGuard({}), CrossVerify({})])

    assert result.decision.verdict is Verdict.PASS
    assert any(w.rule == "tests.pass_on_pre_change_code" for w in result.decision.warnings)
    assert "warn-only" in render_markdown(result)


def test_bezwartosciowy_test_blokuje_po_zdjeciu_warn_only(repo):
    repo.write("calc.py", "def cena(x):\n    return x * 1.23\n")
    repo.commit("baza")
    repo.checkout("feature", create=True)
    repo.write("calc.py", "def cena(x, rabat=0.0):\n    return x * 1.23 * (1 - rabat)\n")
    repo.write(
        "tests/test_calc.py",
        "from calc import cena\n\n\ndef test_cena():\n    assert cena(100) == 123.0\n",
    )
    repo.commit("feat: rabaty")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    strict = policy()
    strict.warn_only = set()
    result = run_gates(change, strict, gates=[ScopeGuard({}), CrossVerify({})])

    assert result.decision.verdict is Verdict.BLOCK
    assert any(r.rule == "tests.pass_on_pre_change_code" for r in result.decision.reasons)


def test_przebieg_zapisuje_sie_do_store_a(repo, tmp_path):
    repo.checkout("feature", create=True)
    repo.write("src/app.py", "x = 1\n")
    repo.commit("zmiana")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")
    result = run_gates(change, policy(), gates=gates())

    store = Store(tmp_path / "runs.db")
    store.record(result, change)

    row = store.runs_since(1)[0]
    assert row["run_id"] == result.run_id
    assert row["branch"] == "feature"
    assert row["verdict"] == result.decision.verdict.value


def test_raport_ogranicza_liczbe_znalezisk(repo):
    """Twardy limit z PLAN.md §9 — inaczej zespół przestaje czytać komentarz."""
    repo.write("pyproject.toml", manifest("requests"))
    repo.commit("baza")
    repo.checkout("feature", create=True)
    fake = [f"zmyslony-pakiet-{i}" for i in range(15)]
    repo.write("pyproject.toml", manifest("requests", *fake))
    repo.commit("feat: dużo zależności")

    change = ChangeContext.from_git(repo.path, "main", "HEAD")
    result = run_gates(change, policy(), gates=gates())
    markdown = render_markdown(result, max_findings=10)

    assert "Znaleziska (10 z 15)" in markdown
    assert "limit w komentarzu jest celowy" in markdown
