"""Testy G0.scope: fakty o rozmiarze diffa i mapowanie `ticket → zakres`."""

from __future__ import annotations

from gatekeeper.core.change import ChangeContext
from gatekeeper.gates.g0_scope import ScopeGuard


def _scope_map(repo, mapping: str) -> None:
    repo.write("policy/scope_map.yaml", mapping)


def test_bez_ticketu_scope_map_nie_jest_sprawdzany(repo):
    repo.checkout("feature", create=True)
    repo.write("src/billing/invoice.py", "x = 1\n")
    repo.commit("zmiana bez ticketu")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = ScopeGuard({}).run(change)

    assert result.facts["diff.scope_map_matched"] is False
    assert result.facts["diff.out_of_scope_files"] == 0
    assert result.findings == []


def test_plik_poza_zakresem_ticketu_jest_flagowany(repo):
    _scope_map(repo, "components:\n  AUTH:\n    - \"src/auth/**\"\n")
    repo.commit("dodaj scope_map")
    repo.checkout("AUTH-42", create=True)
    repo.write("src/billing/invoice.py", "x = 1\n")  # poza zakresem AUTH
    repo.commit("AUTH-42: naprawa sesji, przy okazji faktury")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = ScopeGuard({}).run(change)

    assert result.facts["diff.scope_map_matched"] is True
    assert result.facts["diff.out_of_scope_files"] == 1
    assert result.status == "pass"  # flaga, nie blokada — decyduje polityka
    assert result.findings[0].rule_id == "diff.out_of_scope_files"
    assert "src/billing/invoice.py" in result.findings[0].evidence["snippet"]


def test_plik_w_zakresie_ticketu_nie_jest_flagowany(repo):
    _scope_map(repo, "components:\n  AUTH:\n    - \"src/auth/**\"\n")
    repo.commit("dodaj scope_map")
    repo.checkout("AUTH-42", create=True)
    repo.write("src/auth/session.py", "x = 1\n")
    repo.commit("AUTH-42: naprawa sesji")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = ScopeGuard({}).run(change)

    assert result.facts["diff.scope_map_matched"] is True
    assert result.facts["diff.out_of_scope_files"] == 0
    assert result.findings == []


def test_plik_testowy_jest_zawsze_w_zakresie(repo):
    _scope_map(repo, "components:\n  AUTH:\n    - \"src/auth/**\"\n")
    repo.commit("dodaj scope_map")
    repo.checkout("AUTH-42", create=True)
    repo.write("tests/test_session.py", "def test_x():\n    assert True\n")
    repo.commit("AUTH-42: test")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = ScopeGuard({}).run(change)

    assert result.facts["diff.out_of_scope_files"] == 0


def test_prefiks_bez_wpisu_w_mapie_nie_blokuje(repo):
    _scope_map(repo, "components:\n  AUTH:\n    - \"src/auth/**\"\n")
    repo.commit("dodaj scope_map")
    repo.checkout("PAY-9", create=True)  # prefiks PAY nie jest w mapie
    repo.write("src/billing/invoice.py", "x = 1\n")
    repo.commit("PAY-9: faktury")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = ScopeGuard({}).run(change)

    assert result.facts["diff.scope_map_matched"] is False
    assert result.facts["diff.out_of_scope_files"] == 0


def test_brak_pliku_scope_map_nie_wywraca_bramki(repo):
    repo.checkout("AUTH-1", create=True)
    repo.write("src/billing/invoice.py", "x = 1\n")
    repo.commit("AUTH-1: zmiana bez pliku scope_map w repo")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = ScopeGuard({}).run(change)

    assert result.facts["diff.scope_map_matched"] is False
