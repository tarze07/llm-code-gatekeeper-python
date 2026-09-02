"""Testy G3.sast na prawdziwym semgrepie i realnym zestawie reguł „nigdy".

Reguły same mają testy pozytywne/negatywne (`semgrep --test`, kamień 3);
tu sprawdzamy, że bramka poprawnie filtruje trafienia do zmienionych linii
i przekłada je na decyzję. Pomijane, gdy semgrep nie jest zainstalowany.
"""

from __future__ import annotations

import shutil

import pytest
from gatekeeper_core.core.change import ChangeContext
from gatekeeper_core.gates.g3_sast import SastGuard

pytestmark = pytest.mark.skipif(
    shutil.which("semgrep") is None, reason="semgrep niedostępny — zainstaluj `.[gates]`"
)


def test_eval_na_wejsciu_w_zmienionej_linii_blokuje(repo):
    repo.checkout("feature", create=True)
    repo.write(
        "src/handler.py",
        "def handle(request):\n    return eval(request.get('expr'))\n",
    )
    repo.commit("feat: dynamiczna ewaluacja")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = SastGuard({}).run(change)

    assert result.status == "fail"
    assert result.facts["sast.critical_count"] >= 1
    assert "sast.no-eval-on-input" in result.facts["sast.rule_ids"]
    finding = next(f for f in result.findings if f.rule_id == "sast.no-eval-on-input")
    assert finding.file == "src/handler.py"


def test_niegrozny_kod_przechodzi(repo):
    repo.checkout("feature", create=True)
    repo.write("src/clean.py", "def add(a, b):\n    return a + b\n")
    repo.commit("feat: dodawanie")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = SastGuard({}).run(change)

    assert result.status == "pass"
    assert result.facts["sast.finding_count"] == 0


def test_wzorzec_poza_zmienionymi_liniami_nie_blokuje_tego_pr(repo):
    # Nowa linia musi być daleko od starej — `only_changed_lines` ma świadomy
    # margines +3 linii kontekstu, więc zbyt bliski sąsiedztwo dałoby fałszywy
    # negatyw testu, nie błąd bramki.
    padding = "\n".join(f"# {i}" for i in range(20))
    repo.write(
        "src/legacy.py", f"def old(request):\n    return eval(request.get('expr'))\n\n{padding}\n"
    )
    repo.commit("dług sprzed bramy")
    repo.checkout("feature", create=True)
    repo.write(
        "src/legacy.py",
        f"def old(request):\n    return eval(request.get('expr'))\n\n{padding}\n\n\ndef nowa():\n"
        "    return 1\n",
    )
    repo.commit("feat: nowa funkcja, stary dług zostaje")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = SastGuard({}).run(change)

    assert result.status == "pass"
    assert result.facts["sast.finding_count"] == 0


def test_brak_semgrepa_jest_bledem_bramki(repo, monkeypatch):
    repo.checkout("feature", create=True)
    repo.write("src/app.py", "x = 1\n")
    repo.commit("zmiana")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    monkeypatch.setattr(shutil, "which", lambda name: None)
    result = SastGuard({}).run(change)

    assert result.status == "error"
