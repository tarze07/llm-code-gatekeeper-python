"""Testy G1.static na prawdziwych binariach (integracja, nie golden file).

Adaptery mają już testy na zapisanym wyjściu (`test_adapters_linters.py`,
`test_adapters_dotnet.py`); tu sprawdzamy, że sama bramka — filtrowanie do
zmienionych linii, decyzja `pass`/`fail`, obsługa braku narzędzia — działa
na żywych binariach. Testy Pythona pomijane bez ruffa, testy TS bez tsc,
testy C# bez dotnet — każda grupa niezależnie.
"""

from __future__ import annotations

import shutil

import pytest

from gatekeeper.core.change import ChangeContext
from gatekeeper.gates.g1_static import StaticGuard

requires_ruff = pytest.mark.skipif(
    shutil.which("ruff") is None, reason="ruff niedostępny — zainstaluj `.[gates]`"
)
requires_tsc = pytest.mark.skipif(
    shutil.which("tsc") is None, reason="tsc niedostępny (npm i -g typescript)"
)
requires_dotnet = pytest.mark.skipif(
    shutil.which("dotnet") is None, reason="dotnet niedostępny (.NET SDK)"
)


@requires_ruff
def test_brak_zmienionych_plikow_pythona_przechodzi_bez_uruchamiania_narzedzi(repo):
    repo.checkout("feature", create=True)
    repo.write("README.md", "# projekt\n\nnowy opis\n")
    repo.commit("docs: opis")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = StaticGuard({}).run(change)

    assert result.status == "pass"
    assert result.facts["static.python_files_checked"] == 0


@requires_ruff
def test_niebezpieczny_wzorzec_w_zmienionej_linii_blokuje(repo):
    repo.checkout("feature", create=True)
    repo.write(
        "src/risky.py",
        "def load(data):\n"
        "    try:\n"
        "        return data['x']\n"
        "    except:\n"  # E722 — nie jest w RUFF_HIGH_PREFIXES
        "        pass\n",  # S110 razem z E722 -> try-except-pass, S w prefiksach -> HIGH
    )
    repo.commit("feat: ryzykowny kod")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = StaticGuard({}).run(change)

    assert result.status == "fail"
    assert result.facts["static.high_severity_count"] >= 1
    assert any(f.rule_id == "ruff.S110" for f in result.findings)


@requires_ruff
def test_bezpieczny_kod_przechodzi(repo):
    repo.checkout("feature", create=True)
    repo.write("src/clean.py", "def add(a: int, b: int) -> int:\n    return a + b\n")
    repo.commit("feat: dodawanie")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = StaticGuard({"require_mypy": False}).run(change)

    assert result.status == "pass"


@requires_ruff
def test_wymyslone_wywolanie_api_blokuje_gdy_mypy_wymagany(repo):
    """Klasa defektu, dla której ta bramka istnieje: wywołanie API, którego nie ma."""
    repo.checkout("feature", create=True)
    repo.write(
        "src/typed.py",
        "def add(a: int, b: int) -> int:\n"
        "    return a + b\n\n"
        "def use() -> None:\n"
        "    add('x', 'y')\n",
    )
    repo.commit("feat: użycie")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = StaticGuard({"require_mypy": True}).run(change)

    assert result.status == "fail"
    assert any(f.rule_id == "mypy.arg-type" for f in result.findings)
    assert result.facts["static.mypy_available"] is True


@requires_ruff
def test_znaleziska_poza_zmienionymi_liniami_sa_odfiltrowane(repo):
    """Defekt w linii, której PR nie ruszył, nie ma prawa zablokować tego PR-a."""
    repo.write("src/legacy.py", "import os\n\n\ndef ok():\n    return 1\n")
    repo.commit("baza z długiem")  # `os` nieużywany od zawsze
    repo.checkout("feature", create=True)
    repo.write(
        "src/legacy.py",
        "import os\n\n\ndef ok():\n    return 1\n\n\ndef nowa():\n    return 2\n",
    )
    repo.commit("feat: nowa funkcja, stary dług zostaje")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = StaticGuard({"require_mypy": False}).run(change)

    assert result.status == "pass"
    assert not any(f.rule_id == "ruff.F401" for f in result.findings)


def test_brak_ruffa_jest_bledem_bramki(repo, monkeypatch):
    repo.checkout("feature", create=True)
    repo.write("src/app.py", "x = 1\n")
    repo.commit("zmiana")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    monkeypatch.setattr(shutil, "which", lambda name: None)
    result = StaticGuard({}).run(change)

    assert result.status == "error"
    assert result.facts["static.ruff_available"] is False


# --------------------------------------------------------------------- ts/js


@requires_tsc
def test_ts_bez_tsconfig_przechodzi_bez_wolania_tsc(repo):
    repo.checkout("feature", create=True)
    repo.write("app.ts", "export const x: number = 'nie liczba';\n")
    repo.commit("feat: ts bez configu")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = StaticGuard({}).run(change)

    assert result.status == "pass"
    assert result.facts["static.ts_files_checked"] == 1
    assert result.facts["static.tsconfig_found"] is False


@requires_tsc
def test_wymyslone_wywolanie_api_w_ts_blokuje(repo):
    repo.checkout("feature", create=True)
    repo.write(
        "tsconfig.json",
        '{"compilerOptions": {"strict": true, "noEmit": true, "target": "ES2020", '
        '"module": "commonjs"}, "include": ["*.ts"]}\n',
    )
    repo.write(
        "app.ts",
        "function add(a: number, b: number): number {\n"
        "  return a + b;\n"
        "}\n\n"
        'add("x", "y");\n',
    )
    repo.commit("feat: ts z halucynowanym wywolaniem")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = StaticGuard({}).run(change)

    assert result.status == "fail"
    assert any(f.rule_id == "tsc.TS2345" for f in result.findings)
    assert result.facts["static.tsc_available"] is True


@requires_tsc
def test_eslint_bez_configu_przechodzi_bez_wolania_narzedzia(repo):
    repo.checkout("feature", create=True)
    repo.write("app.js", "eval('cokolwiek');\n")
    repo.commit("feat: js bez configu eslinta")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = StaticGuard({}).run(change)

    assert result.status == "pass"
    assert result.facts["static.js_files_checked"] == 1
    assert result.facts["static.eslint_config_found"] is False


@requires_tsc
def test_eslint_z_configem_lapie_reguly_problem(repo):
    repo.checkout("feature", create=True)
    repo.write(
        "eslint.config.js",
        "module.exports = [{ rules: { 'no-eval': 'error' }, "
        "languageOptions: { ecmaVersion: 2020, sourceType: 'script' } }];\n",
    )
    repo.write("app.js", "function run(input) {\n  return eval(input);\n}\n")
    repo.commit("feat: js z eval")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = StaticGuard({}).run(change)

    assert result.status == "fail"
    assert any(f.rule_id == "eslint.no-eval" for f in result.findings)
    assert result.facts["static.eslint_available"] is True


# ------------------------------------------------------------------------ c#


@requires_dotnet
def test_csharp_bez_csproj_przechodzi_bez_wolania_dotneta(repo):
    repo.checkout("feature", create=True)
    repo.write("Loose.cs", "namespace X;\npublic class Loose {}\n")
    repo.commit("feat: cs bez projektu")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = StaticGuard({}).run(change)

    assert result.status == "pass"
    assert result.facts["static.csharp_files_checked"] == 1
    assert result.facts["static.csproj_found"] is False


@requires_dotnet
def test_wymyslone_wywolanie_api_w_csharp_blokuje(repo, tmp_path):
    import subprocess

    def dotnet_(*args):
        subprocess.run(["dotnet", *args], cwd=repo.path, check=True, capture_output=True)

    dotnet_("new", "classlib", "-n", "Demo", "-o", ".")
    repo.commit("baza: szkielet projektu")
    dotnet_("restore", "-v", "quiet")

    repo.checkout("feature", create=True)
    repo.write(
        "Calc.cs",
        "namespace Demo;\n\npublic class Calc\n{\n"
        "    public int Add(int a, string b)\n    {\n        return a + b;\n    }\n}\n",
    )
    repo.commit("feat: cs z bledem typu")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = StaticGuard({}).run(change)

    assert result.status == "fail"
    assert any(f.rule_id == "dotnet.CS0029" for f in result.findings)
    assert result.facts["static.dotnet_available"] is True
