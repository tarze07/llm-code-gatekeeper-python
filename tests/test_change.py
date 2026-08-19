from __future__ import annotations

from gatekeeper.core.change import (
    ChangeContext,
    glob_to_regex,
    matches_any,
    parse_unified_diff,
)

DIFF = """diff --git a/src/app.py b/src/app.py
index 1111111..2222222 100644
--- a/src/app.py
+++ b/src/app.py
@@ -3,0 +4,2 @@ def hello():
+    log.info("start")
+    check()
@@ -10 +12 @@ def bye():
-    return 1
+    return 2
diff --git a/removed.txt b/removed.txt
deleted file mode 100644
--- a/removed.txt
+++ /dev/null
@@ -1 +0,0 @@
-stare
"""


def test_parse_unified_diff_liczy_linie_po_stronie_head():
    result = parse_unified_diff(DIFF)
    assert result["src/app.py"] == {4, 5, 12}
    assert "removed.txt" not in result  # plik usunięty nie ma strony head


def test_glob_obsluguje_podwojna_gwiazdke():
    assert glob_to_regex("**/auth/**").match("services/api/auth/login.py")
    assert glob_to_regex("**/auth/**").match("auth/login.py")
    assert not glob_to_regex("**/auth/**").match("services/authorization.py")
    # pojedyncza gwiazdka nie przekracza separatora katalogów
    assert not glob_to_regex("src/*.py").match("src/pkg/a.py")
    assert glob_to_regex("src/*.py").match("src/a.py")


def test_matches_any_na_liscie_wzorcow():
    assert matches_any("poetry.lock", ["**/*.lock"])
    assert matches_any("app/migrations/0001_init.py", ["**/migrations/**"])


def test_from_git_uzywa_merge_base_a_nie_czubka_galezi(repo):
    """Diff nie może zawierać commitów, które doszły na main po odbiciu gałęzi."""
    repo.checkout("feature", create=True)
    repo.write("src/feature.py", "x = 1\n")
    repo.commit("feature: dodaj moduł")

    repo.checkout("main")
    repo.write("src/other.py", "y = 2\n")  # cudza zmiana na main
    repo.commit("main: cudza zmiana")
    repo.checkout("feature")

    ctx = ChangeContext.from_git(repo.path, "main", "HEAD")
    assert ctx.paths() == ["src/feature.py"]


def test_pliki_generowane_sa_wykluczone_z_efektywnego_rozmiaru(repo):
    repo.checkout("feature", create=True)
    repo.write("poetry.lock", "\n".join(f"line {i}" for i in range(500)))
    repo.write("src/app.py", "def hello():\n    return 'siema'\n")
    repo.commit("feat: zmiana + lockfile")

    ctx = ChangeContext.from_git(repo.path, "main", "HEAD")
    assert ctx.total_lines > 500
    assert ctx.effective_lines < 10
    assert [f.path for f in ctx.effective_files] == ["src/app.py"]


def test_wykrywanie_ticketu_z_nazwy_galezi(repo):
    repo.checkout("feature/PROJ-42-date-format", create=True)
    repo.write("src/app.py", "def hello():\n    return 'x'\n")
    repo.commit("zmiana")

    ctx = ChangeContext.from_git(repo.path, "main", "HEAD")
    assert ctx.ticket is not None
    assert ctx.ticket.id == "PROJ-42"
    assert ctx.ticket.source == "branch"


def test_zmiana_tylko_dokumentacyjna(repo):
    repo.checkout("docs", create=True)
    repo.write("README.md", "# projekt\n\nopis\n")
    repo.commit("docs: opis")

    ctx = ChangeContext.from_git(repo.path, "main", "HEAD")
    assert ctx.is_docs_only


def test_file_at_zwraca_tresc_z_obu_stron(repo):
    repo.checkout("feature", create=True)
    repo.write("src/app.py", "def hello():\n    return 'nowe'\n")
    repo.commit("zmiana")

    ctx = ChangeContext.from_git(repo.path, "main", "HEAD")
    assert "nowe" in (ctx.file_at(ctx.head_sha, "src/app.py") or "")
    assert "hi" in (ctx.file_at(ctx.base_sha, "src/app.py") or "")
    assert ctx.file_at(ctx.base_sha, "nie-istnieje.py") is None


def test_rename_nie_jest_liczony_jako_wielki_diff(repo):
    repo.checkout("feature", create=True)
    (repo.path / "src" / "renamed.py").write_bytes((repo.path / "src" / "app.py").read_bytes())
    (repo.path / "src" / "app.py").unlink()
    repo.commit("refactor: zmiana nazwy modułu")

    ctx = ChangeContext.from_git(repo.path, "main", "HEAD")
    assert [f.status for f in ctx.files] == ["R"]
    assert ctx.effective_lines == 0
