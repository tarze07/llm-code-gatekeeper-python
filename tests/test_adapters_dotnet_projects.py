"""Testy odnajdywania projektów .NET i `dotnet list package --vulnerable`
(`adapters/dotnet_projects.py`, core) — na zapisanej próbce prawdziwego
wyjścia, nagranej na SDK 8.0. Wydzielone z `test_adapters_dotnet.py`, bo ten
moduł jest współdzielony przez `CsharpStaticChecker` (G1.static, csharp-pack)
i `deps.ecosystems.NuGetEcosystem` (G3.sca, core).
"""

from __future__ import annotations

from pathlib import Path

from gatekeeper.adapters.dotnet_projects import (
    find_project_for,
    parse_dotnet_list_vulnerable,
    projects_for,
)
from gatekeeper.core.finding import Severity

VULN_GOLDEN = Path(__file__).parent / "data" / "dotnet_list_vulnerable.json"
REPO = Path("/repo")


# ------------------------------------------------------------- odnajdywanie projektów


def test_find_project_for_najblizszy_przodek(tmp_path):
    (tmp_path / "src" / "Api").mkdir(parents=True)
    (tmp_path / "src" / "Api" / "Api.csproj").write_text("<Project />")
    (tmp_path / "src" / "Api" / "Controllers").mkdir()
    (tmp_path / "src" / "Api" / "Controllers" / "Home.cs").write_text("// x")

    assert find_project_for(tmp_path, "src/Api/Controllers/Home.cs") == "src/Api/Api.csproj"


def test_find_project_for_brak_projektu_w_calym_repo(tmp_path):
    (tmp_path / "Home.cs").write_text("// x")
    assert find_project_for(tmp_path, "Home.cs") is None


def test_projects_for_deduplikuje_i_sortuje(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "A.csproj").write_text("<Project />")
    (tmp_path / "a" / "One.cs").write_text("// x")
    (tmp_path / "a" / "Two.cs").write_text("// x")

    assert projects_for(tmp_path, ["a/One.cs", "a/Two.cs"]) == ["a/A.csproj"]


# ---------------------------------------------------------- dotnet list --vulnerable


def test_parsowanie_dotnet_list_vulnerable_golden_file_filtruje_do_nowych_pakietow():
    payload = VULN_GOLDEN.read_text(encoding="utf-8")
    findings = parse_dotnet_list_vulnerable(payload, REPO, {"system.net.http"}, "G3.sca")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "sca.GHSA-7jgj-8wvc-jh57"
    assert finding.file == "VulnDemo.csproj"
    assert finding.evidence["package"] == "System.Net.Http"
    assert finding.severity == Severity.HIGH


def test_dotnet_list_vulnerable_pakiet_spoza_new_packages_jest_pomijany():
    """Golden file audytuje `System.Net.Http`, ale ten PR go nie dodaje —
    to dług zastanych zależności, nie coś, co ten PR wnosi."""
    payload = VULN_GOLDEN.read_text(encoding="utf-8")
    findings = parse_dotnet_list_vulnerable(payload, REPO, {"newtonsoft.json"}, "G3.sca")
    assert findings == []


def test_dotnet_list_vulnerable_obsluguje_pakiety_tranzytywne():
    """`--include-transitive` umieszcza część znalezisk w `transitivePackages`,
    nie `topLevelPackages` — ten sam kształt wpisu, inny klucz nadrzędny."""
    payload = (
        '{"projects": [{"path": "/repo/App.csproj", "frameworks": [{"framework": "net8.0", '
        '"transitivePackages": [{"id": "Newtonsoft.Json", "resolvedVersion": "9.0.1", '
        '"vulnerabilities": [{"severity": "Moderate", '
        '"advisoryurl": "https://github.com/advisories/GHSA-5crp-9r3c-p9vr"}]}]}]}]}'
    )
    findings = parse_dotnet_list_vulnerable(payload, REPO, {"newtonsoft.json"}, "G3.sca")
    assert len(findings) == 1
    assert findings[0].rule_id == "sca.GHSA-5crp-9r3c-p9vr"


def test_pusty_raport_dotnet_list_vulnerable_nie_wywraca_adaptera():
    assert parse_dotnet_list_vulnerable("", REPO, {"x"}, "G3.sca") == []
    assert parse_dotnet_list_vulnerable('{"projects": []}', REPO, set(), "G3.sca") == []
