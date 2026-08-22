from __future__ import annotations

import pytest

from gatekeeper.deps import manifests, typosquat
from gatekeeper.deps.manifests import NPM, NUGET, PYPI, Dependency

PYPROJECT = """
[project]
name = "demo"
dependencies = ["requests>=2.31", "pydantic ~= 2.0", "typer"]

[project.optional-dependencies]
dev = ["pytest>=8", "ruff"]

[dependency-groups]
lint = ["mypy"]
"""

POETRY = """
[tool.poetry.dependencies]
python = "^3.12"
httpx = "^0.27"

[tool.poetry.group.dev.dependencies]
pytest = "^8.0"
"""

REQUIREMENTS = """
# komentarz
requests==2.31.0
pydantic[email]>=2.0  # z ekstrasami
uvicorn ; python_version >= "3.12"
-r base.txt
--index-url https://example.com/simple
git+https://github.com/example/pkg.git
"""

PACKAGE_JSON = """
{
  "dependencies": {"react": "^18.0.0", "@babel/core": "^7.0.0"},
  "devDependencies": {"vitest": "^1.0.0"},
  "optionalDependencies": {"local-thing": "file:../local"}
}
"""

CSPROJ = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="Serilog" Version="3.1.1" />
  </ItemGroup>
</Project>
"""

DIRECTORY_PACKAGES_PROPS = """<Project>
  <ItemGroup>
    <PackageVersion Include="Newtonsoft.Json" Version="13.0.3" />
  </ItemGroup>
</Project>
"""

PACKAGES_CONFIG = """<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="13.0.3" targetFramework="net472" />
</packages>
"""


def names(deps: set[Dependency]) -> set[str]:
    return {d.name for d in deps}


def test_parsowanie_pyproject_pep621_i_pep735():
    assert names(manifests.parse_pyproject(PYPROJECT)) == {
        "requests",
        "pydantic",
        "typer",
        "pytest",
        "ruff",
        "mypy",
    }


def test_parsowanie_poetry_pomija_pythona():
    assert names(manifests.parse_pyproject(POETRY)) == {"httpx", "pytest"}


def test_parsowanie_requirements_pomija_opcje_i_urle():
    assert names(manifests.parse_requirements(REQUIREMENTS)) == {
        "requests",
        "pydantic",
        "uvicorn",
    }


def test_parsowanie_package_json_pomija_zaleznosci_lokalne():
    assert names(manifests.parse_package_json(PACKAGE_JSON)) == {
        "react",
        "@babel/core",
        "vitest",
    }


def test_parsowanie_csproj_sdk_style():
    deps = manifests.parse_csproj_like(CSPROJ, "Demo.csproj")
    assert names(deps) == {"Newtonsoft.Json", "Serilog"}
    assert all(d.ecosystem == NUGET for d in deps)


def test_parsowanie_directory_packages_props():
    deps = manifests.parse_csproj_like(DIRECTORY_PACKAGES_PROPS, "Directory.Packages.props")
    assert names(deps) == {"Newtonsoft.Json"}


def test_parsowanie_packages_config_legacy():
    deps = manifests.parse_csproj_like(PACKAGES_CONFIG, "packages.config")
    assert names(deps) == {"Newtonsoft.Json"}


def test_csproj_niepoprawny_xml_zwraca_pusty_zbior():
    assert manifests.parse_csproj_like("<not valid xml", "Demo.csproj") == set()


def test_manifest_kind_rozpoznaje_pliki_dotnet():
    assert manifests.manifest_kind("Demo.csproj") == "csproj"
    assert manifests.manifest_kind("Demo.fsproj") == "csproj"
    assert manifests.manifest_kind("Directory.Packages.props") == "directory.packages.props"
    assert manifests.manifest_kind("packages.config") == "packages.config"


def test_parse_manifest_dispatchuje_do_csproj():
    deps = manifests.parse_manifest("Demo.csproj", CSPROJ)
    assert {d.ecosystem for d in deps} == {NUGET}


def test_normalizacja_pep503_uznaje_nazwy_za_rownowazne():
    before = {Dependency(PYPI, "typing_extensions", "m")}
    after = {Dependency(PYPI, "typing-extensions", "m"), Dependency(PYPI, "nowy", "m")}
    assert [d.name for d in manifests.diff_dependencies(before, after)] == ["nowy"]


def test_diff_dependencies_zwraca_tylko_nowe():
    before = {Dependency(PYPI, "requests", "m")}
    after = {Dependency(PYPI, "requests", "m"), Dependency(PYPI, "httpx", "m")}
    assert [d.name for d in manifests.diff_dependencies(before, after)] == ["httpx"]


# ------------------------------------------------------------- typosquat


@pytest.mark.parametrize(
    "name,expected_hit",
    [
        ("requsts", "requests"),
        ("python-dotnev", "python-dotenv"),
        ("beautifulsup4", "beautifulsoup4"),
        ("rnatplotlib", "matplotlib"),  # homoglif rn → m
        ("numpyy", "numpy"),
    ],
)
def test_wykrywanie_typosquatow_pypi(name, expected_hit):
    hits = [n.candidate for n in typosquat.nearest_popular(PYPI, name)]
    assert expected_hit in hits


@pytest.mark.parametrize("name", ["requests", "numpy", "pydantic", "django", "typer"])
def test_popularne_pakiety_nie_sa_zglaszane(name):
    assert typosquat.nearest_popular(PYPI, name) == []


@pytest.mark.parametrize(
    "name",
    ["opentelemetry-instrumentation-fastapi", "django-storages", "sqlalchemy-utils"],
)
def test_typowe_nazwy_pochodne_nie_dają_falszywych_alarmow(name):
    assert typosquat.nearest_popular(PYPI, name) == []


def test_krotkie_nazwy_maja_wezszy_prog():
    # przy dystansie 2 „ws" pasowałoby do połowy rejestru
    assert typosquat.max_distance_for("ws") == 1
    assert typosquat.max_distance_for("opentelemetry") == 2


def test_wykrywanie_typosquatow_npm():
    hits = [n.candidate for n in typosquat.nearest_popular(NPM, "loadash")]
    assert "lodash" in hits


def test_wykrywanie_typosquatow_nuget():
    hits = [n.candidate for n in typosquat.nearest_popular(NUGET, "Newtonsoft.Jsonn")]
    assert "newtonsoft.json" in hits


@pytest.mark.parametrize("name", ["Newtonsoft.Json", "Serilog", "AutoMapper", "Dapper"])
def test_popularne_pakiety_nuget_nie_sa_zglaszane(name):
    assert typosquat.nearest_popular(NUGET, name) == []


@pytest.mark.parametrize(
    "a,b,cutoff,expected",
    [
        ("abc", "abc", 2, 0),
        ("abc", "abd", 2, 1),
        ("abc", "acb", 2, 1),  # transpozycja to jedna operacja
        ("abcdef", "xyzuvw", 2, 3),  # przerwane po przekroczeniu progu
    ],
)
def test_dystans_damerau_levenshteina(a, b, cutoff, expected):
    assert typosquat.damerau_levenshtein(a, b, cutoff) == expected
