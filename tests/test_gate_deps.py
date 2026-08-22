from __future__ import annotations

import pytest

from gatekeeper.core.change import ChangeContext
from gatekeeper.deps.manifests import NPM, NUGET, PYPI
from gatekeeper.deps.registries import RegistryUnavailable
from gatekeeper.gates.g1_deps import DepGuard
from tests.conftest import FakeRegistry

KNOWN = {
    "requests": {"age_days": 4000},
    "httpx": {"age_days": 2000},
    "fastapi": {"age_days": 2500},
}

NUGET_CSPROJ = """<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>{deps}</ItemGroup></Project>"""


def csproj(*names: str) -> str:
    refs = "".join(f'<PackageReference Include="{n}" Version="1.0.0" />' for n in names)
    return NUGET_CSPROJ.format(deps=refs)


def build(repo, before: str, after: str, filename: str = "pyproject.toml") -> ChangeContext:
    repo.write(filename, before)
    repo.commit("baza")
    repo.checkout("feature", create=True)
    repo.write(filename, after)
    repo.commit("feat: nowa zależność")
    return ChangeContext.from_git(repo.path, "main", "HEAD")


def gate(packages: dict | None = None, nuget_packages: dict | None = None, **config) -> DepGuard:
    return DepGuard(
        config or {},
        registries={
            PYPI: FakeRegistry(PYPI, packages if packages is not None else KNOWN),
            NPM: FakeRegistry(NPM, {}),
            NUGET: FakeRegistry(NUGET, nuget_packages or {}),
        },
    )


def manifest(*deps: str) -> str:
    body = ", ".join(f'"{d}"' for d in deps)
    return f'[project]\nname = "demo"\ndependencies = [{body}]\n'


def test_halucynowany_pakiet_jest_blokowany(repo):
    change = build(repo, manifest("requests"), manifest("requests", "httpx-turbo-client"))
    result = gate().run(change)

    assert result.status == "fail"
    assert result.facts["deps.unknown_package"] is True
    finding = next(f for f in result.findings if f.rule_id == "deps.unknown_package")
    assert "httpx-turbo-client" in finding.title
    assert finding.severity == "critical"


def test_typosquat_jest_blokowany(repo):
    change = build(repo, manifest("requests"), manifest("requests", "requsts"))
    result = gate({"requsts": {"age_days": 3}}).run(change)

    assert result.facts["deps.typosquat_suspect"] is True
    finding = next(f for f in result.findings if f.rule_id == "deps.typosquat_suspect")
    assert "requests" in finding.evidence["similar_to"]


def test_stary_pakiet_o_podobnej_nazwie_to_tylko_informacja(repo):
    """Ustabilizowany pakiet nie jest podszyciem tylko dlatego, że nazywa się podobnie."""
    change = build(repo, manifest("requests"), manifest("requests", "requsts"))
    result = gate({"requsts": {"age_days": 2000}}).run(change)

    assert result.facts["deps.typosquat_suspect"] is False
    assert {f.rule_id for f in result.findings} == {"deps.similar_name"}


def test_mlody_pakiet_daje_znalezisko_high(repo):
    change = build(repo, manifest("requests"), manifest("requests", "brand-new-lib"))
    result = gate({"brand-new-lib": {"age_days": 12}}).run(change)

    assert result.facts["deps.too_young"] is True
    finding = next(f for f in result.findings if f.rule_id == "deps.too_young")
    assert finding.severity == "high"


def test_istniejaca_zaleznosc_nie_jest_sprawdzana_ponownie(repo):
    change = build(repo, manifest("requests"), manifest("requests", "httpx"))
    result = gate().run(change)

    assert result.facts["deps.new_packages"] == ["httpx"]
    assert result.status == "pass"


def test_pakiety_wewnetrzne_sa_pomijane(repo):
    change = build(repo, manifest("requests"), manifest("requests", "acme-internal-utils"))
    result = gate(internal_prefixes=["acme-"]).run(change)

    assert result.facts["deps.new_packages"] == []
    assert result.status == "pass"


def test_zmiana_bez_manifestu_nie_uruchamia_sieci(repo):
    repo.checkout("feature", create=True)
    repo.write("src/app.py", "def hello():\n    return 'x'\n")
    repo.commit("zmiana kodu")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    registry = FakeRegistry(PYPI, KNOWN)
    result = DepGuard({}, registries={PYPI: registry}).run(change)

    assert result.status == "pass"
    assert registry.calls == []


def test_niedostepny_rejestr_daje_blad_a_nie_zielona_bramke(repo):
    class Broken:
        ecosystem = PYPI

        def fetch(self, name):
            raise RegistryUnavailable("timeout")

    change = build(repo, manifest("requests"), manifest("requests", "cokolwiek"))
    result = DepGuard({}, registries={PYPI: Broken()}).run(change)

    assert result.status == "error"
    assert "nieosiągalny" in result.message


def test_requirements_txt_tez_jest_obslugiwany(repo):
    change = build(repo, "requests==2.31.0\n", "requests==2.31.0\nzmyslony-pakiet==1.0\n",
                   filename="requirements.txt")
    result = gate().run(change)

    assert result.facts["deps.unknown_package"] is True


# -------------------------------------------------------------------- nuget


def test_halucynowany_pakiet_nuget_jest_blokowany(repo):
    repo.write("Demo.csproj", csproj("Newtonsoft.Json"))
    repo.commit("baza")
    repo.checkout("feature", create=True)
    repo.write("Demo.csproj", csproj("Newtonsoft.Json", "Halucynowany.Pakiet.Ktorego.Nie.Ma"))
    repo.commit("feat: nowy pakiet NuGet")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = gate(nuget_packages={"newtonsoft.json": {"age_days": 4000}}).run(change)

    assert result.status == "fail"
    assert result.facts["deps.unknown_package"] is True
    finding = next(f for f in result.findings if f.rule_id == "deps.unknown_package")
    assert "Halucynowany.Pakiet.Ktorego.Nie.Ma" in finding.title
    assert finding.file == "Demo.csproj"


def test_mlody_pakiet_nuget_daje_znalezisko_high(repo):
    repo.write("Demo.csproj", csproj("Newtonsoft.Json"))
    repo.commit("baza")
    repo.checkout("feature", create=True)
    repo.write("Demo.csproj", csproj("Newtonsoft.Json", "Brand.New.Lib"))
    repo.commit("feat: mlody pakiet NuGet")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = gate(
        nuget_packages={
            "newtonsoft.json": {"age_days": 4000},
            "brand.new.lib": {"age_days": 10},
        }
    ).run(change)

    assert result.facts["deps.too_young"] is True
    finding = next(f for f in result.findings if f.rule_id == "deps.too_young")
    assert finding.severity == "high"


def test_directory_packages_props_jest_obslugiwany(repo):
    props = '<Project><ItemGroup>{deps}</ItemGroup></Project>'
    repo.write(
        "Directory.Packages.props",
        props.format(deps='<PackageVersion Include="Newtonsoft.Json" Version="13.0.3" />'),
    )
    repo.commit("baza")
    repo.checkout("feature", create=True)
    repo.write(
        "Directory.Packages.props",
        props.format(
            deps='<PackageVersion Include="Newtonsoft.Json" Version="13.0.3" />'
            '<PackageVersion Include="Nieznany.Pakiet" Version="1.0.0" />'
        ),
    )
    repo.commit("feat: cpm")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = gate(nuget_packages={"newtonsoft.json": {"age_days": 4000}}).run(change)

    assert result.facts["deps.unknown_package"] is True


@pytest.mark.parametrize("status", ["pass", "fail"])
def test_fakty_sa_zawsze_kompletne(repo, status):
    after = manifest("requests", "httpx") if status == "pass" else manifest("requests", "nie-ma")
    change = build(repo, manifest("requests"), after)
    result = gate().run(change)

    for fact in DepGuard.facts:
        assert fact in result.facts, f"brak faktu {fact} — polityka odwoła się do pustki"
