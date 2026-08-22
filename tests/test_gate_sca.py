"""Testy G3.sca — pip-audit jest zaślepiony (`monkeypatch`), tak jak rejestr
pakietów w testach G1.deps: prawdziwe zapytania do PyPI/OSV wymagają sieci
i nie mają prawa decydować, czy CI jest zielone. Parser realnego wyjścia
pip-audit ma osobne testy na zapisanej próbce (`test_adapters_sca.py`).
"""

from __future__ import annotations

from gatekeeper.adapters import dotnet, sca
from gatekeeper.core.change import ChangeContext
from gatekeeper.core.finding import Finding, Severity
from gatekeeper.gates.g3_sca import ScaGuard


def manifest(*deps: str) -> str:
    body = ", ".join(f'"{d}"' for d in deps)
    return f'[project]\nname = "demo"\ndependencies = [{body}]\n'


def test_brak_zmiany_manifestu_przechodzi_bez_wolania_narzedzia(repo, monkeypatch):
    called = []
    monkeypatch.setattr(sca, "run_pip_audit", lambda *a, **k: called.append(1) or [])

    repo.checkout("feature", create=True)
    repo.write("src/app.py", "x = 1\n")
    repo.commit("zmiana bez zależności")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = ScaGuard({}).run(change)

    assert result.status == "pass"
    assert result.facts["sca.checked_package_count"] == 0
    assert called == []


def test_nowa_zaleznosc_z_podatnoscia_blokuje(repo, monkeypatch):
    def fake_run_pip_audit(
        repo_path, sandbox, gate, requirements, new_packages, manifest, timeout_s
    ):
        assert new_packages == {"urllib3"}
        return [
            Finding(
                gate=gate,
                rule_id="sca.PYSEC-2021-108",
                severity=Severity.HIGH,
                title="urllib3==1.26.4: PYSEC-2021-108",
                failure_scenario="podatność testowa",
                file=manifest,
                evidence={"package": "urllib3", "version": "1.26.4"},
            )
        ]

    monkeypatch.setattr(sca, "run_pip_audit", fake_run_pip_audit)

    repo.write("pyproject.toml", manifest("requests"))
    repo.commit("baza")
    repo.checkout("feature", create=True)
    repo.write("pyproject.toml", manifest("requests", "urllib3"))
    repo.commit("feat: nowy klient")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = ScaGuard({}).run(change)

    assert result.status == "fail"
    assert result.facts["sca.checked_package_count"] == 1
    assert result.facts["sca.vulnerable_package_count"] == 1
    assert result.findings[0].rule_id == "sca.PYSEC-2021-108"


def test_nowa_zaleznosc_bez_podatnosci_przechodzi(repo, monkeypatch):
    monkeypatch.setattr(sca, "run_pip_audit", lambda *a, **k: [])

    repo.write("pyproject.toml", manifest("requests"))
    repo.commit("baza")
    repo.checkout("feature", create=True)
    repo.write("pyproject.toml", manifest("requests", "six"))
    repo.commit("feat: six")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = ScaGuard({}).run(change)

    assert result.status == "pass"
    assert result.facts["sca.checked_package_count"] == 1
    assert result.facts["sca.vulnerable_package_count"] == 0


def test_brak_narzedzia_to_blad_a_nie_zielona_bramka(repo, monkeypatch):
    monkeypatch.setattr(sca, "run_pip_audit", _raise_missing)

    repo.write("pyproject.toml", manifest("requests"))
    repo.commit("baza")
    repo.checkout("feature", create=True)
    repo.write("pyproject.toml", manifest("requests", "urllib3"))
    repo.commit("feat: nowy klient")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    assert ScaGuard({}).run(change).status == "error"
    assert ScaGuard({"require_tool": False}).run(change).status == "skipped"


def _raise_missing(*a, **k):
    from gatekeeper.adapters.base import ToolMissing

    raise ToolMissing("nie znaleziono programu: pip-audit")


def test_nowa_zaleznosc_npm_z_podatnoscia_blokuje(repo, monkeypatch):
    def fake_run_npm_audit(repo_path, sandbox, gate, new_packages):
        assert new_packages == {"left-pad"}
        return [
            Finding(
                gate=gate,
                rule_id="sca.1096485",
                severity=Severity.HIGH,
                title="left-pad: podatność testowa",
                failure_scenario="podatność testowa",
                file="package.json",
                evidence={"package": "left-pad"},
            )
        ]

    monkeypatch.setattr(sca, "run_npm_audit", fake_run_npm_audit)

    repo.write("package.json", '{"dependencies": {}}\n')
    repo.commit("baza")
    repo.checkout("feature", create=True)
    repo.write("package.json", '{"dependencies": {"left-pad": "1.0.0"}}\n')
    repo.commit("feat: left-pad")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = ScaGuard({}).run(change)

    assert result.status == "fail"
    assert result.facts["sca.checked_package_count"] == 1
    assert result.facts["sca.checked_ecosystems"] == ["npm"]
    assert result.findings[0].rule_id == "sca.1096485"


def test_nowa_zaleznosc_nuget_z_podatnoscia_blokuje(repo, monkeypatch):
    def fake_run_dotnet_list_vulnerable(repo_path, sandbox, gate, project, new_packages, **kw):
        assert project == "Demo.csproj"
        assert new_packages == {"newtonsoft.json"}
        return [
            Finding(
                gate=gate,
                rule_id="sca.GHSA-test",
                severity=Severity.HIGH,
                title="Newtonsoft.Json: podatność testowa",
                failure_scenario="podatność testowa",
                file=project,
                evidence={"package": "Newtonsoft.Json"},
            )
        ]

    monkeypatch.setattr(dotnet, "run_dotnet_list_vulnerable", fake_run_dotnet_list_vulnerable)

    csproj = (
        '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>{deps}</ItemGroup></Project>'
    )
    repo.write("Demo.csproj", csproj.format(deps=""))
    repo.commit("baza")
    repo.checkout("feature", create=True)
    repo.write(
        "Demo.csproj",
        csproj.format(deps='<PackageReference Include="Newtonsoft.Json" Version="9.0.1" />'),
    )
    repo.commit("feat: newtonsoft.json")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = ScaGuard({}).run(change)

    assert result.status == "fail"
    assert result.facts["sca.checked_ecosystems"] == ["nuget"]
    assert result.findings[0].rule_id == "sca.GHSA-test"
