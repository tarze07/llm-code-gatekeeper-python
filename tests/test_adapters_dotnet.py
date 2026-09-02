"""Testy adaptera `dotnet build` (G1.static) na zapisanej próbce prawdziwego
wyjścia — nagranej na SDK 8.0, nie z dokumentacji. `dotnet build` dzieli
format diagnostyk z tsc (wspólny parser w `adapters/base.py`), więc tu
testujemy głównie to, co jest specyficzne dla .NET-a: dopisek `[projekt.csproj]`.

Odnajdywanie projektów i `dotnet list package --vulnerable` mają własny
plik testowy: `test_adapters_dotnet_projects.py` (core, współdzielone z
G3.sca) — patrz `adapters/dotnet_projects.py`.
"""

from __future__ import annotations

from pathlib import Path

from gatekeeper.adapters.dotnet import parse_dotnet_build
from gatekeeper.core.finding import Severity

BUILD_GOLDEN = Path(__file__).parent / "data" / "dotnet_build_output.txt"
REPO = Path("/repo")


def test_parsowanie_dotnet_build_golden_file():
    findings = parse_dotnet_build(BUILD_GOLDEN.read_text(encoding="utf-8"), REPO, "G1.static")

    assert len(findings) == 2
    by_rule = {f.rule_id: f for f in findings}
    assert by_rule["dotnet.CS0029"].severity == Severity.HIGH
    assert by_rule["dotnet.CS0029"].file == "Calc.cs"
    assert by_rule["dotnet.CS0029"].line == 8
    assert by_rule["dotnet.CS0219"].severity == Severity.MEDIUM  # warning, nie error


def test_dotnet_build_odcina_dopisek_projektu_od_tresci():
    findings = parse_dotnet_build(BUILD_GOLDEN.read_text(encoding="utf-8"), REPO, "G1.static")
    assert all("[" not in f.title and "csproj" not in f.title for f in findings)


def test_pusty_raport_dotnet_build_nie_wywraca_adaptera():
    assert parse_dotnet_build("", REPO, "G1.static") == []
    assert parse_dotnet_build("Build succeeded.\n    0 Warning(s)\n", REPO, "G1.static") == []
