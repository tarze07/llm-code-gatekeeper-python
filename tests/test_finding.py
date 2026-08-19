from __future__ import annotations

import pytest

from gatekeeper.core.finding import Finding, Severity, compute_fingerprint


def make(**kwargs) -> Finding:
    base = dict(
        gate="G1.deps",
        rule_id="deps.unknown_package",
        severity=Severity.HIGH,
        title="tytuł",
        failure_scenario="przy wejściu X funkcja zwróci Y zamiast Z",
    )
    base.update(kwargs)
    return Finding(**base)


def test_severity_jest_porzadkiem_liniowym():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO
    assert Severity.HIGH >= "high"
    assert Severity.parse("CRITICAL") is Severity.CRITICAL
    assert Severity.HIGH == "high"  # StrEnum nadal porównuje się z tekstem


def test_severity_odrzuca_nieznana_wage():
    with pytest.raises(ValueError):
        Severity.parse("straszne")


def test_fingerprint_nie_zalezy_od_numeru_linii():
    a = make(file="src/app.py", line=10, evidence={"snippet": "import foo"})
    b = make(file="src/app.py", line=317, evidence={"snippet": "import   foo"})
    assert a.fingerprint == b.fingerprint


def test_fingerprint_zalezy_od_pliku_i_reguly():
    a = make(file="src/a.py", evidence={"snippet": "x"})
    b = make(file="src/b.py", evidence={"snippet": "x"})
    c = make(file="src/a.py", rule_id="deps.too_young", evidence={"snippet": "x"})
    assert len({a.fingerprint, b.fingerprint, c.fingerprint}) == 3


def test_znalezisko_bez_scenariusza_awarii_jest_bledem():
    # Wymóg z PLAN.md §G4 egzekwowany dla wszystkich bramek, nie tylko dla LLM.
    with pytest.raises(ValueError, match="scenariusza awarii"):
        make(failure_scenario="   ")


def test_waga_sortowania_laczy_severity_i_pewnosc():
    pewne_medium = make(severity=Severity.MEDIUM, confidence=1.0)
    niepewne_high = make(severity=Severity.HIGH, confidence=0.3)
    assert niepewne_high.weight > pewne_medium.weight


def test_compute_fingerprint_jest_stabilny_miedzy_uruchomieniami():
    assert compute_fingerprint("r", "f.py", " a  b ") == compute_fingerprint("r", "f.py", "a b")
