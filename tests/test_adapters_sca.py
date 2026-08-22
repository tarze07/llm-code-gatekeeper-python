"""Testy adapterów SCA na zapisanych próbkach prawdziwego wyjścia.

Próbki pip-audit pochodzą z realnego `pip-audit -f json -r requirements.txt`
na `urllib3==1.26.4` + `requests==2.31.0` (podatne) i `six==1.16.0` (czyste).
Próbka npm audit pochodzi z realnego `npm audit --json` na `request@2.88.2`
(łańcuch zależności z wieloma podatnościami, w tym `via` mieszające obiekty
advisory ze stringami nazw pakietów tranzytywnych — dokładnie ten przypadek,
którego parser musi pilnować). Opisy podatności są przycięte tam, gdzie
parser ich nie czyta, ale kształt JSON-a jest nietknięty.
"""

from __future__ import annotations

from pathlib import Path

from gatekeeper.adapters.sca import parse_npm_audit, parse_pip_audit
from gatekeeper.core.finding import Severity

VULNERABLE = Path(__file__).parent / "data" / "pip_audit_vulnerable.json"
CLEAN = Path(__file__).parent / "data" / "pip_audit_clean.json"
NPM_VULNERABLE = Path(__file__).parent / "data" / "npm_audit_vulnerable.json"


def test_parsowanie_pip_audit_golden_file_filtruje_do_nowych_pakietow():
    """`requirements.txt` miał tylko urllib3+requests, ale pip-audit audytuje
    też tranzytywne zależności (charset-normalizer, idna, certifi) — te nie
    są `new_packages`, więc bramka nie ma prawa ich zgłosić jako dług tego PR-a."""
    payload = VULNERABLE.read_text(encoding="utf-8")
    findings = parse_pip_audit(payload, "requirements.txt", {"urllib3", "requests"}, "G3.sca")

    packages = {f.evidence["package"] for f in findings}
    assert packages == {"urllib3", "requests"}
    assert all(f.file == "requirements.txt" for f in findings)
    assert all(f.severity == Severity.HIGH for f in findings)


def test_pip_audit_dedukuje_zdublowane_id_tej_samej_podatnosci():
    """pip-audit zwraca ten sam `id` dwa razy w jednym `dep.vulns` (dwa
    źródła danych) — bez deduplikacji ten sam CVE trafiłby do raportu dwa razy."""
    payload = VULNERABLE.read_text(encoding="utf-8")
    findings = parse_pip_audit(payload, "requirements.txt", {"urllib3"}, "G3.sca")

    ids = [f.rule_id for f in findings]
    assert len(ids) == len(set(ids))  # brak duplikatów
    assert "sca.PYSEC-2021-108" in ids


def test_pip_audit_pakiet_bez_znanych_podatnosci_golden_file():
    payload = CLEAN.read_text(encoding="utf-8")
    findings = parse_pip_audit(payload, "requirements.txt", {"six"}, "G3.sca")
    assert findings == []


def test_pusty_raport_pip_audit_nie_wywraca_adaptera():
    assert parse_pip_audit("", "requirements.txt", {"six"}, "G3.sca") == []
    assert parse_pip_audit('{"dependencies": []}', "requirements.txt", set(), "G3.sca") == []


def test_pip_audit_normalizuje_wielkosc_liter_pakietu():
    payload = CLEAN.read_text(encoding="utf-8")
    # `new_packages` przechowuje znormalizowane nazwy (PEP 503) — wielkość
    # liter w manifeście nie ma prawa zgubić dopasowania.
    findings = parse_pip_audit(payload, "requirements.txt", {"six"}, "G3.sca")
    assert findings == []
    findings = parse_pip_audit(payload, "requirements.txt", {"SIX"}, "G3.sca")
    assert findings == []  # "SIX" != znormalizowane "six" -> po prostu nie pasuje, nie wybucha


# --------------------------------------------------------------- npm audit


def test_parsowanie_npm_audit_golden_file_filtruje_do_nowych_pakietow():
    """`request` jest jedynym pakietem, który ten (hipotetyczny) PR dodaje —
    reszta (`form-data`, `qs`, `tough-cookie`, `uuid`) to tranzytywny dług,
    audytowany przez npm razem z nim, ale nie wprowadzony przez ten PR."""
    payload = NPM_VULNERABLE.read_text(encoding="utf-8")
    findings = parse_npm_audit(payload, {"request"}, "G3.sca")

    assert len(findings) == 1
    assert findings[0].evidence["package"] == "request"
    assert findings[0].rule_id == "sca.1096727"
    assert findings[0].severity == Severity.HIGH


def test_npm_audit_pomija_wpisy_via_ktore_sa_nazwami_pakietow():
    """`request`'s `via` miesza jeden obiekt advisory z czterema stringami
    (nazwy pakietów tranzytywnych) — te drugie nie mają prawa stać się
    czterema fałszywymi znaleziskami dla samego `request`."""
    payload = NPM_VULNERABLE.read_text(encoding="utf-8")
    findings = parse_npm_audit(payload, {"request"}, "G3.sca")
    assert len(findings) == 1  # nie 5


def test_npm_audit_wielu_nowych_pakietow_golden_file():
    payload = NPM_VULNERABLE.read_text(encoding="utf-8")
    findings = parse_npm_audit(
        payload, {"request", "form-data", "qs", "tough-cookie", "uuid"}, "G3.sca"
    )
    packages = {f.evidence["package"] for f in findings}
    assert packages == {"request", "form-data", "qs", "tough-cookie", "uuid"}
    assert len(findings) == 6  # form-data ma dwa advisory we `via`


def test_pusty_raport_npm_audit_nie_wywraca_adaptera():
    assert parse_npm_audit("", {"x"}, "G3.sca") == []
    assert parse_npm_audit('{"vulnerabilities": {}}', set(), "G3.sca") == []
