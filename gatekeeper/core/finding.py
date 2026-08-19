"""Wspólny model danych dla wszystkich bramek.

Jeden typ `Finding` obowiązuje zarówno adapter gitleaksa, jak i recenzenta LLM.
Dwie decyzje projektowe, które później trudno cofnąć (patrz TOOLS.md §1.1):

* `facts` są oddzielone od `findings` — polityka operuje na faktach, człowiek
  czyta znaleziska;
* `fingerprint` liczy się z treści, nie z numeru linii — inaczej każdy rebase
  odtwarza wszystkie wyciszenia.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _RANK[self.value]

    @classmethod
    def parse(cls, value: str | Severity) -> Severity:
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).strip().lower())
        except ValueError as exc:
            raise ValueError(f"nieznana waga: {value!r}") from exc

    @classmethod
    def is_severity(cls, value: Any) -> bool:
        return isinstance(value, cls) or (
            isinstance(value, str) and value.strip().lower() in _RANK
        )

    # Porządek liniowy — potrzebny polityce (`sast.severity >= high`).
    # StrEnum dziedziczy porównania po `str`, więc trzeba je nadpisać jawnie.
    def __lt__(self, other: Any) -> bool:  # type: ignore[override]
        return self.rank < Severity.parse(other).rank

    def __le__(self, other: Any) -> bool:  # type: ignore[override]
        return self.rank <= Severity.parse(other).rank

    def __gt__(self, other: Any) -> bool:  # type: ignore[override]
        return self.rank > Severity.parse(other).rank

    def __ge__(self, other: Any) -> bool:  # type: ignore[override]
        return self.rank >= Severity.parse(other).rank


def compute_fingerprint(rule_id: str, file: str | None, snippet: str | None) -> str:
    """Stabilny identyfikator znaleziska.

    Celowo *nie* zawiera numeru linii: to samo znalezisko po przesunięciu pliku
    ma zachować fingerprint, żeby wyciszenia i „nowe od ostatniego pusha"
    przeżyły rebase.
    """
    normalized = re.sub(r"\s+", " ", (snippet or "").strip())
    payload = "|".join([rule_id, file or "", normalized])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class Finding:
    gate: str
    rule_id: str
    severity: Severity
    title: str
    failure_scenario: str
    file: str | None = None
    line: int | None = None
    confidence: float = 1.0
    evidence: dict[str, Any] = field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        if not self.failure_scenario.strip():
            # Wymóg z PLAN.md §G4: bez konkretnego scenariusza awarii zgłoszenie
            # jest opinią, nie znaleziskiem. Egzekwowane dla wszystkich bramek.
            raise ValueError(f"{self.rule_id}: brak scenariusza awarii")
        object.__setattr__(self, "severity", Severity.parse(self.severity))
        if not self.fingerprint:
            snippet = self.evidence.get("snippet") or self.title
            object.__setattr__(
                self, "fingerprint", compute_fingerprint(self.rule_id, self.file, snippet)
            )

    @property
    def location(self) -> str:
        if self.file is None:
            return "—"
        return f"{self.file}:{self.line}" if self.line else self.file

    @property
    def weight(self) -> float:
        """Klucz sortowania raportu: waga przemnożona przez pewność."""
        return self.severity.rank + self.confidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate": self.gate,
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "title": self.title,
            "failure_scenario": self.failure_scenario,
            "file": self.file,
            "line": self.line,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "fingerprint": self.fingerprint,
        }


GateStatus = Literal["pass", "fail", "error", "skipped"]


@dataclass
class GateResult:
    gate: str
    status: GateStatus
    duration_s: float = 0.0
    findings: list[Finding] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)
    artifacts: list[Path] = field(default_factory=list)
    message: str = ""
    warn_only: bool = False

    @property
    def worst_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate": self.gate,
            "status": self.status,
            "duration_s": round(self.duration_s, 3),
            "warn_only": self.warn_only,
            "message": self.message,
            "facts": _jsonable(self.facts),
            "findings": [f.to_dict() for f in self.findings],
            "artifacts": [str(p) for p in self.artifacts],
        }


class Verdict(StrEnum):
    PASS = "PASS"
    PASS_WITH_REVIEW = "PASS-WITH-REVIEW"
    BLOCK = "BLOCK"


ReasonSource = Literal["blocking", "threshold", "human_review", "gate_error"]


@dataclass(frozen=True)
class Reason:
    """Powód decyzji: reguła polityki + fakt, który ją wyzwolił.

    Decyzja bez wskazania przyczyny jest dla recenzenta bezużyteczna, więc
    `Decision` nie potrafi powstać bez listy `Reason`.
    """

    source: ReasonSource
    rule: str
    detail: str
    gate: str | None = None
    fingerprints: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "rule": self.rule,
            "detail": self.detail,
            "gate": self.gate,
            "fingerprints": list(self.fingerprints),
        }


@dataclass
class Decision:
    verdict: Verdict
    reasons: list[Reason] = field(default_factory=list)
    warnings: list[Reason] = field(default_factory=list)
    suppressed: list[Reason] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "reasons": [r.to_dict() for r in self.reasons],
            "warnings": [r.to_dict() for r in self.warnings],
            "suppressed": [r.to_dict() for r in self.suppressed],
        }


@dataclass
class RunResult:
    run_id: str
    repo: str
    base_sha: str
    head_sha: str
    gate_results: list[GateResult]
    decision: Decision
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    duration_s: float = 0.0
    policy_version: int = 0
    not_checked: list[str] = field(default_factory=list)

    @property
    def findings(self) -> list[Finding]:
        return [f for g in self.gate_results for f in g.findings]

    @property
    def facts(self) -> dict[str, Any]:
        merged: dict[str, Any] = {}
        for g in self.gate_results:
            merged.update(g.facts)
        return merged

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "repo": self.repo,
            "base_sha": self.base_sha,
            "head_sha": self.head_sha,
            "started_at": self.started_at.isoformat(),
            "duration_s": round(self.duration_s, 3),
            "policy_version": self.policy_version,
            "decision": self.decision.to_dict(),
            "gates": [g.to_dict() for g in self.gate_results],
            "not_checked": self.not_checked,
        }


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    if isinstance(value, Severity):
        return value.value
    if isinstance(value, Path):
        return str(value)
    return value
