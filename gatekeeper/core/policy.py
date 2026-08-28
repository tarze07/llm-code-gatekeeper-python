"""Polityka jako kod: parser `policy/gates.yaml` + ewaluator wyrażeń.

Świadomie *bez* `eval`. Gramatyka jest maleńka:

    WYRAŻENIE := fakt | fakt OPERATOR wartość
    OPERATOR  := >= | <= | == | != | > | < | in

Trzydzieści linii parsera zamiast wykonywania stringów z pliku konfiguracyjnego,
który — jak wszystko w tym repo — może zostać zmodyfikowany przez agenta.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any

import yaml

from .change import ChangeContext
from .finding import Decision, GateResult, Reason, Severity, Verdict

_MISSING = object()
_OPS = (">=", "<=", "==", "!=", ">", "<", " in ")
_EXPR_RE = re.compile(r"^\s*([A-Za-z_][\w.]*)\s*(>=|<=|==|!=|>|<|\bin\b)?\s*(.*?)\s*$")

ON_VIOLATION = ("block", "review", "warn")


class PolicyError(ValueError):
    pass


# --------------------------------------------------------------------------
# wyrażenia
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Expression:
    raw: str
    fact: str
    op: str | None = None
    value: Any = None

    @classmethod
    def parse(cls, raw: str) -> Expression:
        m = _EXPR_RE.match(raw)
        if not m:
            raise PolicyError(f"nie potrafię sparsować wyrażenia: {raw!r}")
        fact, op, rhs = m.group(1), m.group(2), m.group(3)
        if op is None:
            if rhs:
                raise PolicyError(f"brak operatora w wyrażeniu: {raw!r}")
            return cls(raw=raw, fact=fact)
        if not rhs:
            raise PolicyError(f"brak prawej strony w wyrażeniu: {raw!r}")
        return cls(raw=raw, fact=fact, op=op, value=_parse_value(rhs))

    def evaluate(self, facts: dict[str, Any]) -> bool:
        lhs = facts.get(self.fact, _MISSING)
        if lhs is _MISSING or lhs is None:
            # Brakujący fakt nigdy nie wyzwala reguły. Żeby to nie było cichą
            # dziurą, `Policy.lint()` odrzuca politykę odwołującą się do faktu,
            # którego żadna bramka nie deklaruje.
            return False
        if self.op is None:
            return bool(lhs) if not isinstance(lhs, (list, tuple, set, dict)) else len(lhs) > 0
        if self.op == "in":
            container = self.value if isinstance(self.value, (list, tuple, set)) else [self.value]
            return lhs in container
        return _compare(lhs, self.op, self.value)


def _parse_value(raw: str) -> Any:
    raw = raw.strip()
    if raw.startswith("[") and raw.endswith("]"):
        return [_parse_value(x) for x in raw[1:-1].split(",") if x.strip()]
    if (raw.startswith('"') and raw.endswith('"')) or (raw.startswith("'") and raw.endswith("'")):
        return raw[1:-1]
    low = raw.lower()
    if low in ("true", "false"):
        return low == "true"
    if low in ("null", "none"):
        return None
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        pass
    return raw


def _compare(lhs: Any, op: str, rhs: Any) -> bool:
    if Severity.is_severity(lhs) and Severity.is_severity(rhs):
        lhs, rhs = Severity.parse(lhs).rank, Severity.parse(rhs).rank
    elif isinstance(lhs, bool) or isinstance(rhs, bool):
        lhs, rhs = bool(lhs), bool(rhs)
    elif _is_number(lhs) and _is_number(rhs):
        lhs, rhs = float(lhs), float(rhs)
    else:
        lhs, rhs = str(lhs), str(rhs)
    dispatch: dict[str, Callable[[], bool]] = {
        ">=": lambda: lhs >= rhs,
        "<=": lambda: lhs <= rhs,
        ">": lambda: lhs > rhs,
        "<": lambda: lhs < rhs,
        "==": lambda: lhs == rhs,
        "!=": lambda: lhs != rhs,
    }
    return dispatch[op]()


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


# --------------------------------------------------------------------------
# elementy polityki
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Threshold:
    fact: str
    min: float | None = None
    max: float | None = None
    on_violation: str = "block"
    message: str = ""

    def violation(self, facts: dict[str, Any]) -> str | None:
        value = facts.get(self.fact, _MISSING)
        if value is _MISSING or value is None or not _is_number(value):
            return None
        if self.min is not None and value < self.min:
            return f"{self.fact} = {_fmt(value)} < wymagane {_fmt(self.min)}"
        if self.max is not None and value > self.max:
            return f"{self.fact} = {_fmt(value)} > dozwolone {_fmt(self.max)}"
        return None


@dataclass(frozen=True)
class PathRule:
    patterns: tuple[str, ...]

    @property
    def raw(self) -> str:
        return f"paths_match: {list(self.patterns)}"


@dataclass(frozen=True)
class Exemption:
    """Wyjątek od reguły — zawsze z właścicielem, powodem i datą wygaśnięcia."""

    rule: str
    owner: str
    reason: str
    expires: date
    fingerprints: tuple[str, ...] = ()

    def is_expired(self, today: date | None = None) -> bool:
        return self.expires < (today or date.today())

    def matches(self, reason: Reason) -> bool:
        if self.fingerprints:
            return bool(set(self.fingerprints) & set(reason.fingerprints))
        return self.rule == reason.rule


@dataclass
class Policy:
    version: int = 1
    blocking: list[Expression] = field(default_factory=list)
    thresholds: list[Threshold] = field(default_factory=list)
    human_review: list[Expression | PathRule] = field(default_factory=list)
    warn_only: set[str] = field(default_factory=set)
    on_gate_error: str = "review"
    max_findings_reported: int = 10
    exemptions: list[Exemption] = field(default_factory=list)
    gates: dict[str, dict[str, Any]] = field(default_factory=dict)
    source: Path | None = None

    # ---------- wczytywanie ----------

    @classmethod
    def load(cls, path: Path | str, exemptions_path: Path | str | None = None) -> Policy:
        path = Path(path)
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        exemptions: list[Exemption] = []
        if exemptions_path is None:
            candidate = path.parent / "exceptions.yaml"
            exemptions_path = candidate if candidate.exists() else None
        if exemptions_path is not None:
            exemptions = _load_exemptions(Path(exemptions_path))
        policy = cls.from_dict(data, exemptions=exemptions)
        policy.source = path
        return policy

    @classmethod
    def from_dict(cls, data: dict[str, Any], exemptions: list[Exemption] | None = None) -> Policy:
        thresholds = []
        for fact, spec in (data.get("thresholds") or {}).items():
            spec = spec or {}
            if "min" not in spec and "max" not in spec:
                raise PolicyError(f"próg {fact!r} nie ma ani `min`, ani `max`")
            on_violation = spec.get("on_violation", "block")
            if on_violation not in ON_VIOLATION:
                raise PolicyError(f"próg {fact!r}: nieznane `on_violation`: {on_violation!r}")
            thresholds.append(
                Threshold(
                    fact=fact,
                    min=spec.get("min"),
                    max=spec.get("max"),
                    on_violation=on_violation,
                    message=spec.get("message", ""),
                )
            )

        human_review: list[Expression | PathRule] = []
        for entry in data.get("human_review_required_when") or []:
            if isinstance(entry, dict) and "paths_match" in entry:
                human_review.append(PathRule(tuple(entry["paths_match"])))
            elif isinstance(entry, str):
                human_review.append(Expression.parse(entry))
            else:
                raise PolicyError(f"nieobsługiwany wpis human_review: {entry!r}")

        on_gate_error = data.get("on_gate_error", "review")
        if on_gate_error not in ON_VIOLATION:
            raise PolicyError(f"nieznane `on_gate_error`: {on_gate_error!r}")

        return cls(
            version=int(data.get("version", 1)),
            blocking=[Expression.parse(x) for x in (data.get("blocking") or [])],
            thresholds=thresholds,
            human_review=human_review,
            warn_only=set(data.get("warn_only") or []),
            on_gate_error=on_gate_error,
            max_findings_reported=int(data.get("max_findings_reported", 10)),
            exemptions=exemptions or [],
            gates=data.get("gates") or {},
        )

    def gate_config(self, gate_id: str) -> dict[str, Any]:
        return dict(self.gates.get(gate_id) or {})

    def is_warn_only(self, gate_id: str) -> bool:
        return gate_id in self.warn_only

    # ---------- walidacja ----------

    def lint(self, known_facts: Iterable[str] = (), known_gates: Iterable[str] = ()) -> list[str]:
        errors: list[str] = []
        if self.version != 1:
            errors.append(f"nieobsługiwana wersja polityki: {self.version}")

        known_facts = set(known_facts)
        if known_facts:
            referenced = {e.fact for e in self.blocking}
            referenced |= {t.fact for t in self.thresholds}
            referenced |= {e.fact for e in self.human_review if isinstance(e, Expression)}
            for fact in sorted(referenced - known_facts):
                errors.append(
                    f"reguła odwołuje się do faktu {fact!r}, którego nie deklaruje żadna bramka "
                    "— literówka w polityce oznacza regułę, która nigdy nie zadziała"
                )

        known_gates = set(known_gates)
        if known_gates:
            for gate_id in sorted(self.warn_only - known_gates):
                errors.append(f"`warn_only` wskazuje nieznaną bramkę: {gate_id!r}")
            for gate_id in sorted(set(self.gates) - known_gates):
                errors.append(f"`gates` konfiguruje nieznaną bramkę: {gate_id!r}")

        for ex in self.exemptions:
            if ex.is_expired():
                errors.append(
                    f"wyjątek dla {ex.rule!r} (właściciel: {ex.owner}) wygasł {ex.expires} "
                    "— usuń go albo przedłuż świadomie"
                )
        return errors

    def expiring_exemptions(self, within_days: int = 7) -> list[Exemption]:
        today = date.today()
        return [
            e
            for e in self.exemptions
            if not e.is_expired(today) and (e.expires - today).days <= within_days
        ]

    # ---------- decyzja ----------

    def decide(
        self,
        facts: dict[str, Any],
        gate_results: list[GateResult],
        change: ChangeContext | None = None,
    ) -> Decision:
        blockers: list[Reason] = []
        reviews: list[Reason] = []
        warnings: list[Reason] = []
        suppressed: list[Reason] = []
        by_fact = _findings_by_fact(gate_results)

        def emit(reason: Reason, action: str, gate_id: str | None) -> None:
            if gate_id and self.is_warn_only(gate_id):
                warnings.append(reason)
                return
            active = [e for e in self.exemptions if e.matches(reason) and not e.is_expired()]
            if active:
                suppressed.append(reason)
                return
            {"block": blockers, "review": reviews, "warn": warnings}[action].append(reason)

        for expr in self.blocking:
            if expr.evaluate(facts):
                gate_id = _gate_for_fact(gate_results, expr.fact)
                emit(
                    Reason(
                        source="blocking",
                        rule=expr.raw,
                        detail=_detail(expr, facts),
                        gate=gate_id,
                        fingerprints=by_fact.get(expr.fact, ()),
                    ),
                    "block",
                    gate_id,
                )

        for threshold in self.thresholds:
            violation = threshold.violation(facts)
            if violation:
                gate_id = _gate_for_fact(gate_results, threshold.fact)
                emit(
                    Reason(
                        source="threshold",
                        rule=threshold.fact,
                        detail=threshold.message or violation,
                        gate=gate_id,
                        fingerprints=by_fact.get(threshold.fact, ()),
                    ),
                    threshold.on_violation,
                    gate_id,
                )

        for rule in self.human_review:
            if isinstance(rule, PathRule):
                if change is None:
                    continue
                hits = change.match_paths(list(rule.patterns))
                if hits:
                    reviews.append(
                        Reason(
                            source="human_review",
                            rule=rule.raw,
                            detail="zmiana dotyka ścieżki wrażliwej: "
                            + ", ".join(sorted(hits)[:5])
                            + (f" (+{len(hits) - 5})" if len(hits) > 5 else ""),
                        )
                    )
            elif rule.evaluate(facts):
                gate_id = _gate_for_fact(gate_results, rule.fact)
                if not self.is_warn_only(gate_id or ""):
                    reviews.append(
                        Reason(
                            source="human_review",
                            rule=rule.raw,
                            detail=_detail(rule, facts),
                            gate=gate_id,
                            fingerprints=by_fact.get(rule.fact, ()),
                        )
                    )

        for result in gate_results:
            if result.status != "error":
                continue
            reason = Reason(
                source="gate_error",
                rule=f"{result.gate}.error",
                detail=result.message or "bramka nie zakończyła się poprawnie",
                gate=result.gate,
            )
            # Bramka, która się wywaliła, niczego nie udowodniła. Cichy `pass`
            # w tym miejscu jest najgorszą możliwą awarią całego systemu.
            emit(reason, "warn" if result.warn_only else self.on_gate_error, None)

        if blockers:
            verdict = Verdict.BLOCK
        elif reviews:
            verdict = Verdict.PASS_WITH_REVIEW
        else:
            verdict = Verdict.PASS
        return Decision(
            verdict=verdict,
            reasons=blockers + reviews,
            warnings=warnings,
            suppressed=suppressed,
        )


# --------------------------------------------------------------------------


def _load_exemptions(path: Path) -> list[Exemption]:
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    out: list[Exemption] = []
    for entry in data.get("exceptions") or []:
        missing = [k for k in ("rule", "owner", "reason", "expires") if not entry.get(k)]
        if missing:
            raise PolicyError(f"wyjątek {entry!r}: brak pól {missing}")
        expires = entry["expires"]
        if isinstance(expires, str):
            expires = datetime.strptime(expires, "%Y-%m-%d").date()
        if isinstance(expires, datetime):
            expires = expires.date()
        out.append(
            Exemption(
                rule=entry["rule"],
                owner=entry["owner"],
                reason=entry["reason"],
                expires=expires,
                fingerprints=tuple(entry.get("fingerprints") or []),
            )
        )
    return out


def _findings_by_fact(gate_results: list[GateResult]) -> dict[str, tuple[str, ...]]:
    """Łączy fakt z znaleziskami, które go wywołały — po `rule_id`."""
    out: dict[str, list[str]] = {}
    for result in gate_results:
        for finding in result.findings:
            out.setdefault(finding.rule_id, []).append(finding.fingerprint)
    return {k: tuple(v) for k, v in out.items()}


def _gate_for_fact(gate_results: list[GateResult], fact: str) -> str | None:
    for result in gate_results:
        if fact in result.facts:
            return result.gate
    for result in gate_results:
        if any(f.rule_id == fact for f in result.findings):
            return result.gate
    return None


def _detail(expr: Expression, facts: dict[str, Any]) -> str:
    value = facts.get(expr.fact)
    if isinstance(value, (list, tuple, set)):
        value = ", ".join(str(v) for v in list(value)[:5])
    return f"{expr.fact} = {value}"


def _fmt(value: float) -> str:
    return f"{value:g}"
