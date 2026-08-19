"""G0 — provenance: co wyprodukowało tę zmianę.

Bramka, która niczego nie blokuje, a bez której nie da się prowadzić reszty
systemu. Jej produktem są **dane**: który model, który agent, która sesja,
czy człowiek dotykał kodu po agencie. Bez tego pytanie „które narzędzie
generuje nam najwięcej defektów" pozostaje kwestią przeczuć, a to ono decyduje
o wyborze narzędzi w zespole (PLAN.md §6).

Źródłem są trailery commitów — jedyne miejsce, które przeżywa rebase, merge
i przeniesienie repozytorium:

    Generated-By: codex/gpt-5
    Session-Id: 0f3a9c…
    Model-Version: 2026-05

Świadomie **nie blokujemy** braku trailera. Repozytorium, które dopiero
zaczyna, nie ma ich nigdzie, a bramka blokująca od pierwszego dnia zostałaby
wyłączona pierwszego dnia. Fakt `provenance.unknown_origin` jest w polityce
i każdy zespół decyduje sam, kiedy go włączyć.
"""

from __future__ import annotations

import time
from typing import Any

from ..core.change import ChangeContext, Commit
from ..core.finding import Finding, GateResult, Severity
from . import Gate, register

#: Nazwy trailerów, którymi agenci oznaczają swoje commity.
GENERATOR_TRAILERS = ("generated-by", "co-authored-by", "assisted-by", "agent")
SESSION_TRAILERS = ("session-id", "conversation-id", "run-id")
MODEL_TRAILERS = ("model", "model-version")

#: Fragmenty adresów e-mail typowe dla botów i agentów.
DEFAULT_BOT_MARKERS = (
    "noreply@anthropic.com",
    "bot@",
    "[bot]",
    "noreply@openai.com",
    "devin@",
    "cursor@",
)


@register
class Provenance(Gate):
    id = "G0.provenance"
    name = "Pochodzenie zmiany"
    budget_s = 10.0
    facts = (
        "provenance.model",
        "provenance.agent",
        "provenance.session_id",
        "provenance.commits",
        "provenance.generated_commits",
        "provenance.human_edited",
        "provenance.unknown_origin",
        "provenance.agent_ratio",
    )

    def run(self, change: ChangeContext) -> GateResult:
        started = time.monotonic()
        commits = change.commits
        bot_markers = tuple(self.config.get("bot_markers", DEFAULT_BOT_MARKERS))

        generated = [c for c in commits if _generator(c) or _looks_like_bot(c, bot_markers)]
        human = [c for c in commits if c not in generated]
        agents = sorted({a for c in generated if (a := _generator(c))})
        models = sorted({m for c in generated if (m := _model(c))})
        sessions = sorted({s for c in generated if (s := _session(c))})

        facts: dict[str, Any] = {
            "provenance.model": models[0] if len(models) == 1 else (models or None),
            "provenance.agent": agents[0] if len(agents) == 1 else (agents or None),
            "provenance.session_id": sessions[0] if len(sessions) == 1 else (sessions or None),
            "provenance.commits": len(commits),
            "provenance.generated_commits": len(generated),
            "provenance.human_edited": bool(generated) and bool(human),
            "provenance.unknown_origin": bool(commits) and not generated,
            "provenance.agent_ratio": (len(generated) / len(commits)) if commits else 0.0,
        }

        findings: list[Finding] = []
        if facts["provenance.unknown_origin"] and self.config.get("require_trailer", False):
            findings.append(_missing_trailer_finding(self.id, commits))

        return self.result(
            status="fail" if findings else "pass",
            duration_s=time.monotonic() - started,
            facts=facts,
            findings=findings,
            message=_summary(facts, agents, models),
        )


def _generator(commit: Commit) -> str | None:
    for name in GENERATOR_TRAILERS:
        value = commit.trailer(name)
        if value:
            return value.strip()
    return None


def _model(commit: Commit) -> str | None:
    for name in MODEL_TRAILERS:
        value = commit.trailer(name)
        if value:
            return value.strip()
    # `Generated-By: codex/gpt-5` niesie i agenta, i model
    generator = _generator(commit)
    if generator and "/" in generator:
        return generator.split("/", 1)[1].strip()
    return None


def _session(commit: Commit) -> str | None:
    for name in SESSION_TRAILERS:
        value = commit.trailer(name)
        if value:
            return value.strip()
    return None


def _looks_like_bot(commit: Commit, markers: tuple[str, ...]) -> bool:
    haystack = f"{commit.author} {commit.author_email}".lower()
    return any(marker.lower() in haystack for marker in markers)


def _missing_trailer_finding(gate_id: str, commits: list[Commit]) -> Finding:
    return Finding(
        gate=gate_id,
        rule_id="provenance.unknown_origin",
        severity=Severity.LOW,
        title=f"Żaden z {len(commits)} commitów nie mówi, co wyprodukowało tę zmianę",
        failure_scenario=(
            "Przy incydencie nie da się ustalić, który model i która sesja wygenerowały "
            "wadliwy kod, więc ten sam defekt wróci z tego samego narzędzia. Dodaj trailer "
            "`Generated-By: <narzędzie>/<model>` w konfiguracji agenta."
        ),
        file=None,
        evidence={"snippet": ",".join(c.sha[:8] for c in commits[:5])},
    )


def _summary(facts: dict[str, Any], agents: list[str], models: list[str]) -> str:
    if facts["provenance.unknown_origin"]:
        return f"{facts['provenance.commits']} commitów bez oznaczenia pochodzenia"
    if not facts["provenance.commits"]:
        return "brak commitów w zakresie"
    parts = [f"{facts['provenance.generated_commits']}/{facts['provenance.commits']} od agenta"]
    if agents:
        parts.append("agent: " + ", ".join(agents))
    if models:
        parts.append("model: " + ", ".join(models))
    if facts["provenance.human_edited"]:
        parts.append("człowiek edytował po agencie")
    return " · ".join(parts)
