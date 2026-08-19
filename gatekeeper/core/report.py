"""Raport: markdown do PR, Check Runy do GitHuba, JSON do archiwum.

Trzy renderery z jednego `RunResult`. Dwie rzeczy są tu polityką, nie
formatowaniem:

* **limit znalezisk w komentarzu** — przeciwdziałanie zmęczeniu alertami
  wpisane w kod, nie w dobre chęci (PLAN.md §9);
* **sekcja „czego ta brama nie sprawdza"** — brama, która milczy o swoich
  lukach, produkuje fałszywe poczucie bezpieczeństwa.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from .finding import Finding, RunResult, Severity, Verdict

#: Znacznik idempotencji: skrypt publikujący szuka go, żeby *zaktualizować*
#: istniejący komentarz zamiast dokładać kolejny przy każdym pushu.
MARKER = "<!-- gatekeeper:report -->"

_VERDICT_STYLE = {
    Verdict.PASS: ("✅", "PASS", "success"),
    Verdict.PASS_WITH_REVIEW: ("👀", "PASS-WITH-REVIEW", "neutral"),
    Verdict.BLOCK: ("🚫", "BLOCK", "failure"),
}

_STATUS_ICON = {
    "pass": "✅",
    "fail": "❌",
    "error": "⚠️",
    "skipped": "⏭️",
}

_SEVERITY_ICON = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def render_markdown(run: RunResult, max_findings: int = 10) -> str:
    icon, label, _ = _VERDICT_STYLE[run.decision.verdict]
    out: list[str] = [MARKER, f"## {icon} {label} — brama jakości"]
    out.append(
        f"`{run.base_sha[:7]}` → `{run.head_sha[:7]}` · "
        f"{len(run.gate_results)} bramki · {run.duration_s:.1f}s · "
        f"polityka v{run.policy_version} · "
        # Identyfikator przebiegu jest w raporcie, bo bez niego `gatekeeper incident`
        # wymagałby szukania po bazie — a wtedy nikt nigdy nie oznaczy incydentu.
        f"przebieg `{run.run_id}`"
    )

    if run.decision.reasons:
        out.append("\n### Dlaczego")
        out.append("| | Reguła | Szczegół |")
        out.append("|---|---|---|")
        for reason in run.decision.reasons:
            mark = "🚫" if reason.source in ("blocking", "threshold") else "👀"
            out.append(f"| {mark} | `{reason.rule}` | {reason.detail} |")
    else:
        out.append("\nWszystkie uruchomione bramki przeszły.")

    findings = sorted(run.findings, key=lambda f: f.weight, reverse=True)
    if findings:
        shown = findings[:max_findings]
        header = f"\n### Znaleziska ({len(shown)} z {len(findings)})"
        out.append(header)
        for f in shown:
            out.append(_render_finding(f))
        if len(findings) > len(shown):
            out.append(
                f"\n_Pozostałe {len(findings) - len(shown)} znalezisk w artefakcie "
                f"`gatekeeper-report.json` — limit w komentarzu jest celowy._"
            )

    out.append("\n### Bramki")
    out.append("| Bramka | Status | Czas | Podsumowanie |")
    out.append("|---|---|---|---|")
    for g in run.gate_results:
        icon = _STATUS_ICON.get(g.status, "•")
        suffix = " _(warn-only)_" if g.warn_only else ""
        out.append(
            f"| `{g.gate}` | {icon} {g.status}{suffix} | "
            f"{g.duration_s:.1f}s | {g.message} |"
        )

    if run.decision.warnings:
        out.append("\n<details><summary>Ostrzeżenia (nie blokują)</summary>\n")
        for w in run.decision.warnings:
            out.append(f"- `{w.rule}` — {w.detail}")
        out.append("\n</details>")

    if run.decision.suppressed:
        out.append("\n<details><summary>Wyciszone wyjątkiem</summary>\n")
        for s in run.decision.suppressed:
            out.append(f"- `{s.rule}` — {s.detail}")
        out.append("\n</details>")

    if run.not_checked:
        out.append("\n<details><summary>Czego ta brama <b>nie</b> sprawdza</summary>\n")
        for item in run.not_checked:
            out.append(f"- {item}")
        out.append("\n</details>")

    return "\n".join(out) + "\n"


def _render_finding(f: Finding) -> str:
    icon = _SEVERITY_ICON.get(f.severity, "•")
    lines = [
        f"\n**{icon} {f.title}**",
        # Fingerprint w raporcie, bo to argument `gatekeeper verdict` — bez niego
        # nikt nie oceni znaleziska, a bez ocen nie policzymy precyzji bramki.
        f"`{f.location}` · `{f.rule_id}` · {f.gate} · `{f.fingerprint}`",
        "",
        f.failure_scenario,
    ]
    return "\n".join(lines)


def render_check_runs(run: RunResult) -> list[dict[str, Any]]:
    """Payloady do `POST /repos/{owner}/{repo}/check-runs` — po jednym na bramkę."""
    checks: list[dict[str, Any]] = []
    for g in run.gate_results:
        conclusion = {
            "pass": "success",
            "fail": "failure",
            "error": "action_required",
            "skipped": "skipped",
        }[g.status]
        if g.warn_only and conclusion in ("failure", "action_required"):
            conclusion = "neutral"
        checks.append(
            {
                "name": f"gatekeeper / {g.gate}",
                "head_sha": run.head_sha,
                "status": "completed",
                "conclusion": conclusion,
                "output": {
                    "title": g.message[:120] or g.gate,
                    "summary": _gate_summary(g.facts),
                    "annotations": _annotations(g.findings),
                },
            }
        )
    _, label, conclusion = _VERDICT_STYLE[run.decision.verdict]
    checks.append(
        {
            "name": "gatekeeper / decyzja",
            "head_sha": run.head_sha,
            "status": "completed",
            "conclusion": conclusion,
            "output": {
                "title": label,
                "summary": render_markdown(run),
            },
        }
    )
    return checks


def render_json(run: RunResult) -> str:
    return json.dumps(run.to_dict(), ensure_ascii=False, indent=2)


def _gate_summary(facts: dict[str, Any]) -> str:
    if not facts:
        return "brak faktów"
    return "\n".join(f"- `{k}`: {v}" for k, v in sorted(facts.items()))


def _annotations(findings: Iterable[Finding], limit: int = 50) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for f in list(findings)[:limit]:
        if not f.file:
            continue
        line = f.line or 1
        out.append(
            {
                "path": f.file,
                "start_line": line,
                "end_line": line,
                "annotation_level": "failure" if f.severity >= Severity.HIGH else "warning",
                "title": f.title[:255],
                "message": f.failure_scenario[:0xFFFF],
                "raw_details": f.rule_id,
            }
        )
    return out
