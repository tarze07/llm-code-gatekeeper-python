"""Trwały ślad przebiegów bramy (SQLite).

Powstaje w kamieniu 2, a nie na końcu projektu — i to jest świadoma decyzja.
Metryki z rozdz. 6 PLAN.md liczy się z historii, więc dołożenie store'a za
kwartał oznacza kwartał bez danych i progi dobierane na wyczucie.

Zapisujemy również **werdykty ludzi** o znaleziskach. Bez nich nie da się
policzyć precyzji bramki, a bez precyzji nie wiadomo, które reguły kasować.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from .change import ChangeContext
from .finding import RunResult

DEFAULT_PATH = Path(".gatekeeper/runs.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id           TEXT PRIMARY KEY,
    repo             TEXT NOT NULL,
    base_sha         TEXT NOT NULL,
    head_sha         TEXT NOT NULL,
    branch           TEXT,
    ticket           TEXT,
    verdict          TEXT NOT NULL,
    duration_s       REAL NOT NULL,
    policy_version   INTEGER,
    diff_lines       INTEGER,
    diff_files       INTEGER,
    started_at       TEXT NOT NULL,
    caused_incident  INTEGER NOT NULL DEFAULT 0,
    incident_note    TEXT
);

CREATE TABLE IF NOT EXISTS gate_runs (
    run_id     TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    gate       TEXT NOT NULL,
    status     TEXT NOT NULL,
    duration_s REAL NOT NULL,
    warn_only  INTEGER NOT NULL DEFAULT 0,
    message    TEXT,
    PRIMARY KEY (run_id, gate)
);

CREATE TABLE IF NOT EXISTS findings (
    run_id           TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    fingerprint      TEXT NOT NULL,
    gate             TEXT NOT NULL,
    rule_id          TEXT NOT NULL,
    severity         TEXT NOT NULL,
    file             TEXT,
    line             INTEGER,
    title            TEXT NOT NULL,
    failure_scenario TEXT NOT NULL,
    confidence       REAL NOT NULL,
    PRIMARY KEY (run_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS reasons (
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    rule   TEXT NOT NULL,
    detail TEXT,
    gate   TEXT
);

CREATE TABLE IF NOT EXISTS facts (
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    key    TEXT NOT NULL,
    value  TEXT,
    PRIMARY KEY (run_id, key)
);

-- Werdykt człowieka o znalezisku: jedyne źródło prawdy o precyzji bramki.
CREATE TABLE IF NOT EXISTS verdicts (
    fingerprint TEXT NOT NULL,
    rule_id     TEXT NOT NULL,
    verdict     TEXT NOT NULL CHECK (verdict IN ('true_positive', 'false_positive')),
    author      TEXT,
    note        TEXT,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (fingerprint, created_at)
);

CREATE INDEX IF NOT EXISTS idx_runs_started ON runs(started_at);
CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_verdicts_rule ON verdicts(rule_id);
"""


@dataclass(frozen=True)
class RulePrecision:
    rule_id: str
    findings: int
    judged: int
    true_positives: int

    @property
    def precision(self) -> float | None:
        return self.true_positives / self.judged if self.judged else None


class Store:
    def __init__(self, path: Path | str = DEFAULT_PATH) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as conn:
            conn.executescript(SCHEMA)
            conn.commit()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    # ---------------------------------------------------------------- zapis

    def record(self, run: RunResult, change: ChangeContext | None = None) -> None:
        facts = run.facts
        with closing(self._connect()) as conn:
            conn.execute(
                """INSERT OR REPLACE INTO runs
                   (run_id, repo, base_sha, head_sha, branch, ticket, verdict, duration_s,
                    policy_version, diff_lines, diff_files, started_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    run.run_id,
                    run.repo,
                    run.base_sha,
                    run.head_sha,
                    change.branch if change else None,
                    change.ticket.id if change and change.ticket else None,
                    run.decision.verdict.value,
                    run.duration_s,
                    run.policy_version,
                    facts.get("diff.effective_lines"),
                    facts.get("diff.effective_files"),
                    run.started_at.isoformat(),
                ),
            )
            conn.executemany(
                """INSERT OR REPLACE INTO gate_runs
                   (run_id, gate, status, duration_s, warn_only, message) VALUES (?,?,?,?,?,?)""",
                [
                    (run.run_id, g.gate, g.status, g.duration_s, int(g.warn_only), g.message)
                    for g in run.gate_results
                ],
            )
            conn.executemany(
                """INSERT OR REPLACE INTO findings
                   (run_id, fingerprint, gate, rule_id, severity, file, line, title,
                    failure_scenario, confidence)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                [
                    (
                        run.run_id,
                        f.fingerprint,
                        f.gate,
                        f.rule_id,
                        f.severity.value,
                        f.file,
                        f.line,
                        f.title,
                        f.failure_scenario,
                        f.confidence,
                    )
                    for f in run.findings
                ],
            )
            conn.executemany(
                "INSERT INTO reasons (run_id, source, rule, detail, gate) VALUES (?,?,?,?,?)",
                [
                    (run.run_id, r.source, r.rule, r.detail, r.gate)
                    for r in run.decision.reasons + run.decision.warnings
                ],
            )
            conn.executemany(
                "INSERT OR REPLACE INTO facts (run_id, key, value) VALUES (?,?,?)",
                [
                    (run.run_id, k, json.dumps(v, ensure_ascii=False, default=str))
                    for k, v in facts.items()
                ],
            )
            conn.commit()

    def record_verdict(
        self,
        fingerprint: str,
        verdict: Literal["true_positive", "false_positive"],
        author: str | None = None,
        note: str | None = None,
    ) -> str:
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT rule_id FROM findings WHERE fingerprint = ? ORDER BY rowid DESC LIMIT 1",
                (fingerprint,),
            ).fetchone()
            if row is None:
                raise KeyError(f"nie znam znaleziska o fingerprincie {fingerprint!r}")
            conn.execute(
                """INSERT OR REPLACE INTO verdicts
                   (fingerprint, rule_id, verdict, author, note, created_at)
                   VALUES (?,?,?,?,?,?)""",
                (
                    fingerprint,
                    row["rule_id"],
                    verdict,
                    author,
                    note,
                    datetime.now(UTC).isoformat(),
                ),
            )
            conn.commit()
            return str(row["rule_id"])

    def mark_incident(self, run_id: str, note: str | None = None) -> None:
        """Oznacza przebieg, po którym zmiana wywołała incydent na produkcji."""
        with closing(self._connect()) as conn:
            cursor = conn.execute(
                "UPDATE runs SET caused_incident = 1, incident_note = ? WHERE run_id = ?",
                (note, run_id),
            )
            if cursor.rowcount == 0:
                raise KeyError(f"nie znam przebiegu {run_id!r}")
            conn.commit()

    # ------------------------------------------------------------- odczyt

    def query(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with closing(self._connect()) as conn:
            return list(conn.execute(sql, params).fetchall())

    def runs_since(self, days: int) -> list[sqlite3.Row]:
        return self.query(
            "SELECT * FROM runs WHERE started_at >= datetime('now', ?) ORDER BY started_at DESC",
            (f"-{days} days",),
        )

    def rule_precision(self, days: int = 90) -> list[RulePrecision]:
        rows = self.query(
            """
            SELECT f.rule_id                                            AS rule_id,
                   COUNT(*)                                             AS findings,
                   SUM(CASE WHEN v.verdict IS NOT NULL THEN 1 ELSE 0 END)        AS judged,
                   SUM(CASE WHEN v.verdict = 'true_positive' THEN 1 ELSE 0 END)  AS tp
            FROM findings f
            JOIN runs r ON r.run_id = f.run_id
            LEFT JOIN verdicts v ON v.fingerprint = f.fingerprint
            WHERE r.started_at >= datetime('now', ?)
            GROUP BY f.rule_id
            ORDER BY findings DESC
            """,
            (f"-{days} days",),
        )
        return [
            RulePrecision(r["rule_id"], r["findings"], r["judged"] or 0, r["tp"] or 0)
            for r in rows
        ]
