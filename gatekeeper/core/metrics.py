"""Metryki skuteczności bramy (PLAN.md §6).

System oceniający też wymaga oceny — inaczej po kwartale nikt nie wie, czy
pomaga. Liczymy tylko to, co da się policzyć z danych, które faktycznie mamy,
i **jawnie oznaczamy metryki bez danych** zamiast pokazywać zero. Zero i „brak
pomiaru" to dwie różne rzeczy, a mylenie ich jest najprostszym sposobem na
wyciągnięcie fałszywego wniosku.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass
from typing import Any

from .store import Store


@dataclass(frozen=True)
class Metric:
    name: str
    value: float | None
    unit: str = ""
    target: str = ""
    note: str = ""

    def render(self) -> str:
        if self.value is None:
            return f"{self.name}: brak danych ({self.note})"
        formatted = (
            f"{self.value:.0%}" if self.unit == "%" else f"{self.value:g}{self.unit}"
        )
        target = f" (cel: {self.target})" if self.target else ""
        return f"{self.name}: {formatted}{target}"


@dataclass
class Report:
    days: int
    runs: int
    metrics: list[Metric]
    rules: list[dict[str, Any]]

    def render(self) -> str:
        lines = [f"Metryki bramy — ostatnie {self.days} dni, {self.runs} przebiegów", ""]
        lines += [f"  {m.render()}" for m in self.metrics]
        if self.rules:
            lines += ["", "  Reguły wg liczby znalezisk:"]
            for rule in self.rules:
                precision = (
                    f"{rule['precision']:.0%}" if rule["precision"] is not None else "—"
                )
                lines.append(
                    f"    {rule['rule_id']:<38} {rule['findings']:>4} znalezisk, "
                    f"ocenionych {rule['judged']:>3}, precyzja {precision}"
                )
        return "\n".join(lines)


def collect(store: Store, days: int = 30) -> Report:
    runs = store.runs_since(days)
    total = len(runs)
    metrics: list[Metric] = []

    if total == 0:
        empty = Metric("brak przebiegów w okresie", None, note="uruchom bramę")
        return Report(days, 0, [empty], [])

    blocked = sum(1 for r in runs if r["verdict"] == "BLOCK")
    review = sum(1 for r in runs if r["verdict"] == "PASS-WITH-REVIEW")
    clean = sum(1 for r in runs if r["verdict"] == "PASS")

    metrics.append(Metric("Zablokowane", blocked / total, "%"))
    metrics.append(
        Metric(
            "Bez ręcznego review",
            clean / total,
            "%",
            target="rosnący, ale nie kosztem escape rate",
        )
    )
    metrics.append(Metric("Skierowane do człowieka", review / total, "%"))

    durations = [r["duration_s"] for r in runs if r["duration_s"] is not None]
    metrics.append(
        Metric("Mediana czasu przejścia", statistics.median(durations), "s", target="< 1200s")
        if durations
        else Metric("Mediana czasu przejścia", None, note="brak pomiarów")
    )

    rules = store.rule_precision(days)
    judged = sum(r.judged for r in rules)
    true_positives = sum(r.true_positives for r in rules)
    metrics.append(
        Metric("Precyzja bramki", true_positives / judged, "%", target="> 80%")
        if judged
        else Metric(
            "Precyzja bramki",
            None,
            note="nikt nie ocenił jeszcze żadnego znaleziska — `gatekeeper verdict`",
        )
    )

    incidents = sum(1 for r in runs if r["caused_incident"])
    passed_through = total - blocked
    if incidents == 0:
        # Zero incydentów i brak oznaczania incydentów wyglądają w bazie tak samo,
        # a znaczą coś zupełnie innego. Nie udajemy pomiaru, którego nie ma.
        metrics.append(
            Metric(
                "Escape rate",
                None,
                note="żaden przebieg nie jest oznaczony jako incydent — `gatekeeper incident`",
            )
        )
    elif passed_through:
        metrics.append(
            Metric("Escape rate", incidents / passed_through, "%", target="trend malejący")
        )

    characterization = _sum_fact(store, days, "tests.characterization_used")
    if characterization is not None:
        metrics.append(
            Metric(
                "Testy zwolnione z cross-verify",
                characterization,
                "",
                note="rosnąca liczba = bramka przestaje sprawdzać",
            )
        )

    return Report(
        days=days,
        runs=total,
        metrics=metrics,
        rules=[
            {
                "rule_id": r.rule_id,
                "findings": r.findings,
                "judged": r.judged,
                "precision": r.precision,
            }
            for r in rules
        ],
    )


def _sum_fact(store: Store, days: int, key: str) -> float | None:
    rows = store.query(
        """SELECT f.value AS value FROM facts f
           JOIN runs r ON r.run_id = f.run_id
           WHERE f.key = ? AND r.started_at >= datetime('now', ?)""",
        (key, f"-{days} days"),
    )
    if not rows:
        return None
    total = 0.0
    for row in rows:
        try:
            total += float(row["value"])
        except (TypeError, ValueError):
            continue
    return total
