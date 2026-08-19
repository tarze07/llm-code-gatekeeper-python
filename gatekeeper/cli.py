"""CLI bramy jakości."""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import typer

from .core import metrics as metrics_module
from .core.change import ChangeContext
from .core.finding import Verdict
from .core.orchestrator import run_gates
from .core.policy import Policy, PolicyError
from .core.report import render_check_runs, render_json, render_markdown
from .core.store import DEFAULT_PATH as DEFAULT_STORE
from .core.store import Store
from .gates import known_facts, known_gate_ids

app = typer.Typer(no_args_is_help=True, add_completion=False, help="Brama jakości dla kodu z LLM")
policy_app = typer.Typer(no_args_is_help=True, help="Operacje na polityce")
app.add_typer(policy_app, name="policy")

DEFAULT_POLICY = Path("policy/gates.yaml")

EXIT_OK = 0
EXIT_BLOCK = 1
EXIT_REVIEW = 2
EXIT_USAGE = 3


@app.command()
def run(
    base: str = typer.Option(..., "--base", "-b", help="Gałąź/commit bazowy (liczymy merge-base)"),
    head: str = typer.Option("HEAD", "--head", "-h"),
    repo: Path = typer.Option(Path("."), "--repo", "-C"),
    policy_path: Path = typer.Option(DEFAULT_POLICY, "--policy", "-p"),
    exceptions: Path | None = typer.Option(None, "--exceptions"),
    fmt: str = typer.Option("markdown", "--format", "-f", help="markdown | json | github"),
    output: Path | None = typer.Option(None, "--output", "-o"),
    json_report: Path | None = typer.Option(
        None, "--json-report", help="Zapisz pełny raport JSON (pełna lista znalezisk)"
    ),
    gate: list[str] | None = typer.Option(None, "--gate", help="Uruchom tylko wskazane bramki"),
    ticket: str | None = typer.Option(None, "--ticket"),
    fail_on: str = typer.Option("block", "--fail-on", help="block | review | never"),
    no_fast_path: bool = typer.Option(False, "--no-fast-path"),
    store_path: Path = typer.Option(DEFAULT_STORE, "--store", help="Baza przebiegów (SQLite)"),
    no_store: bool = typer.Option(False, "--no-store", help="Nie zapisuj śladu przebiegu"),
) -> None:
    """Uruchamia bramki na zakresie `base..head` i wypisuje decyzję."""
    try:
        policy = Policy.load(policy_path, exceptions)
    except (OSError, PolicyError) as exc:
        typer.secho(f"polityka: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(EXIT_USAGE) from exc

    errors = policy.lint(known_facts(), known_gate_ids())
    if errors:
        for err in errors:
            typer.secho(f"polityka: {err}", fg=typer.colors.RED, err=True)
        raise typer.Exit(EXIT_USAGE)

    change = ChangeContext.from_git(repo, base, head, ticket_id=ticket)
    result = run_gates(change, policy, only=gate, fast_path=not no_fast_path)

    if not no_store:
        try:
            Store(_resolve_store(store_path, repo)).record(result, change)
        except sqlite3.Error as exc:
            # Ślad audytowy jest ważny, ale nie na tyle, żeby awaria zapisu
            # unieważniała decyzję, którą właśnie policzyliśmy.
            typer.secho(
                f"uwaga: nie zapisano śladu przebiegu ({exc})",
                fg=typer.colors.YELLOW,
                err=True,
            )

    if fmt == "markdown":
        rendered = render_markdown(result, policy.max_findings_reported)
    elif fmt == "json":
        rendered = render_json(result)
    elif fmt == "github":
        rendered = json.dumps(render_check_runs(result), ensure_ascii=False, indent=2)
    else:
        typer.secho(f"nieznany format: {fmt}", fg=typer.colors.RED, err=True)
        raise typer.Exit(EXIT_USAGE)

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        typer.echo(rendered)

    if json_report:
        json_report.parent.mkdir(parents=True, exist_ok=True)
        json_report.write_text(render_json(result), encoding="utf-8")

    verdict = result.decision.verdict
    if fail_on == "never":
        raise typer.Exit(EXIT_OK)
    if verdict == Verdict.BLOCK:
        raise typer.Exit(EXIT_BLOCK)
    if verdict == Verdict.PASS_WITH_REVIEW and fail_on == "review":
        raise typer.Exit(EXIT_REVIEW)
    raise typer.Exit(EXIT_OK)


@policy_app.command("lint")
def policy_lint(
    policy_path: Path = typer.Option(DEFAULT_POLICY, "--policy", "-p"),
    exceptions: Path | None = typer.Option(None, "--exceptions"),
    expiring_days: int = typer.Option(7, "--expiring-days"),
) -> None:
    """Waliduje politykę: literówki w faktach, złe progi, wygasłe wyjątki."""
    try:
        policy = Policy.load(policy_path, exceptions)
    except (OSError, PolicyError) as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(EXIT_BLOCK) from exc

    errors = policy.lint(known_facts(), known_gate_ids())
    for err in errors:
        typer.secho(f"BŁĄD: {err}", fg=typer.colors.RED, err=True)
    for ex in policy.expiring_exemptions(expiring_days):
        typer.secho(
            f"UWAGA: wyjątek {ex.rule!r} ({ex.owner}) wygasa {ex.expires}",
            fg=typer.colors.YELLOW,
        )
    if errors:
        raise typer.Exit(EXIT_BLOCK)
    typer.secho(
        f"OK — {len(policy.blocking)} reguł blokujących, {len(policy.thresholds)} progów, "
        f"{len(policy.exemptions)} wyjątków",
        fg=typer.colors.GREEN,
    )


@policy_app.command("facts")
def policy_facts() -> None:
    """Wypisuje fakty, którymi wolno operować w polityce."""
    for fact in sorted(known_facts()):
        typer.echo(fact)


@app.command()
def verdict(
    fingerprint: str = typer.Argument(..., help="Fingerprint znaleziska z raportu"),
    false_positive: bool = typer.Option(False, "--false-positive", help="Znalezisko było błędne"),
    true_positive: bool = typer.Option(False, "--true-positive", help="Znalezisko było trafne"),
    author: str | None = typer.Option(None, "--author"),
    note: str | None = typer.Option(None, "--note"),
    store_path: Path = typer.Option(DEFAULT_STORE, "--store"),
) -> None:
    """Zapisuje ocenę człowieka o znalezisku — jedyne źródło danych o precyzji bramki."""
    if false_positive == true_positive:
        typer.secho(
            "podaj dokładnie jedno: --false-positive albo --true-positive",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(EXIT_USAGE)
    try:
        rule = Store(store_path).record_verdict(
            fingerprint,
            "false_positive" if false_positive else "true_positive",
            author=author,
            note=note,
        )
    except KeyError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(EXIT_USAGE) from exc
    typer.secho(f"zapisano werdykt dla reguły `{rule}`", fg=typer.colors.GREEN)


@app.command()
def incident(
    run_id: str = typer.Argument(..., help="Identyfikator przebiegu z raportu"),
    note: str | None = typer.Option(None, "--note"),
    store_path: Path = typer.Option(DEFAULT_STORE, "--store"),
) -> None:
    """Oznacza przebieg, po którym zmiana wywołała incydent — liczy się do escape rate."""
    try:
        Store(store_path).mark_incident(run_id, note)
    except KeyError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(EXIT_USAGE) from exc
    typer.secho(f"przebieg {run_id} oznaczony jako incydent", fg=typer.colors.GREEN)


@app.command()
def calibrate(
    cases_path: Path = typer.Option(
        Path("calibration/cases.yaml"), "--cases", help="Plik z przypadkami kalibracyjnymi"
    ),
    fixtures_dir: Path = typer.Option(
        Path("calibration/fixtures"), "--fixtures", help="Katalog z parami base/head"
    ),
    policy_path: Path = typer.Option(DEFAULT_POLICY, "--policy", "-p"),
    exceptions: Path | None = typer.Option(None, "--exceptions"),
) -> None:
    """Uruchamia celowo zepsute/czyste PR-y przeciw polityce (PLAN.md §6)."""
    from .calibration import load_cases, run_calibration

    try:
        policy = Policy.load(policy_path, exceptions)
    except (OSError, PolicyError) as exc:
        typer.secho(f"polityka: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(EXIT_USAGE) from exc

    try:
        cases = load_cases(cases_path)
    except OSError as exc:
        typer.secho(f"zestaw kalibracyjny: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(EXIT_USAGE) from exc

    report = run_calibration(cases, policy, fixtures_dir)
    typer.echo(report.render())
    if not report.ok:
        raise typer.Exit(EXIT_BLOCK)


@app.command()
def metrics(
    days: int = typer.Option(30, "--days", "-d"),
    store_path: Path = typer.Option(DEFAULT_STORE, "--store"),
) -> None:
    """Skuteczność bramy: co blokuje, jak trafnie, jak szybko."""
    typer.echo(metrics_module.collect(Store(store_path), days).render())


def _resolve_store(store_path: Path, repo: Path) -> Path:
    """Domyślna baza mieszka w ocenianym repozytorium, nie w katalogu roboczym."""
    return store_path if store_path.is_absolute() else Path(repo) / store_path


def main() -> None:  # pragma: no cover
    try:
        app()
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":  # pragma: no cover
    main()
