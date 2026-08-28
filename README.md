# llm-code-gatekeeper

Brama jakości dla kodu generowanego przez agentów LLM (Codex, Claude Code, Cursor, Devin…).

Odpowiada na pytanie: **czy ta zmiana może pójść na produkcję?** — decyzją `PASS` / `PASS-WITH-REVIEW` / `BLOCK`, z uzasadnieniem i śladem audytowym.

📄 **[PLAN.md](PLAN.md)** — pełny plan: katalog defektów specyficznych dla LLM, architektura 7 bramek (G0–G6), polityka jako kod, metryki skuteczności, roadmapa 3-miesięczna, stack narzędziowy, ryzyka.

🔧 **[TOOLS.md](TOOLS.md)** — plan implementacji: specyfikacja każdego narzędzia (interfejs, algorytm, pułapki, test akceptacyjny, koszt), układ pakietu, kolejność budowy w 6 kamieniach.

🚀 **[USAGE.md](USAGE.md)** — jak tego użyć: mam kod od agenta i co dalej. Cztery kroki do pierwszego uruchomienia, znaczenie decyzji, integracja z PR-ami.

## Skrót

| Bramka | Zakres | Budżet |
|---|---|---|
| G0 | Provenance, rozmiar i zakres diffa | < 10 s |
| G1 | Build, lint, typy, weryfikacja zależności | < 3 min |
| G2 | Testy, diff coverage, mutacje, weryfikacja krzyżowa | < 15 min |
| G3 | SAST, SCA, sekrety, IaC, licencje | < 10 min |
| G4 | Review semantyczny — panel LLM + weryfikacja adwersaryjna | < 5 min |
| G5 | Człowiek — wyzwalany polityką, nie domyślnie | — |
| G6 | Gotowość wdrożeniowa: migracje, rollback, obserwowalność | < 1 min |

Założenie, na którym stoi całość: w pracy z agentem **testy, lockfile, konfiguracja i opis PR pochodzą od tego samego autora co kod** — więc żadnego z nich nie można traktować jako niezależnego dowodu poprawności.

## Stan implementacji

Zbudowane są **kamienie 1–3** z [TOOLS.md](TOOLS.md) (koniec fazy 1 z PLAN.md) oraz pierwszy element **kamienia 4** (`G2.test_sanity`):

| Element | Co robi |
|---|---|
| `core/change.py` | `ChangeContext` — jedyne miejsce znające gita; merge-base, dodane linie, pliki generowane, trailery commitów |
| `core/finding.py` | wspólny model `Finding` / `GateResult` / `Decision`; fingerprint niezależny od numeru linii |
| `core/policy.py` | `policy/gates.yaml` bez `eval`; progi, wyjątki z datą wygaśnięcia, `warn_only`, walidacja literówek |
| `core/report.py` | komentarz do PR (jeden, aktualizowany), Check Runy, JSON |
| `core/store.py` | ślad przebiegów w SQLite + werdykty ludzi o znaleziskach |
| `core/metrics.py` | precyzja, rozkład werdyktów, escape rate — z jawnym „brak danych" zamiast zera |
| `core/runner.py` | granica bezpieczeństwa: izolacja sieci (`unshare --net`), limity pamięci/czasu, czyszczenie sekretów ze środowiska |
| `core/orchestrator.py` | fale bramek wg zależności, równoległość, budżety egzekwowane jako `error`, ścieżka szybka dla docs-only |
| `gatekeeper/calibration.py` | zestaw kalibracyjny — celowo zepsute/czyste PR-y jako `calibration/cases.yaml` + `calibration/fixtures/` |
| `G0.scope` | rozmiar i higiena zakresu; `scope_map.yaml` — ticket → dozwolone ścieżki |
| `G0.provenance` | model/agent/sesja z trailerów commitów — dane pod „defekty per model" |
| `G1.deps` | nowe zależności: istnienie w rejestrze, wiek, typosquat/slopsquat — PyPI, npm, **NuGet** |
| `G1.static` | Python: ruff + mypy · TS/JS: tsc + eslint · **C#: `dotnet build`** — na zmienionych liniach, łapie halucynacje API |
| `G2.cross_verify` | nowe testy uruchomione przeciw kodowi **sprzed** zmiany — wykrywa testy, które niczego nie dowodzą (**tylko Python**) |
| `G2.test_sanity` | linter jakości nowych testów (AST): brak asercji, asercja na stałą, mock porównywany z własnym `return_value`, sam `is not None`, połknięty wyjątek — **tylko Python**, `warn_only` |
| `G3.secrets` | gitleaks; sekret w diffie blokuje, zastany idzie do długu |
| `G3.sast` | reguły „nigdy" (`rules/semgrep/`) na zmienionych liniach — TLS, eval, SQLi, `shell=True`/`Process.Start`, deserializacja, IAM — Python, TS/JS, **C#** |
| `G3.sca` | pip-audit (PyPI), npm audit (npm), **`dotnet list package --vulnerable` (NuGet)** — na nowo dodanych zależnościach; jedyna bramka z dostępem do sieci |

Nie sprawdza jeszcze: pokrycia różnicowego, mutacji, flaky-testów i contract-diff (reszta G2 — `test.no_new_path` w `G2.test_sanity` czeka na diff-coverage), weryfikacji krzyżowej i jakości testów dla TS/JS/C# (reszta G2), IaC/licencje (reszta G3), G4 (panel LLM), G6. Brama wypisuje tę listę w każdym raporcie.

## Szybki start

```bash
pip install -e ".[dev,gates]"   # dev: pytest; gates: ruff, mypy, semgrep, pip-audit
# gitleaks instaluje się osobno (binarka Go, nie pakiet pip) — patrz USAGE.md
# TS/JS (tsc, eslint) i C# (dotnet) też instalują się osobno — narzędzia
# projektu ocenianego, nie zależności samej bramy; patrz USAGE.md

gatekeeper policy lint --policy policy/gates.yaml
gatekeeper run --repo /ścieżka/do/repo --base origin/main
gatekeeper policy facts          # fakty dozwolone w polityce
gatekeeper calibrate             # celowo zepsute/czyste PR-y przeciw polityce

gatekeeper verdict <fingerprint> --false-positive   # ocena znaleziska przez człowieka
gatekeeper incident <run-id>                        # zmiana wywołała incydent
gatekeeper metrics --days 30                        # skuteczność bramy
```

Pełna instrukcja krok po kroku — [USAGE.md](USAGE.md).

Kody wyjścia: `0` = PASS, `1` = BLOCK, `2` = PASS-WITH-REVIEW przy `--fail-on review`, `3` = błąd użycia.

Integracja z GitHubem: [`.github/workflows/gatekeeper.yml`](.github/workflows/gatekeeper.yml) + [`scripts/post_pr_comment.sh`](scripts/post_pr_comment.sh).
