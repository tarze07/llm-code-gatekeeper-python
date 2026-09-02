# llm-code-gatekeeper

Pack **Python** dla [`llm-code-gatekeeper-core`](https://github.com/tarze07/llm-code-gatekeeper-core) — silnika bramy jakości dla kodu generowanego przez agentów LLM (Codex, Claude Code, Cursor, Devin…).

Odpowiada na pytanie: **czy ta zmiana może pójść na produkcję?** — decyzją `PASS` / `PASS-WITH-REVIEW` / `BLOCK`, z uzasadnieniem i śladem audytowym.

## Cztery repozytoria

System jest podzielony na wspólny rdzeń + cienkie pack'i per język, złożone przez [entry points](https://packaging.python.org/en/latest/specifications/entry-points/), nie przez import wprost:

- **[`llm-code-gatekeeper-core`](https://github.com/tarze07/llm-code-gatekeeper-core)** — silnik: `ChangeContext`, model `Finding`/`GateResult`/`Decision`, polityka, CLI (`gatekeeper`), 10 bramek G0–G3 jako logika dispatchu, manifest+rejestr+typosquat+SCA dla PyPI/npm/NuGet (język-agnostyczne, więc żyją tu, nie w pack'ach).
- **`llm-code-gatekeeper`** (to repo) — Python: `ruff`+`mypy` (`G1.static`), testy przez `ast` (`G2.cross_verify`/`G2.test_sanity`/`G2.diff_coverage`), reguły „nigdy" specyficzne dla Pythona (`G3.sast`).
- **[`llm-code-gatekeeper-ts`](https://github.com/tarze07/llm-code-gatekeeper-ts)** — TS/JS: `tsc`+`eslint` (`G1.static`), reguły „nigdy" TS/JS.
- **[`llm-code-gatekeeper-csharp`](https://github.com/tarze07/llm-code-gatekeeper-csharp)** — C#: `dotnet build` (`G1.static`), reguły „nigdy" C#.

Instalujesz core + pack(i) dla języków w ocenianym repo — `gatekeeper.gates`/`gatekeeper.static_checkers`/`gatekeeper.semgrep_rule_packs`/`gatekeeper.test_toolchains`/`gatekeeper.dep_ecosystems` (entry points) same się odnajdują, jeden `gatekeeper run` obsługuje mieszany diff (np. Python + TS w jednym PR-ze) bez żadnej konfiguracji.

📄 **[PLAN.md](PLAN.md)** / 🔧 **[TOOLS.md](TOOLS.md)** / 🚀 **[USAGE.md](USAGE.md)** — pełny plan, specyfikacja narzędzi i instrukcja użycia, napisane dla całego systemu przed fizycznym podziałem na repozytoria; architektura bramek (G0–G6) i decyzje projektowe wciąż aktualne, tylko rozmieszczenie kodu na pakiety się zmieniło (patrz sekcja wyżej).

## Skrót bramek

| Bramka | Zakres | Właściciel |
|---|---|---|
| G0 | Provenance, rozmiar i zakres diffa | core |
| G1.deps | Nowe zależności: rejestr, wiek, typosquat — PyPI/npm/NuGet | core |
| G1.static | Build/lint/typy na zmienionych liniach | core (dispatch) + pack per język |
| G2 | Testy: weryfikacja krzyżowa, jakość, diff coverage | core (dispatch) + pack per język |
| G3.secrets | gitleaks | core |
| G3.sast | Reguły „nigdy" (semgrep) | core (dispatch) + pack per język |
| G3.sca | pip-audit/npm audit/`dotnet list --vulnerable` | core |
| G4–G6 | Review semantyczny, człowiek, gotowość wdrożeniowa | planowane |

Założenie, na którym stoi całość: w pracy z agentem **testy, lockfile, konfiguracja i opis PR pochodzą od tego samego autora co kod** — więc żadnego z nich nie można traktować jako niezależnego dowodu poprawności.

## Co jest w tym repo

| Element | Co robi |
|---|---|
| `gatekeeper_python/adapters/linters.py` | `PythonStaticChecker` — ruff + mypy, rejestrowany pod `gatekeeper.static_checkers` |
| `gatekeeper_python/adapters/semgrep.py` | `PythonRulePack` — `rules/semgrep/python.yaml`, rejestrowany pod `gatekeeper.semgrep_rule_packs` |
| `gatekeeper_python/testing/` | `PythonTestToolchain` (`gatekeeper.test_toolchains`): discovery testów przez `ast`, jakość testów, cross-verify (uruchomienie na kodzie sprzed zmiany), coverage różnicowe |
| `gatekeeper_python/adapters/coverage.py` | `coverage.py` + `diff-cover`, branch-aware — konsumowane przez `PythonTestToolchain.produce_coverage_report()` |

`G2.cross_verify`/`G2.test_sanity`/`G2.diff_coverage` nie mają jeszcze odpowiednika dla TS/JS/C# — brak zarejestrowanego `TestToolchain` to `skipped`, nie błąd; native helpery (TS Compiler API, Roslyn) są zaplanowane jako osobne zlecenia.

## Szybki start

```bash
pip install -e ".[dev,gates]"
# gitleaks/semgrep instalują się osobno (nie zależności pip) — patrz USAGE.md

gatekeeper policy lint --policy policy/gates.yaml
gatekeeper run --repo /ścieżka/do/repo --base origin/main
gatekeeper calibrate             # celowo zepsute/czyste PR-y przeciw polityce

gatekeeper verdict <fingerprint> --false-positive   # ocena znaleziska przez człowieka
gatekeeper incident <run-id>                        # zmiana wywołała incydent
gatekeeper metrics --days 30                        # skuteczność bramy
```

Pełna instrukcja krok po kroku — [USAGE.md](USAGE.md).

Kody wyjścia: `0` = PASS, `1` = BLOCK, `2` = PASS-WITH-REVIEW przy `--fail-on review`, `3` = błąd użycia.

Integracja z GitHubem: [`.github/workflows/gatekeeper.yml`](.github/workflows/gatekeeper.yml) + [`scripts/post_pr_comment.sh`](https://github.com/tarze07/llm-code-gatekeeper-core/blob/main/scripts/post_pr_comment.sh) (core-owy).
