# Plan implementacji: narzędzia bramy jakości

Dokument towarzyszący [PLAN.md](PLAN.md). PLAN.md mówi *co* sprawdzać. Ten dokument mówi *co zbudować* — narzędzie po narzędziu: interfejs, algorytm, pułapki, test akceptacyjny, koszt.

**Założenia stackowe** (do zmiany, ale reszta dokumentu z nich wynika):
- rdzeń i wszystkie własne bramki: **Python 3.12**, pakiet `gatekeeper`, CLI przez `typer`,
- orkiestracja: **GitHub Actions**, integracja przez Check Runs API,
- narzędzia zewnętrzne (semgrep, gitleaks, mutmut…) **nie są przepisywane** — piszemy do nich adaptery normalizujące wyjście,
- pierwszy język docelowy ocenianych repozytoriów: Python; JS/TS i C# jako kolejne, przez ten sam interfejs adapterów — G0–G3 mają dziś (kamień 3) pełny parytet dla wszystkich trzech, G2 wciąż tylko Python.

**Zasada podziału pracy:** wszystko, co istnieje jako dojrzałe narzędzie OSS, jest adapterem (1–2 dni). Wszystko, co jest specyficzne dla kodu z agenta, piszemy sami (3–10 dni) — i to jest właściwa wartość projektu.

---

## 0. Mapa: co kupujemy, co budujemy

| Bramka | Adapter (gotowe) | Własne narzędzie | Priorytet |
|---|---|---|---|
| G0 | — | `provenance`, `scope-guard` | **P0** |
| G1 | ruff, mypy, tsc, eslint, `dotnet build` | `dep-guard` (PyPI, npm, NuGet) | **P0** |
| G2 | pytest, diff-cover, mutmut | `cross-verify`, `test-sanity`, `mutation-scope`, `flaky-hunter`, `contract-diff` | **P0** (`cross-verify`, Python), P1 reszta + adaptery TS/JS/C# |
| G3 | semgrep, gitleaks, trivy, checkov, pip-audit, npm audit, `dotnet list package --vulnerable` | zestaw reguł „nigdy" (Python, TS/JS, C#), normalizator znalezisk | **P0** (sekrety, SAST, SCA — zbudowane), P1 reszta (IaC, licencje) |
| G4 | Claude API | `review-panel`, `context-builder`, `adversarial-verifier` | P2 |
| G5 | — | `report-renderer` (część core) | P1 |
| G6 | — | `deploy-readiness` | P3 |
| Rdzeń | — | `core` (model danych, runner, policy, store, CLI) | **P0** |
| Meta | — | `calibration-harness`, `metrics` | P1 |

Sumarycznie: **~55–70 osobodni** do pełnego systemu, **~12 osobodni** do pierwszego działającego wycinka (rozdz. 8).

---

## 1. Rdzeń (`gatekeeper.core`) — buduje się pierwszy, bo wszystko inne od niego zależy

Bez wspólnego modelu danych każda bramka wymyśli własny format i agregacja decyzji stanie się nie do napisania. To najczęstszy błąd w takich projektach: bramki powstają wcześniej niż kontrakt między nimi.

### Układ pakietu

```
gatekeeper/
├── pyproject.toml
├── gatekeeper/
│   ├── cli.py                  # gatekeeper run / explain / calibrate / report
│   ├── core/
│   │   ├── change.py           # ChangeContext — jedyne źródło prawdy o diffie
│   │   ├── finding.py          # Finding, Severity, GateResult, Decision
│   │   ├── runner.py           # uruchamianie procesów: timeout, sandbox, artefakty
│   │   ├── policy.py           # parser + ewaluator policy/gates.yaml, wyjątki
│   │   ├── orchestrator.py     # DAG bramek, równoległość, budżety, fail-fast
│   │   ├── report.py           # render: JSON, markdown, GitHub Check Run
│   │   └── store.py            # SQLite: przebiegi, znaleziska, decyzje, werdykty ludzi
│   ├── gates/                  # po jednym module na bramkę
│   └── adapters/               # normalizacja wyjść narzędzi zewnętrznych
├── policy/gates.yaml
├── rules/semgrep/              # reguły „nigdy"
├── prompts/                    # wersjonowane prompty recenzentów G4
└── calibration/                # zestaw kalibracyjny + PR-y celowo zepsute
```

### 1.1 `core/finding.py` — model danych

Jeden typ `Finding` dla wszystkich bramek, od gitleaksa po recenzenta LLM. Bez tego nie da się zrobić ani jednego wspólnego raportu, ani liczyć precyzji.

```python
class Severity(StrEnum):        # porządek liniowy, porównywalny w policy
    INFO = "info"; LOW = "low"; MEDIUM = "medium"; HIGH = "high"; CRITICAL = "critical"

@dataclass(frozen=True)
class Finding:
    gate: str                   # "G3.secrets"
    rule_id: str                # "gitleaks.aws-access-key" — stabilny, do statystyk i wyciszeń
    severity: Severity
    file: str | None            # ścieżka względem repo
    line: int | None
    title: str                  # jedno zdanie
    failure_scenario: str       # "przy wejściu X funkcja zwróci Y zamiast Z" — WYMAGANE
    confidence: float           # 0..1
    evidence: dict              # surowe wyjście narzędzia, do audytu
    fingerprint: str            # sha256(rule_id + ścieżka + znormalizowany fragment kodu)

@dataclass
class GateResult:
    gate: str
    status: Literal["pass", "fail", "error", "skipped", "warn_only"]
    duration_s: float
    findings: list[Finding]
    facts: dict[str, Any]       # np. {"diff_coverage": 0.83, "typosquat_suspect": True}
    artifacts: list[Path]       # logi, raporty HTML, wyjścia narzędzi
```

Dwie decyzje projektowe, które później trudno cofnąć:

- **`facts` osobno od `findings`.** Policy operuje na faktach (`mutation_score >= 0.6`), człowiek czyta znaleziska. Zmieszanie tego oznacza policy pełną parsowania stringów.
- **`fingerprint` liczony z *treści*, nie z numeru linii.** Inaczej każdy rebase odtwarza wszystkie wyciszenia i znaleziska „nowe od ostatniego pusha" nie działają.

**Koszt:** 2 dni. **Test akceptacyjny:** round-trip JSON, stabilność fingerprintu przy przesunięciu pliku o 50 linii.

### 1.2 `core/change.py` — `ChangeContext`

Jedyne miejsce, które zna gita. Każda bramka dostaje ten obiekt i nie woła `git` samodzielnie.

```python
class ChangeContext:
    base_sha: str; head_sha: str
    files: list[ChangedFile]        # ścieżka, status (A/M/D/R), język, zmienione linie
    added_lines(path) -> set[int]   # do diff coverage i scope'owania mutacji
    is_test_file(path) -> bool      # heurystyka per język, konfigurowalna
    ticket: Ticket | None           # z tytułu/gałęzi/trailera, NIE z opisu PR
    provenance: Provenance | None
    worktree_at(sha) -> Path        # git worktree add — do cross-verify i mutacji
```

**Pułapki:**
- `base_sha` to **merge-base**, nie `origin/main@HEAD` — inaczej diff zawiera cudze commity i `scope-guard` wybucha fałszywymi alarmami.
- pliki zmienione nazwą (`R`) trzeba śledzić, inaczej rename modułu wygląda jak wielki diff,
- `worktree_at` musi sprzątać po sobie także przy wyjątku (context manager).

**Koszt:** 2 dni.

### 1.3 `core/runner.py` — uruchamianie procesów

**Ważne, a łatwe do przeoczenia: brama uruchamia testy z PR-a, czyli wykonuje niezaufany kod napisany przez agenta.** Runner musi więc:
- działać bez sekretów w środowisku (żadnych tokenów CI, kluczy do rejestrów),
- mieć zablokowaną sieć poza whitelistą (rejestry pakietów) — inaczej „test" agenta może zawołać dowolny endpoint,
- limit czasu, pamięci i liczby procesów; twardy `kill -9` po przekroczeniu,
- write-access tylko do własnego worktree; `policy/`, `.github/` i `rules/` montowane read-only.

Implementacja: kontener (docker/podman) z `--network`, `--memory`, `--pids-limit`, oraz `--read-only` na katalogach polityki. Lokalnie fallback na `subprocess` z timeoutem i wyraźnym ostrzeżeniem, że tryb jest niebezpieczny.

**Koszt:** 3 dni. **Test akceptacyjny:** PR z testem próbującym odczytać `$GITHUB_TOKEN` i wysłać go na zewnątrz — musi ponieść porażkę na obu barierach.

### 1.4 `core/policy.py` — polityka jako kod

Parser `policy/gates.yaml` z rozdz. 4 PLAN.md + ewaluator wyrażeń.

- Wyrażenia progowe (`sast.severity >= high`) — **własny mini-ewaluator na AST, nie `eval`**. Gramatyka: `fakt operator wartość`, `paths_match: [globy]`, `and`/`or`. Trzydzieści linii, zero ryzyka.
- Wynik: `Decision(verdict: PASS | PASS_WITH_REVIEW | BLOCK, reasons: list[Reason])`, gdzie każdy `Reason` wskazuje regułę polityki **i** znalezisko/fakt, które ją wyzwoliło. Decyzja bez wskazania przyczyny jest bezużyteczna dla recenzenta.
- **Wyjątki z datą ważności:** `policy/exceptions.yaml` — wpis `{rule, scope, owner, reason, expires}`. Wygasły wyjątek = błąd walidacji polityki, nie ciche przepuszczenie. Osobna komenda `gatekeeper policy lint` w CI na `policy/` i cotygodniowy raport wygasających.
- **Tryb `warn_only` per bramka** — pierwszoklasowy, nie hack. Każda nowa bramka wchodzi na produkcję w tym trybie na tydzień.

**Koszt:** 3 dni. **Test akceptacyjny:** tablica ~20 przypadków (fakty → oczekiwany werdykt), w tym wygasły wyjątek i konflikt reguł.

### 1.5 `core/orchestrator.py` + `report.py` + `store.py`

- **Orchestrator:** DAG bramek z budżetami czasowymi; G1 i G3 równolegle; G2 po G1; G4 dopiero po zielonym G1–G3 (to jest reguła kosztowa z PLAN.md — kodujemy ją jako zależność w DAG, nie jako `if` w środku bramki). Ścieżka szybka: diff wyłącznie w `docs/`/`*.md` → tylko G0 + sekrety.
- **Report:** trzy renderery z jednego `RunResult`. Markdown do PR (jeden komentarz, aktualizowany — klucz idempotencji w ukrytym komentarzu HTML), Check Run per bramka, JSON do archiwum. **Limit 10 znalezisk w komentarzu, posortowanych wagą**, reszta za linkiem — to jest przeciwdziałanie zmęczeniu alertami z rozdz. 9 PLAN.md, wpisane w kod, nie w dobre chęci.
- **Store:** SQLite (`runs`, `findings`, `decisions`, `human_verdicts`, `overrides`). Potrzebny od początku, bo bez historii nie policzysz ani precyzji, ani escape rate, a dokładanie go później oznacza brak danych z pierwszego kwartału.

**Koszt:** 4 dni łącznie.

---

## 2. G0 — provenance i higiena zmiany

### 2.1 `provenance` — metadane pochodzenia

**Cel:** wiedzieć, który model i która sesja wyprodukowały zmianę — inaczej statystyki „defekty per model" z rozdz. 6 są niemożliwe do zebrania.

**Wejście:** commity z zakresu `base..head`, opcjonalnie `.gatekeeper/session.json` zapisany przez agenta.
**Wyjście:** fakty `provenance.model`, `provenance.agent`, `provenance.session_id`, `provenance.human_edited`, `provenance.iterations`.

**Algorytm:**
1. Parsuj trailery commitów (`Generated-By: codex/gpt-5`, `Session-Id: …`, `Co-Authored-By:`).
2. Brak trailera przy autorze z listy botów → `provenance.unknown_origin = True`.
3. `human_edited` = istnieje commit bez trailera po commicie z trailerem.
4. Zapisz do `store` — to jest właściwy produkt tej bramki; blokowanie tu jest wtórne.

**Pułapki:** squash-merge zjada trailery pośrednich commitów → trailer musi trafić też do opisu PR-a (szablon) albo do notatki gita. Wersja modelu bywa nieznana agentowi — akceptujemy `unknown`, nie zmyślamy.

**Dostarczyć razem z narzędziem:** gotowy hook/snippet do wklejenia w konfigurację agenta (`CLAUDE.md`/`AGENTS.md`), który wymusza trailer. Bez tego bramka nie ma danych wejściowych.

**Koszt:** 2 dni.

### 2.2 `scope-guard` — rozmiar i zakres

**Cel:** najskuteczniejsza pojedyncza reguła w systemie (PLAN.md §G0) — duży diff od agenta jest nierecenzowalny.

**Wyjście:** `diff.lines`, `diff.files`, `scope.out_of_scope_paths`, `scope.match_ratio`.

**Algorytm:**
1. Policz zmienione linie i pliki **z wyłączeniem** wygenerowanych (lockfile, snapshoty, `*.pb.go`, migracje) — lista wzorców w polityce. Bez tego każdy PR z lockfile'em przekracza próg i zespół natychmiast wyłącza bramkę.
2. Zakres z ticketu: mapowanie `ticket → dozwolone globy` z `policy/scope_map.yaml` (np. komponent w Jirze → ścieżki). Brak mapowania → bramka raportuje, nie blokuje.
3. Flaga, gdy plik poza zakresem **i** nie jest ewidentnie towarzyszący (test do zmienionego pliku, import).

**Test akceptacyjny:** PR o formatowaniu daty dotykający `auth/` → flaga; PR z 3000 linii samego `package-lock.json` → brak flagi.

**Koszt:** 3 dni.

---

## 3. G1 — statyczna poprawność

### 3.1 Adaptery statyczne

Cienka warstwa: uruchom narzędzie → sparsuj wyjście (JSON/SARIF) → `list[Finding]`. Ruff, mypy `--strict`, pyright, tsc, eslint. Wspólna klasa bazowa `ToolAdapter` z `command()`, `parse()`, `severity_map`.

**Jedyna nietrywialna decyzja:** raportujemy **tylko znaleziska w zmienionych liniach** (+3 linie kontekstu), inaczej pierwszy przebieg na starszym repo daje 4000 błędów mypy i projekt umiera w dniu wdrożenia. Filtrowanie po `ChangeContext.added_lines`.

**Koszt:** 3 dni na komplet adapterów + SARIF jako format pośredni.

### 3.2 `dep-guard` — weryfikacja zależności ⭐

**Cel:** halucynowane i typosquatowane pakiety (*slopsquatting*) — klasa defektu, której żaden istniejący skaner nie łapie, bo wszystkie zakładają, że pakiet w manifeście jest prawdziwy.

**Wejście:** diff manifestów (`pyproject.toml`, `requirements*.txt`, `package.json`) + lockfile + **importy w kodzie**.
**Wyjście:** `deps.unknown_package`, `deps.typosquat_suspect`, `deps.too_young`, `deps.low_downloads`, `deps.no_source_repo`, `deps.undeclared_import`, `deps.unjustified`.

**Algorytm (per nowy pakiet):**
1. **Istnienie** — PyPI JSON API / npm registry. 404 → `unknown_package` (BLOCK). To pojedynczo najczęstszy błąd agenta.
2. **Wiek** — data pierwszego wydania; < 90 dni → flaga.
3. **Popularność** — pobrania (pypistats / npm downloads API) poniżej progu → flaga.
4. **Repo źródłowe** — `project_urls`/`repository` istnieje i odpowiada 200.
5. **Typosquat** — dystans Damerau-Levenshtein ≤ 2 do listy top-5000 pakietów, po **normalizacji PEP 503** (`-`/`_`/`.` → jedno) i po podmianie homoglifów (`rn`→`m`, `l`→`1`, cyrylica). Trafienie przy jednocześnie niskich pobraniach → `typosquat_suspect` (BLOCK).
6. **Kierunek odwrotny** — `import X` w kodzie bez wpisu w manifeście → `undeclared_import`. Agenci robią to nagminnie i CI to łapie dopiero na runtime.
7. **Uzasadnienie** — nowa zależność bez akapitu „dlaczego" w opisie PR → flaga (nie blokada).

**Pułapki, które trzeba rozwiązać w kodzie, nie w dokumentacji:**
- **Lista top-N musi być zwendorowana i wersjonowana w repo** (odświeżana raz na miesiąc jobem). Pobieranie jej w locie z sieci robi z bramki źródło niedeterminizmu i punkt awarii.
- Mapowanie import → nazwa dystrybucji nie jest tożsamościowe (`import yaml` ↔ `PyYAML`, `import cv2` ↔ `opencv-python`). Potrzebna tablica aliasów + `importlib.metadata.packages_distributions()` dla zainstalowanych.
- Pakiety wewnętrzne/prywatne rejestry → whitelist prefiksów w polityce, inaczej każdy firmowy pakiet to `unknown_package`.
- Rate limity rejestrów → cache na dysku z TTL 24 h.

**Test akceptacyjny:** fixture z pakietami `requsts`, `python-dotnev`, świeżo utworzonym pakietem testowym i pakietem nieistniejącym — wszystkie cztery muszą zostać złapane, a 50 popularnych pakietów musi przejść bez fałszywego alarmu.

**Koszt:** 5 dni. **Priorytet: najwyższy po rdzeniu.**

---

## 4. G2 — dowód behawioralny (najtrudniejsza i najbardziej wartościowa część)

### 4.1 `cross-verify` — nowe testy przeciw staremu kodowi ⭐⭐

**Cel:** wykrycie testu, który niczego nie dowodzi. Najlepszy stosunek wartości do kosztu w całym systemie.

**Algorytm:**
1. `git worktree` na `base_sha`.
2. Nałóż **wyłącznie pliki testowe** z `head` (oraz fixture'y/conftest — nie kod produkcyjny).
3. Zbierz listę **nowych i zmodyfikowanych testów** (AST: nazwy funkcji/klas testowych obecne w head, nieobecne lub zmienione w base).
4. Uruchom dokładnie te testy (`pytest --deselect` reszty).
5. Klasyfikuj wynik per test:
   - **FAILED na asercji** → dowód poprawny (test wykrywa różnicę),
   - **ERROR przy imporcie / collection** (nowy moduł jeszcze nie istnieje) → dowód słaby, ale akceptowalny; osobny fakt,
   - **PASSED** → `tests.pass_on_pre_change_code` → **BLOCK**.

**Fałszywe alarmy — trzeba je obsłużyć, inaczej bramka zostanie wyłączona w drugim tygodniu.** Trzy legalne przypadki, w których nowy test *powinien* przejść na starym kodzie:
- **czysty refaktor** (zachowanie bez zmian),
- **backfill testów** do istniejącego, nieprzetestowanego kodu,
- **test regresyjny do buga naprawionego wcześniej** w innym PR.

Rozwiązanie: marker w kodzie testu (`@pytest.mark.characterization`) albo etykieta PR-a — jawna, policzalna deklaracja autora. Bramka wtedy nie blokuje, ale **zapisuje deklarację do store'a** i raportuje jej użycie w metrykach miesięcznych. Nadużywanie markera staje się widoczne w liczbach.

**Test akceptacyjny:** repo-fixture z parą PR-ów — jeden z prawdziwym testem nowej funkcji, jeden z testem asertującym stan już istniejący. Drugi musi zostać zablokowany.

**Koszt:** 4 dni (Python), +2 dni na adapter JS/TS.

### 4.2 `test-sanity` — linter jakości testów

**Cel:** testy-atrapy. Analiza AST plików testowych ze zmian.

Reguły (`rule_id` → waga):
| Reguła | Wykrycie | Waga |
|---|---|---|
| `test.no_assertion` | funkcja testowa bez `assert`/`pytest.raises`/`mock.assert_*` | BLOCK |
| `test.constant_assertion` | `assert True`, `assert 1 == 1`, `assert x == x` | BLOCK |
| `test.mock_echo` | wartość z `Mock(return_value=V)` porównywana z `V` w asercji (dopasowanie po AST, nie regex) | flaga |
| `test.only_smoke` | test wywołuje funkcję, ale asertuje wyłącznie `is not None` | flaga |
| `test.exception_swallowed` | `try/except: pass` wewnątrz testu | flaga |
| `test.no_new_path` | zmodyfikowany test nie dotyka żadnej nowej gałęzi (dane z coverage) | flaga |

**Implementacja:** własne reguły na `ast` + część jako reguły `semgrep` (łatwiejsze do rozszerzania przez zespół — i to jest miejsce, w którym ląduje pętla zwrotna z rozdz. 5 PLAN.md).

**Pułapka:** testy parametryzowane i asercje w helperach (`_assert_valid(x)`) — trzeba śledzić wywołania helperów o jeden poziom w głąb, inaczej `no_assertion` daje fałszywe alarmy na dobrze napisanych testach.

**Koszt:** 4 dni.

### 4.3 `mutation-scope` — testy mutacyjne ograniczone do diffa

**Cel:** jedyny automatyczny dowód, że test cokolwiek testuje. Problem nie jest w mutowaniu (mutmut/Stryker to robią), tylko w **czasie** — pełny przebieg na repo to godziny.

**Algorytm:**
1. Wyznacz mutantów wyłącznie w **zmienionych liniach** (`ChangedFile.added_lines`).
2. Ogranicz zestaw testów per mutant przez **test impact analysis**: coverage z kontekstami (`coverage.py --contexts`) daje mapę linia → testy. Mutant uruchamia tylko te testy.
3. Limit: max ~200 mutantów na PR (próbkowanie deterministyczne po hashu, żeby wynik był powtarzalny), timeout per mutant = 2× czas bazowy testu.
4. `mutation_score = zabici / (zabici + przeżyli)`, mutanty timeoutowane liczone jako zabite, `no coverage` raportowane osobno.
5. Wyjście: fakt + lista **przeżyłych mutantów z fragmentem kodu** — to jest realnie użyteczny raport dla recenzenta („zmiana `>=` na `>` w linii 47 nie psuje żadnego testu").

**Pułapki:** mutanty równoważne (semantycznie identyczne) zawyżają fałszywe alarmy — dlatego próg 60%, nie 90%. Niedeterministyczne testy zabijają wiarygodność — dlatego `flaky-hunter` musi być uruchamiany **przed** mutacjami.

**Koszt:** 5 dni.

### 4.4 `flaky-hunter`

Uruchom nowe/zmienione testy N× (domyślnie 5), różne ziarna losowe i różna kolejność (`pytest-randomly`). Każda niestabilność → BLOCK, z informacją, który test i w którym przebiegu padł. Równolegle, więc koszt czasowy ≈ jeden przebieg.

Dodatkowo: wykrywanie zależności od kolejności (uruchom też w odwróconej kolejności) — częsty defekt w testach generowanych masowo.

**Koszt:** 2 dni.

### 4.5 `diff-coverage` (adapter) i `contract-diff`

- **diff-coverage:** `coverage.py` + `diff-cover` z `base_sha`; fakt `diff_coverage`. Dodatkowo **branch coverage**, nie tylko liniowe — inaczej `if` z pustą gałęzią błędu liczy się jako pokryty. **1 dzień.**
- **contract-diff:** wykrycie zmiany kontraktu, którą agent „zaktualizował" po obu stronach. `oasdiff` dla OpenAPI, `buf breaking` dla protobuf, `graphql-inspector` dla GraphQL. Adapter klasyfikuje zmiany na `breaking` / `non-breaking` i wystawia `api.contract_changed`. **3 dni.**

---

## 5. G3 — bezpieczeństwo

### 5.1 Adaptery i normalizator

semgrep, gitleaks, trufflehog, trivy, osv-scanner, checkov, pip-audit, scancode. Wszystkie mają wyjście JSON lub SARIF → **jeden normalizator SARIF → `Finding`** obsługuje większość. Deduplikacja po `fingerprint` (te same znaleziska z semgrep i bandit).

**Kluczowe zawężenia**, bez których bramka tonie w szumie:
- SCA blokuje tylko na podatnościach w **nowo dodanych** zależnościach (istniejący dług idzie do osobnego raportu tygodniowego),
- sekrety skanowane **także w testach i fixture'ach** (PLAN.md §G3) — tu wyjątkowo bez zawężania do diffa: skan całego drzewa przy pierwszym przebiegu, potem inkrementalnie,
- licencje: blokada wyłącznie na liście `forbidden` z polityki, nie na „nieznanej" licencji.

**Koszt:** 4 dni.

### 5.2 Zestaw reguł „nigdy" (`rules/semgrep/`)

Własne reguły z listy w PLAN.md §G3: wyłączony TLS verify, `eval` na wejściu, SQL przez konkatenację, `shell=True`, `pickle`/`yaml.load`, wildcard IAM, nowy endpoint bez dekoratora autoryzacji.

Ostatnia jest najtrudniejsza i najcenniejsza: wymaga znajomości konwencji repo (dekorator `@requires_auth` albo middleware). Implementacja: reguła semgrep parametryzowana nazwą dekoratora z konfiguracji projektu.

**Do każdej reguły obowiązkowo test pozytywny i negatywny** w `rules/tests/` (`semgrep --test`). Reguła bez testu negatywnego prędzej czy później zaczyna blokować poprawny kod i podkopuje zaufanie do całej bramy.

**Koszt:** 4 dni (7 reguł + testy + kalibracja na realnym repo).

---

## 6. G4 — panel recenzentów LLM

Uruchamiany **tylko po zielonym G1–G3**. Trzy komponenty.

### 6.1 `context-builder` — od tego zależy jakość całej bramki

Recenzent jest tak dobry, jak kontekst, który dostanie. To jest właściwa praca inżynierska w G4; prompty są łatwe.

Buduje per recenzent:
- diff w formacie z numerami linii (żeby model mógł się odwołać do konkretnej linii),
- **ticket** — dla recenzenta „intencji" **bez opisu PR napisanego przez agenta** (PLAN.md §G4). Egzekwowane w kodzie: osobna funkcja `intent_context()`, która fizycznie nie ma dostępu do pola z opisem,
- pliki powiązane: definicje symboli używanych w diffie, wywołujący zmienione funkcje (ctags/tree-sitter, jeden poziom),
- istniejące abstrakcje dla recenzenta „spójności" — mapa modułów + `CLAUDE.md`/`AGENTS.md` repo,
- wyniki G1–G3 (co już zostało sprawdzone maszynowo — żeby recenzent nie powtarzał pracy lintera).

Budżet tokenów per recenzent i strategia przycinania (najpierw diff, potem kontekst wywołań). Cache po SHA plików — niezmienione pliki nie są przesyłane ponownie (prompt caching).

**Koszt:** 5 dni.

### 6.2 `review-panel` — 5 recenzentów

Pięć niezależnych wywołań (intencja, poprawność, bezpieczeństwo, jakość testów, spójność), osobne konteksty, temperatura 0, **structured output przez tool-use ze schematem** `Finding`. Model inny niż generujący zmianę (wybór na podstawie `provenance.model` z G0 — realne zastosowanie danych z G0).

Prompty w `prompts/reviewers/*.md`, **wersjonowane, z numerem wersji zapisywanym przy każdym znalezisku w store**. Bez tego nie da się stwierdzić, czy zmiana promptu poprawiła, czy pogorszyła precyzję.

**Koszt:** 4 dni.

### 6.3 `adversarial-verifier` — bez tego bramka umrze na fałszywych alarmach

Każde znalezisko → 2–3 niezależne wywołania z zadaniem **obalenia** zarzutu (dostają kod + zarzut, nie dostają uzasadnienia recenzenta). Przy niepewności domyślnie „obalone". Przeżywa tylko to, czego nie udało się obalić. Głosowanie większościowe.

Dodatkowo, po weryfikacji: deduplikacja po fingerprincie, sortowanie wagą × pewność, **twardy limit 10 znalezisk na PR**.

**Kontrola kosztu:** triaż tańszym modelem (odrzucenie ewidentnie stylistycznych zgłoszeń), weryfikacja mocnym.

**Koszt:** 3 dni.

**Wejście na produkcję:** tryb komentarza bez prawa blokowania, dopóki precyzja na zestawie kalibracyjnym nie przekroczy 80% (PLAN.md §7, faza 3). Egzekwowane przez flagę w polityce, nie przez obietnicę.

---

## 7. G6 i pętla zwrotna

### 7.1 `deploy-readiness`

Maszynowy checklist z PLAN.md §G6:
- **migracje:** parser plików Alembic/Django — wykrycie operacji nieodwracalnych (`DROP COLUMN`, `ALTER TYPE` zawężający, `NOT NULL` bez default), brak `downgrade()`, wzorzec expand/contract;
- **feature flag:** zmiana dotyka ścieżki user-facing (globy z polityki) a nie dodano odwołania do systemu flag → flaga;
- **obserwowalność:** nowa funkcja publiczna/endpoint bez metryki i bez logu → flaga (AST: brak wywołań z modułu telemetrii w nowym kodzie);
- **konfiguracja:** nowa zmienna środowiskowa w kodzie bez wpisu w `.env.example`/manifestach wszystkich środowisk → BLOCK. Tania reguła, łapie realny i częsty incydent produkcyjny.

**Koszt:** 4 dni.

### 7.2 `feedback` — sprzężenie zwrotne do agenta

- Eksport `RunResult` → ustrukturyzowane zadanie naprawcze (markdown + JSON) dla agenta, z **licznikiem iteracji w store; po 3 twarda eskalacja do człowieka**.
- **Auto-fix wyłącznie dla klas bezpiecznych** — allowlist `rule_id` w polityce: formatowanie, sortowanie importów, proste ostrzeżenia lintera. Domyślnie pusta, rozszerzana świadomie. Nigdy bezpieczeństwo ani logika.
- **Żniwiarz reguł:** znalezisko powtarzające się w ≥3 PR-ach → propozycja reguły semgrep lub wpisu w `AGENTS.md`, jako automatyczny PR do repo zespołu. To domyka pętlę z PLAN.md §5: każdy defekt zostawia po sobie regułę.

**Koszt:** 4 dni.

### 7.3 `calibration-harness` i `metrics`

- **Harness:** definicja zestawu w `calibration/cases.yaml` (`repo, base_sha, head_sha, oczekiwany werdykt, oczekiwane rule_id`). `gatekeeper calibrate` przepuszcza wszystkie, raportuje precyzję/pokrycie per bramka i **różnicę względem poprzedniego przebiegu** — to jest test regresyjny samej bramy. Cotygodniowo w cronie.
- **PR-y celowo zepsute:** 10–15 syntetycznych przypadków, po jednym na klasę defektu z tabeli w §1 PLAN.md. Budowane jako fixture-repo w `calibration/fixtures/`, wersjonowane razem z kodem.
- **Metrics:** zapytania po store + tygodniowy raport (escape rate, precyzja, fałszywe alarmy G4, czas przejścia, defekty per model). Escape rate wymaga sprzężenia z incydentami — minimalna wersja: etykieta `caused-incident` na PR-ze zamykana ręcznie, plus link z rewertów (`git revert` wskazuje PR źródłowy).

**Koszt:** 5 dni razem. **Buduje się w fazie 1, nie na końcu** — bez danych z pierwszych tygodni progi w polityce pozostaną zgadywaniem.

---

## 8. Kolejność budowy

Mapowanie na roadmapę z PLAN.md §7, z podziałem na dostarczalne kamienie.

### Kamień 1 — „tydzień pierwszy" (~12 dni, realizuje PLAN.md §10)

Minimalny, ale **kompletny pionowo** wycinek: od diffa do decyzji w PR.

| # | Element | Dni |
|---|---|---|
| 1 | `core/finding.py` + `core/change.py` | 4 |
| 2 | `core/policy.py` (podzbiór: progi + blocking) | 2 |
| 3 | `core/report.py` — komentarz PR + Check Run | 2 |
| 4 | adapter gitleaks | 1 |
| 5 | `dep-guard` — wersja minimalna (istnienie + wiek + typosquat) | 2 |
| 6 | `scope-guard` — limit rozmiaru diffa | 1 |

Wynik: brama w trybie `warn-only` łapiąca sekrety, halucynowane pakiety i zbyt duże diffy.

### Kamień 2 — cross-verify (~6 dni)

`cross-verify` + `store` + pierwsze metryki. Osobno, bo to pojedynczo najwartościowsze narzędzie i zasługuje na własny cykl kalibracji.

### Kamień 3 — reszta fundamentu deterministycznego (~15 dni)

`runner` w kontenerze, adaptery G1 i G3 w komplecie, reguły „nigdy", `provenance`, `orchestrator` z budżetami, `calibration-harness`. Koniec fazy 1 z PLAN.md — po niej włączamy blokowanie.

### Kamień 4 — dowód behawioralny (~15 dni)

`test-sanity`, `mutation-scope`, `flaky-hunter`, `diff-coverage`, `contract-diff`.

### Kamień 5 — warstwa semantyczna (~12 dni)

`context-builder`, `review-panel`, `adversarial-verifier`. Wejście bez prawa blokowania.

### Kamień 6 — wdrożeniowa i pętla (~13 dni)

`deploy-readiness`, `feedback`, auto-fix, żniwiarz reguł, raport metryk.

---

## 9. Ryzyka implementacyjne (inne niż ryzyka produktowe z PLAN.md §9)

| Ryzyko | Przeciwdziałanie |
|---|---|
| **Bramka uruchamia niezaufany kod z PR-a** | `core/runner` w kontenerze bez sekretów i bez sieci — projektowane od pierwszego dnia, nie doklejane później |
| **Czas G2 wymyka się spod kontroli** | Test impact analysis + limit mutantów + twarde budżety w orkiestratorze; budżet przekroczony = `error`, nie ciche `pass` |
| **Fałszywe alarmy `cross-verify` na refaktorach** | Markery `characterization`/`test-backfill`, liczone i raportowane |
| **Adaptery gniją przy zmianach wersji narzędzi** | Wersje przypięte, testy adapterów na zapisanych próbkach wyjścia (golden files) |
| **Rdzeń rośnie w monolit** | Kontrakt `Gate.run(ChangeContext) -> GateResult` jako jedyny interfejs; bramki jako pluginy przez entry points — nowa bramka bez dotykania rdzenia |
| **Brak danych do kalibracji na starcie** | Faza 0 z PLAN.md przed kodowaniem: zebranie 30–50 historycznych PR-ów jest zadaniem równoległym do kamienia 1 |
