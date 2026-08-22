# Plan: brama jakości dla kodu generowanego przez agentów LLM

**Cel:** zbudować automatyczny system, który dla zmiany (PR/patch) wyprodukowanej przez agenta LLM (Codex, Claude Code, Cursor, Devin…) odpowiada na pytanie: *czy ten kod może pójść na produkcję?* — z uzasadnieniem, dowodami i jednoznaczną decyzją: `PASS` / `PASS-WITH-REVIEW` / `BLOCK`.

**Nie-cel:** zastąpienie code review przez człowieka. Celem jest przesunięcie uwagi człowieka tam, gdzie faktycznie jest potrzebna, i zablokowanie klas błędów, które maszyna wyłapie taniej i pewniej.

---

## 1. Dlaczego kod z LLM wymaga osobnej bramy

Standardowy CI wykrywa "kod nie działa". Kod z agenta LLM zwykle *działa* — i to jest problem. Klasy defektów, które przechodzą przez klasyczny pipeline:

| Klasa | Objaw | Dlaczego zwykły CI tego nie łapie |
|---|---|---|
| **Halucynowane zależności** | `import`/`require` pakietu, który nie istnieje lub istnieje jako typosquat (*slopsquatting*) | Lockfile powstał razem z kodem — CI instaluje to, co agent wpisał |
| **Testy pisane pod implementację** | 90% pokrycia, testy asertują to, co kod robi, nie to, co powinien | Coverage rośnie, testy są zielone |
| **Testy-atrapy** | `assert True`, mock zwracający oczekiwaną wartość, test bez asercji | Zielone |
| **Zakres większy niż zlecenie** | Agent "przy okazji" przepisał moduł obok, zmienił format logów, podbił zależność | Diff jest duży, ale poprawny składniowo |
| **Sekrety i dane testowe** | Klucz API w fixture, prawdziwy endpoint prod w konfiguracji testowej | Skanery sekretów bywają wyłączone dla testów |
| **Cicha zmiana kontraktu** | Zmieniony kształt odpowiedzi API, nazwa pola, kod błędu | Testy też zaktualizowane — przez tego samego agenta |
| **Dryf architektoniczny** | Nowy wzorzec/biblioteka niezgodna z konwencją repo | Nie ma reguły lintera na "u nas się tak nie robi" |
| **Brak obsługi ścieżek błędów** | Happy path pełny, timeouty/retry/rollback puste | Testy pokrywają happy path |
| **Licencje i pochodzenie kodu** | Fragment skopiowany z GPL/AGPL | Brak skanu licencji |
| **Nadmierne uprawnienia** | Nowa rola IAM `*:*`, `chmod 777`, wyłączony TLS verify "żeby przeszło" | To poprawny kod |

**Wniosek projektowy:** brama musi weryfikować nie tylko *kod*, ale też **artefakty, którym normalnie ufamy** — testy, lockfile, konfigurację, opis PR. W modelu z agentem wszystkie one pochodzą od tego samego, potencjalnie mylącego się autora. To jedyne założenie, na którym opiera się cała reszta planu.

---

## 2. Architektura: łańcuch bramek

```
  patch/PR od agenta
        │
   ┌────▼─────┐  G0  Provenance i higiena zmiany
   │  wejście │      (kto, czym, z jakiego promptu, jaki zakres)
   └────┬─────┘
   ┌────▼─────┐  G1  Statyczna poprawność        ← szybkie, deterministyczne
   │  tanie   │      (build, lint, typy, format, dep-check)
   └────┬─────┘
   ┌────▼─────┐  G2  Dowód behawioralny
   │  testy   │      (testy, mutacje, kontrakty, regresja)
   └────┬─────┘
   ┌────▼─────┐  G3  Bezpieczeństwo
   │   sec    │      (SAST, SCA, sekrety, IaC, licencje)
   └────┬─────┘
   ┌────▼─────┐  G4  Review semantyczny (LLM-as-judge, panel)
   │   AI     │      (intencja vs. implementacja, ryzyko, zakres)
   └────┬─────┘
   ┌────▼─────┐  G5  Człowiek — tylko gdy polityka tego wymaga
   │  human   │
   └────┬─────┘
   ┌────▼─────┐  G6  Gotowość wdrożeniowa
   │  deploy  │      (migracje, feature flag, rollback, obserwowalność)
   └────┬─────┘
        ▼  decyzja + raport + ślad audytowy
```

Zasada kolejności: **najtańsze i najbardziej deterministyczne najpierw**. G4 (LLM) jest drogi i niedeterministyczny — nie uruchamiamy go, dopóki G1–G3 nie przejdą. Odwrotna kolejność to główny błąd projektowy w tego typu systemach.

---

## 3. Bramki — co dokładnie sprawdzać

### G0 — Provenance i higiena zmiany

Bez tego nie da się nic sensownie ocenić ani później zbadać incydentu.

- **Metadane zmiany:** model + wersja, agent/narzędzie, prompt lub zadanie źródłowe, ID sesji, liczba iteracji, czy człowiek edytował po agencie.
- **Oznaczenie w repo:** trailer w commicie (`Generated-By: codex/gpt-5`, `Session-Id: …`) — pozwala potem liczyć statystyki defektów per model.
- **Higiena zakresu:** diff nie przekracza limitu (np. 400 zmienionych linii lub 15 plików) — większe wymagają rozbicia. To najskuteczniejsza pojedyncza reguła w całym systemie: duży diff od agenta jest nierecenzowalny i przez to niebezpieczny.
- **Zgodność z zadaniem:** czy dotknięte pliki mieszczą się w deklarowanym zakresie (ticket → ścieżki). Zmiana w `auth/` przy zadaniu o formatowaniu daty = flaga.

### G1 — Statyczna poprawność (budżet: < 3 min)

- Build / kompilacja, linter, formatter, **typy w trybie strict** (mypy/pyright, tsc `noImplicitAny`) — typy wyłapują dużą część halucynacji API.
- **Weryfikacja zależności** (kluczowe dla LLM):
  - każdy nowy pakiet istnieje w oficjalnym rejestrze,
  - wiek pakietu > 90 dni, liczba pobrań powyżej progu, repo źródłowe istnieje,
  - dystans Levenshteina do popularnych pakietów (wykrywanie typosquat/slopsquat),
  - nowa zależność w ogóle wymaga uzasadnienia w opisie PR.
- Brak martwego kodu, brak `TODO`/`FIXME` bez numeru zadania, brak zakomentowanych bloków.
- Dead-code / nieużywane importy i eksporty (agenci zostawiają dużo śmieci).

### G2 — Dowód behawioralny (budżet: < 15 min)

Tu rozstrzyga się, czy testy są *dowodem*, czy *dekoracją*.

- **Testy jednostkowe/integracyjne** — muszą przechodzić, oczywiste.
- **Pokrycie różnicowe (diff coverage)**, nie globalne: nowy/zmieniony kod ≥ 80%. Globalne pokrycie jest łatwe do oszukania.
- **Testy mutacyjne na samym diffie** (mutmut, Stryker, PIT) — jedyny automatyczny sposób na wykrycie testów-atrap. Próg: mutation score ≥ 60% na zmienionych plikach. Jeżeli mutacja przechodzi niezauważona, test nie testuje niczego.
- **Kontrola jakości testów** (reguły lintera + heurystyki):
  - test bez asercji → BLOCK,
  - `assert True` / asercja na stałą → BLOCK,
  - mock, który zwraca dokładnie wartość porównywaną w asercji → flaga,
  - test dodany do już istniejącej funkcji, ale nietestujący nowej ścieżki → flaga.
- **Weryfikacja krzyżowa testów:** uruchom nowe testy przeciw **kodowi sprzed zmiany**. Test dla nowej funkcjonalności *musi* na starym kodzie polec. Jeśli przechodzi — nie testuje tego, co deklaruje. Tania, bardzo skuteczna technika.
- **Testy kontraktowe** (Pact / schema diff OpenAPI, protobuf, GraphQL) — wykrycie zmiany kontraktu, którą agent "zaktualizował" po obu stronach.
- **Regresja:** pełny zestaw testów projektu, nie tylko nowe.
- **Detekcja flaky:** nowe testy uruchamiane N× (np. 5) — niestabilne odrzucane od razu, zanim zatrują pipeline.
- Dla zmian wrażliwych na wydajność: benchmark z progiem regresji.

### G3 — Bezpieczeństwo (budżet: < 10 min)

- **SAST** — Semgrep (reguły OWASP + własne), CodeQL dla głębszych ścieżek danych.
- **SCA** — podatności w zależnościach (Trivy, osv-scanner, Dependabot); blokada na `HIGH`/`CRITICAL` w nowo dodanych zależnościach.
- **Sekrety** — gitleaks / trufflehog, **także w plikach testowych i fixture'ach** (typowe miejsce wycieków od agentów).
- **IaC** — Checkov/tfsec: uprawnienia, publiczne buckety, otwarte security groups.
- **Licencje** — skan SPDX; blokada licencji copyleft niezgodnych z polityką.
- **Reguły „nigdy"** (własne reguły Semgrep, twarda blokada):
  - wyłączenie weryfikacji TLS/certyfikatów,
  - `eval` / dynamiczne wykonanie na danych z wejścia,
  - budowa SQL przez konkatenację stringów,
  - `subprocess` z `shell=True` na danych wejściowych,
  - deserializacja niezaufanych danych (`pickle`, `yaml.load`),
  - wildcard w politykach IAM/RBAC,
  - nowy publiczny endpoint bez warstwy autoryzacji.
- **Dla kodu obsługującego wejście LLM/agentów:** kontrola granic prompt injection, sandbox dla wykonywanego kodu, limity narzędzi.

### G4 — Review semantyczny (LLM jako recenzent)

Bramka odpowiadająca na pytania, których nie da się wyrazić regułą. Wzorzec: **panel niezależnych recenzentów z różnymi obiektywami**, potem weryfikacja adwersaryjna.

Recenzenci (osobne wywołania, osobne konteksty, każdy z własnym pryzmatem):
1. **Intencja** — czy implementacja realizuje zadanie z ticketu? Co zostało pominięte? Co zrobiono ponad zakres?
2. **Poprawność** — ścieżki błędów, warunki brzegowe, współbieżność, null/pusty zbiór, przepełnienia, timeouty.
3. **Bezpieczeństwo** — model zagrożeń dla tej konkretnej zmiany (uzupełnia SAST o kontekst biznesowy: kto może to wywołać i z jakimi danymi).
4. **Jakość testów** — czy testy dowodzą wymagania, czy tylko odtwarzają implementację? Jakiego testu brakuje?
5. **Spójność z repo** — czy zmiana używa istniejących abstrakcji, czy dubluje coś, co już jest? (Wymaga podania recenzentowi kontekstu istniejących modułów.)

Konstrukcja krytyczna dla wiarygodności:
- **Weryfikacja adwersaryjna:** każde zgłoszenie trafia do 2–3 niezależnych weryfikatorów z instrukcją *obalenia* zarzutu; przy niepewności domyślnie „obalone". Zostaje tylko to, co przeżyje. Bez tego bramka tonie w fałszywych alarmach i zespół przestaje ją czytać — to najczęstsza przyczyna śmierci takich systemów.
- **Inny model niż generujący.** Recenzja kodu z Codeksa przez Codeksa dzieli z nim ślepe plamy. Minimum: inny dostawca lub wyraźnie inny model.
- **Wyjście strukturalne** (JSON): `{plik, linia, kategoria, waga, scenariusz_awarii, pewność}`. Wymóg konkretnego scenariusza awarii („przy wejściu X funkcja zwróci Y zamiast Z") eliminuje większość zgłoszeń stylistycznych udających błędy.
- **Bez dostępu do opisu PR napisanego przez agenta** w recenzencie „intencji" — porównujemy kod z *ticketem*, nie z narracją autora. Inaczej recenzent kupuje opowieść zamiast czytać kod.

### G5 — Człowiek

Polityka wyzwalania (nie „zawsze" i nie „nigdy"):
- zmiana dotyka ścieżki wrażliwej (auth, płatności, dane osobowe, migracje, infrastruktura),
- G4 zgłosiło niezobalone znalezisko wagi ≥ high,
- diff powyżej progu,
- nowa zależność zewnętrzna,
- zmiana publicznego kontraktu API,
- wynik zbiorczy w szarej strefie.

Człowiek dostaje **raport z bramek, nie surowy diff**: co sprawdzono, co przeszło, gdzie dokładnie patrzeć i dlaczego. To jest cała wartość dodana systemu dla recenzenta.

### G6 — Gotowość wdrożeniowa

Checklist wykonywany maszynowo, nie z pamięci:
- migracje bazy: odwracalne, kompatybilne wstecz (expand/contract), przetestowane na kopii,
- zmiana za feature flagiem, jeśli dotyka ścieżki użytkownika,
- plan rollbacku istnieje i jest wykonalny (czy da się cofnąć po migracji?),
- nowe metryki/logi/alerty dla nowej ścieżki — kod bez obserwowalności jest niediagnozowalny na produkcji,
- zmiany konfiguracji i sekretów udokumentowane, zmienne środowiskowe dodane do wszystkich środowisk,
- wpływ na wydajność i koszt (nowe zapytania, N+1, nowe wywołania API),
- deploy kanarkowy z automatycznym progiem cofnięcia.

---

## 4. Decyzja: polityka jako kod

Zamiast jednego wyniku liczbowego („score 82/100") — jawna polityka. Wynik liczbowy zachęca do optymalizowania pod metrykę i ukrywa, *co* zawiodło.

```yaml
# policy/gates.yaml
version: 1

blocking:            # dowolne trafienie => BLOCK
  - secrets.found
  - sast.severity >= high
  - deps.unknown_package
  - deps.typosquat_suspect
  - tests.no_assertion
  - tests.pass_on_pre_change_code     # test nie dowodzi niczego nowego
  - license.forbidden
  - iac.wildcard_permission

thresholds:
  diff_coverage:      { min: 0.80 }
  mutation_score:     { min: 0.60, scope: changed_files }
  diff_size:          { max_lines: 400, max_files: 15 }
  flaky_runs:         { repeat: 5, tolerate_failures: 0 }

human_review_required_when:
  - paths_match: ["**/auth/**", "**/payments/**", "**/migrations/**", "infra/**"]
  - ai_review.unrefuted_findings.severity >= high
  - deps.new_external_package
  - api.contract_changed

deploy_readiness:
  require:
    - migration.reversible
    - rollback.plan_present
    - observability.metrics_added        # gdy dodano nową ścieżkę
    - feature_flag.present               # gdy zmiana user-facing
```

Kluczowe zasady:
- **Wyjątki są jawne i wygasają.** Obejście bramki wymaga wpisu z uzasadnieniem, właścicielem i datą ważności (max 30 dni). Bez wygasania po pół roku polityka jest zbiorem wyjątków.
- **Polityka wersjonowana w repo**, zmiany do niej przechodzą normalne review — inaczej agent nauczy się jej „poprawiać".
- **Agent nie ma uprawnień do modyfikacji `policy/`, CI ani konfiguracji bramek.** Egzekwowane przez CODEOWNERS i uprawnienia gałęzi. To jest granica bezpieczeństwa całego systemu — jeżeli oceniany może zmienić kryteria oceny, reszta nie ma znaczenia.

---

## 5. Sprzężenie zwrotne do agenta

System ma nie tylko blokować, ale i naprawiać — bez tego zespół dostaje wąskie gardło zamiast pomocy.

- Ustrukturyzowany raport z porażek wraca do agenta jako zadanie naprawcze (max 2–3 iteracje, potem eskalacja do człowieka — pętla bez limitu potrafi kręcić się w kółko, generując coraz dziwniejsze obejścia).
- **Auto-fix tylko dla klas bezpiecznych:** formatowanie, importy, proste ostrzeżenia lintera. Nigdy dla znalezisk bezpieczeństwa ani logiki — tam poprawka bez zrozumienia bywa gorsza od błędu.
- Powtarzające się znaleziska → reguła w `CLAUDE.md`/`AGENTS.md` repozytorium lub nowa reguła Semgrep. Każdy defekt, który przeszedł, powinien zostawić po sobie regułę; inaczej ten sam błąd wraca co tydzień.

---

## 6. Metryki: skąd wiadomo, że brama działa

System oceniający też wymaga oceny — inaczej po kwartale nikt nie wie, czy pomaga.

| Metryka | Definicja | Cel |
|---|---|---|
| **Escape rate** | defekty znalezione po merge / wszystkie defekty | trend malejący |
| **Precyzja bramki** | ile z BLOCK to prawdziwe problemy | > 80% |
| **Fałszywe alarmy G4** | zgłoszenia odrzucone przez człowieka | < 20% |
| **Czas przejścia** | mediana od PR do decyzji | < 20 min |
| **Redukcja pracy człowieka** | % PR-ów bez ręcznego review | rosnący, ale nie kosztem escape rate |
| **Change failure rate** | wdrożenia wymagające rollbacku | ≤ poziom sprzed wdrożenia systemu |
| **Defekty per model** | escape rate w podziale na model/agenta | dane do wyboru narzędzi |

**Kalibracja startowa:** zestaw 30–50 historycznych PR-ów z *znanym* wynikiem (część z realnymi defektami, które trafiły na produkcję). Puszczamy je przez bramę i mierzymy, ile złapie. Bez tego progi w `policy/gates.yaml` są zgadywaniem. Warto dodać kilka **celowo zepsutych PR-ów** jako stały test regresyjny samej bramy — sprawdzany co tydzień.

---

## 7. Roadmapa

**Faza 0 — pomiar (1–2 tyg.)**
Zbierz dane: ile PR-ów pochodzi od agentów, jakie defekty przeszły na produkcję w ostatnim kwartale, gdzie dokładnie zawiódł obecny proces. Zbuduj zestaw kalibracyjny. *Bez tego kroku dobierzesz bramki do wyobrażonych problemów, nie do własnych.*

**Faza 1 — fundament deterministyczny (2–3 tyg.)**
G0 + G1 + G3 na istniejącym CI. Same sprawdzone narzędzia, zero LLM. Tryb `warn-only` przez pierwszy tydzień — zbieramy statystyki, potem włączamy blokowanie. Ta faza daje ~60% wartości przy ~20% kosztu.

**Faza 2 — dowód behawioralny (3–4 tyg.)**
G2: diff coverage, testy mutacyjne na diffie, weryfikacja krzyżowa testów, detekcja flaky, testy kontraktowe. Najtrudniejsza technicznie i najbardziej wartościowa faza — tu wykrywa się „zielone, ale bezwartościowe" testy.

**Faza 3 — warstwa semantyczna (3–4 tyg.)**
G4: panel recenzentów + weryfikacja adwersaryjna. Start jako komentarz w PR **bez prawa blokowania**. Prawo blokowania włączamy dopiero, gdy precyzja przekroczy 80% na zestawie kalibracyjnym.

**Faza 4 — gotowość wdrożeniowa i pętla zwrotna (2–3 tyg.)**
G6, polityka jako kod, auto-fix bezpiecznych klas, raportowanie metryk, cotygodniowy test regresyjny bramy.

Razem: ~3 miesiące do pełnego systemu, pierwsza realna wartość po ~3 tygodniach.

---

## 8. Stack — konkretne narzędzia

| Warstwa | Python | JS/TS | C# | Uniwersalne |
|---|---|---|---|---|
| Lint/format | ruff, black | eslint, prettier | `dotnet format` | pre-commit |
| Typy | mypy --strict, pyright | tsc --strict | `dotnet build` (kompilator *jest* kontrolą typów) | — |
| Testy | pytest, hypothesis | vitest/jest, fast-check | `dotnet test` (xUnit/NUnit/MSTest) | — |
| Pokrycie diff | coverage.py + diff-cover | c8 + diff-cover | coverlet + diff-cover | — |
| Mutacje | mutmut, cosmic-ray | Stryker | Stryker.NET | PIT (JVM) |
| SAST | bandit, semgrep | semgrep | semgrep | CodeQL |
| SCA | pip-audit | npm audit | `dotnet list package --vulnerable` | Trivy, osv-scanner |
| Sekrety | — | — | — | gitleaks, trufflehog |
| IaC | — | — | — | Checkov, tfsec |
| Licencje | pip-licenses | license-checker | `dotnet-project-licenses` | ScanCode, Syft/SPDX |
| Kontrakty | schemathesis | Pact | Pact.NET | OpenAPI diff, Buf |
| Orkiestracja | — | — | — | GitHub Actions / GitLab CI + własny orchestrator bramek |
| Warstwa LLM | — | — | — | Claude API (panel recenzentów, structured output) |

Zbudowane dziś (kamień 3, G0–G3): Python, TS/JS i C# mają pełny parytet w
weryfikacji zależności (dep-guard: PyPI/npm/NuGet), poprawności statycznej
(ruff+mypy / tsc+eslint / `dotnet build`), regułach „nigdy” (semgrep) i SCA
(pip-audit / npm audit / `dotnet list package --vulnerable`). Testy,
pokrycie, mutacje i kontrakty z tej tabeli to wciąż kamień 4 — patrz
`G2.cross_verify` w README.md.

**Punkt integracji:** GitHub Check Run per bramka (widoczny status i log) + jeden komentarz zbiorczy z decyzją i uzasadnieniem, aktualizowany przy każdym pushu zamiast mnożenia komentarzy.

---

## 9. Ryzyka samego rozwiązania

| Ryzyko | Przeciwdziałanie |
|---|---|
| **Zmęczenie alertami** — zespół zaczyna klikać „override" | Twardy limit zgłoszeń na PR (np. 10, posortowane wagą); weryfikacja adwersaryjna; miesięczny przegląd precyzji i kasowanie reguł o niskiej trafności |
| **Brama jako wąskie gardło** | Budżety czasowe na bramkę, równoległe uruchamianie, ścieżka szybka dla zmian trywialnych (dokumentacja, testy-only) |
| **Fałszywe poczucie bezpieczeństwa** | Jawny komunikat, czego brama *nie* sprawdza; regularny test celowo zepsutymi PR-ami |
| **Agent uczy się obchodzić bramki** (pisze testy pod mutację, nie pod wymaganie) | Testy mutacyjne + weryfikacja krzyżowa + rotacja/rozszerzanie reguł; agent bez dostępu do `policy/` i CI |
| **Koszt LLM przy dużym wolumenie** | G4 tylko po przejściu G1–G3; cache dla niezmienionych plików; tańszy model do triażu, mocny do weryfikacji |
| **Niedeterminizm recenzji** | Structured output, temperatura 0, głosowanie większościowe, wersjonowanie promptów recenzentów jak kodu |

---

## 10. Pierwszy krok

Najmniejszy sensowny wycinek do zbudowania w tydzień, dający natychmiastowy sygnał:

1. Trailer `Generated-By` w commitach agentów + limit rozmiaru diffa.
2. gitleaks + weryfikacja istnienia i wieku nowych zależności.
3. diff coverage ≥ 80% w trybie `warn-only`.
4. Weryfikacja krzyżowa: nowe testy uruchomione przeciw kodowi sprzed zmiany.

Punkt 4 kosztuje kilkadziesiąt linii skryptu w CI i wykrywa najczęstszy defekt kodu z agenta — test, który niczego nie dowodzi.
