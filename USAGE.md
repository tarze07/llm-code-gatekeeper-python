# Jak tego używać

Przewodnik dla kogoś, kto ma przed sobą kod wygenerowany przez agenta i pyta: *no dobrze, i co teraz?*

Dokument opisuje wyłącznie to, co **jest zbudowane** — kamienie 1 i 2 z [TOOLS.md](TOOLS.md). Czego brama jeszcze nie sprawdza: na końcu, w sekcji [Uczciwe zastrzeżenie](#uczciwe-zastrzeżenie).

**Zacznij od:** [Scenariusz A](#scenariusz-a-sprawdzam-ręcznie-u-siebie) (pięć kroków do pierwszego uruchomienia) → [Co dostaniesz](#co-dostaniesz) → [Co robić, gdy brama krzyknie](#co-robić-gdy-brama-krzyknie).

| Rozdział | O czym |
|---|---|
| [Co to jest](#co-to-jest-w-jednym-zdaniu) | jedno zdanie |
| [Scenariusz A](#scenariusz-a-sprawdzam-ręcznie-u-siebie) | uruchomienie u siebie, krok po kroku |
| [Co dostaniesz](#co-dostaniesz) | jak czytać raport i kody wyjścia |
| [Gdy brama krzyknie](#co-robić-gdy-brama-krzyknie) | pętla naprawcza z agentem, fałszywe alarmy |
| [Co sprawdza każda bramka](#co-dokładnie-sprawdza-każda-bramka) | G0, G1, G3 — zakres i typowe alarmy |
| [Cross-verify](#najważniejsza-bramka-czy-te-testy-w-ogóle-czegoś-dowodzą) | bramka o największej wartości, z markerami |
| [Scenariusz B](#scenariusz-b-niech-się-dzieje-samo-przy-każdym-pr) | automat w GitHubie |
| [Konfiguracja](#co-możesz-ustawić-pod-siebie) | `policy/gates.yaml` i czego (jeszcze) nie da się ustawić |
| [Metryki](#czy-brama-w-ogóle-pomaga) | czy brama pomaga, i skąd to wiadomo |
| [Praca z agentem](#współpraca-z-agentem) | gotowy prompt i wpis do `AGENTS.md` |
| [Rytm pracy](#rytm-pracy-co-robić-i-jak-często) | co robić codziennie, co raz w miesiącu |
| [Ściąga komend](#ściąga-komend) | wszystko w jednym bloku |
| [Bezpieczeństwo](#bezpieczeństwo-i-prywatność) | co brama uruchamia i co wysyła na zewnątrz |
| [Słownik](#słownik) | fakt, znalezisko, powód, fingerprint |
| [Gdy coś nie działa](#kiedy-coś-nie-działa) | komunikaty błędów |
| [FAQ](#faq) | pytania, które padają najczęściej |

---

## Co to jest, w jednym zdaniu

To jest **bramkarz przy wejściu**. Agent wygenerował kod → zanim zmiana trafi na produkcję, bramkarz zadaje jej kilka pytań i wydaje jedną z trzech odpowiedzi: wpuszczam / wpuszczam, ale niech ktoś zerknie / nie wpuszczam.

---

## Scenariusz A: sprawdzam ręcznie, u siebie

### Krok 1 — zainstaluj bramkarza (raz)

```bash
pip install -e /ścieżka/do/llm-code-gatekeeper
gatekeeper --help
```

Alternatywa bez instalowania: używaj binarki z venva projektu bramy —
`/ścieżka/do/llm-code-gatekeeper/.venv/bin/gatekeeper`.

### Krok 2 — zainstaluj narzędzia, na których stoją bramki (raz)

Brama nie ma własnych skanerów — korzysta ze sprawdzonych narzędzi i woła je jako podprocesy.

```bash
pip install -e "/ścieżka/do/llm-code-gatekeeper[gates]"   # ruff, mypy, semgrep, pip-audit
```

Gitleaks to binarka Go, nie pakiet pip — instaluje się osobno:

```bash
curl -sSL -o /tmp/gl.tar.gz \
  https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz
sudo tar -xzf /tmp/gl.tar.gz -C /usr/local/bin gitleaks
gitleaks version
```

Projekt w TS/JS albo C# potrzebuje własnych narzędzi — to narzędzia **ocenianego
projektu**, nie samej bramy, więc nie ma ich w `[gates]`:

```bash
# TS/JS: najlepiej jako devDependency projektu (bramka woła najpierw
# node_modules/.bin/tsc|eslint, dopiero potem szuka globalnej binarki)
cd ~/moj-projekt && npm i -D typescript eslint

# C#: .NET SDK w PATH; bramka zakłada, że `dotnet restore` już się odbył
# (sama nie ściąga pakietów — to jedyne miejsce w G1 z dostępem do sieci,
# którego świadomie nie chcemy)
dotnet --version
```

**Brakującego narzędzia brama nie udaje, że nie ma.** Bramka, której narzędzia zabrakło, zgłosi `error`, a decyzja poleci do `PASS-WITH-REVIEW` z jawnym powodem — brak dowodu to nie jest to samo co dowód braku problemu. Wyjątek: `G1.static`/mypy, tsc, eslint i `dotnet build` są domyślnie opcjonalne (`require_mypy`/`require_tsc`/`require_eslint`/`require_dotnet_build: false` w `gates.yaml`) — wiele repo nie ma ich skonfigurowanych i to nie jest defekt; brama wtedy po prostu pomija ten język bez wołania narzędzia (`tsconfig.json`/config eslinta/`.csproj` musi w ogóle istnieć, inaczej i tak nie ma czego sprawdzać).

Nie musisz mieć wszystkiego naraz — `gatekeeper run --gate G1.deps` uruchamia tylko wskazane bramki.

### Krok 3 — upewnij się, że testy Twojego projektu dają się uruchomić

Bramka `G2.cross_verify` naprawdę uruchamia testy z PR-a, więc potrzebuje `pytest` i zależności Twojego projektu w tym samym środowisku:

```bash
cd ~/moj-projekt
pytest --collect-only -q     # musi działać, zanim brama spróbuje tego samego
```

### Krok 4 — wklej politykę do **swojego** projektu (raz na projekt)

```bash
cd ~/moj-projekt
mkdir -p policy
cp /ścieżka/do/llm-code-gatekeeper/policy/gates.yaml      policy/
cp /ścieżka/do/llm-code-gatekeeper/policy/exceptions.yaml policy/
```

To nie jest formalność techniczna. Polityka — czyli to, co blokuje i jakie są limity — ma leżeć w ocenianym repozytorium, być wersjonowana razem z kodem i chroniona przez CODEOWNERS. Chodzi o to, żeby **agent nie mógł sobie poprawić kryteriów, według których jest oceniany**. To granica bezpieczeństwa całego systemu (PLAN.md §4).

### Krok 5 — puść bramkarza na zmianę agenta

Agent skończył pracę na gałęzi. Stoisz na tej gałęzi:

```bash
cd ~/moj-projekt
gatekeeper run --base main
```

To wszystko. `--base main` znaczy: *porównaj z tym, co jest na `main`*.

Brama sama znajdzie punkt rozejścia gałęzi (merge-base), więc cudze commity, które w międzyczasie doszły na `main`, nie zostaną policzone jako Twoja zmiana.

---

## Co dostaniesz

Przykład z prawdziwego uruchomienia — agent dopisał funkcję rabatów, wymyślił pakiet `discount-calculator-pro` i napisał test, który niczego nie sprawdza:

```
🚫 BLOCK — brama jakości
`8d436e8` → `1574623` · 4 bramki · 0.6s · polityka v1 · przebieg `103ae14b122a`

### Dlaczego
| 🚫 | deps.unknown_package        | deps.unknown_package = True        |
| 👀 | deps.new_external_package   | deps.new_external_package = True   |

### Znaleziska (2 z 2)
🔴 Pakiet `discount-calculator-pro` nie istnieje w rejestrze pypi
   pyproject.toml · deps.unknown_package · G1.deps · `9f1c02aa5b7d3e88`

   Instalacja zależności na dowolnym środowisku przerwie się błędem
   „No matching distribution found for discount-calculator-pro”. Jeżeli ktoś
   opublikuje pakiet o tej nazwie wcześniej niż my zauważymy, zainstalujemy
   jego kod z uprawnieniami naszego procesu budowania.

🟠 Test `test_cena_dziala` przechodzi na kodzie sprzed zmiany
   tests/test_calc.py:4 · tests.pass_on_pre_change_code · G2.cross_verify · `146ae7e603ba6a41`

### Bramki
| G0.scope        | ✅ pass                | 8 linii w 2 plikach                           |
| G1.deps         | ❌ fail                | sprawdzono 1 nowych pakietów                  |
| G2.cross_verify | ❌ fail  (warn-only)   | 0 testów dowodzi zmiany, 1 przechodzi na starym kodzie |
| G3.secrets      | ✅ pass                | 0 sekretów w zmienionych plikach, 0 zastanych |
```

Trzy rzeczy warto zauważyć w tym raporcie:

- **Każde znalezisko ma konkretny scenariusz awarii** — co się realnie stanie. To wymóg wpisany w kod: obiektu znaleziska bez scenariusza nie da się utworzyć. Dzięki temu raport nie zapełnia się uwagami stylistycznymi udającymi błędy.
- **Ciąg na końcu wiersza to fingerprint** (`146ae7e603ba6a41`) — argument do `gatekeeper verdict`. Liczy się z treści, nie z numeru linii, więc przeżywa rebase.
- **`przebieg` w nagłówku** to argument do `gatekeeper incident`.

### Trzy możliwe odpowiedzi

| Wynik | Znaczy | Kod wyjścia |
|---|---|---|
| ✅ **PASS** | nic podejrzanego, jedź | `0` |
| 👀 **PASS-WITH-REVIEW** | nie blokuję, ale niech człowiek zerknie — i mówię dokładnie gdzie oraz dlaczego | `0` |
| 🚫 **BLOCK** | nie wpuszczam, oto powód | `1` |

Kody wyjścia są po to, żeby dało się to wpiąć w skrypt:

```bash
gatekeeper run --base main && ./deploy.sh
```

Jeżeli chcesz, żeby również `PASS-WITH-REVIEW` zatrzymywało skrypt: `--fail-on review` (wtedy kod wyjścia `2`).

---

## Co robić, gdy brama krzyknie

Nie poprawiaj tego ręcznie. **Wklej raport z powrotem agentowi** jako zadanie naprawcze:

> Brama zablokowała zmianę: pakiet `discount-calculator-pro` nie istnieje w PyPI.
> Użyj istniejącej biblioteki albo zaimplementuj to bez nowej zależności.

I puść ponownie. Reguła z planu: **maksymalnie 2–3 takie rundy**, potem sprawa idzie do człowieka — pętla bez limitu potrafi kręcić się w kółko, produkując coraz dziwniejsze obejścia.

Jeżeli znalezisko jest fałszywym alarmem, **nie wyłączaj reguły**. Zrób dwie rzeczy:

```bash
# 1. powiedz bramie, że się pomyliła — inaczej nikt nie policzy jej precyzji
gatekeeper verdict 9f1c02aa5b7d3e88 --false-positive --note "to nasz prywatny rejestr"
```

```yaml
# 2. policy/exceptions.yaml — wyjątek z właścicielem i datą wygaśnięcia
exceptions:
  - rule: deps.too_young
    owner: "@twoj-zespol"
    reason: "klient naszego wewnętrznego API, wydany 2 tygodnie temu"
    expires: 2026-09-10
```

Wyjątek wygasa sam. Po dacie ważności `gatekeeper policy lint` zgłasza błąd i trzeba świadomie zdecydować, czy przedłużyć — bez tego po pół roku polityka jest zbiorem wyjątków.

---

## Co dokładnie sprawdza każda bramka

### `G0.scope` — rozmiar i higiena zmiany

Nie szuka błędów. Odpowiada na pytanie, czy tę zmianę **da się w ogóle zrecenzować**. To najskuteczniejsza pojedyncza reguła w całym systemie: duży diff od agenta jest nierecenzowalny, a przez to niebezpieczny — recenzent przeoczy defekt w partii kodu, której nie przeczyta.

Liczy **linie efektywne**, czyli z pominięciem plików generowanych maszynowo: lockfile'i, snapshotów, migracji, `*_pb2.py`, `vendor/`, plików zminifikowanych. Bez tego pierwszy PR odświeżający `poetry.lock` przekraczałby próg i zespół wyłączyłby bramkę w tydzień.

| Fakt | Co znaczy |
|---|---|
| `diff.effective_lines` | linie do przeczytania przez człowieka (domyślny limit: 400) |
| `diff.effective_files` | pliki do przeczytania (domyślny limit: 15) |
| `diff.total_lines` | wszystko, razem z generowanym |
| `diff.docs_only` | zmiana wyłącznie dokumentacyjna → ścieżka szybka |

Gdy bramka zablokuje: **rozbij PR**, nie podnoś progu. Podniesienie limitu jest decyzją, którą warto podjąć raz, świadomie, a nie pod presją jednego PR-a.

Druga część tej bramki, `scope_map` — mapowanie `prefiks ticketu → dozwolone ścieżki` w `policy/scope_map.yaml` (np. `AUTH-123` → `**/auth/**`). Ticket bez wpisu w mapie nic nie zmienia — to tylko informacyjna flaga (`diff.out_of_scope_files`), dopóki mapa nie pokrywa całego repo, egzekwowanie zakresu byłoby zgadywanką.

### `G0.provenance` — kto to napisał

Nie blokuje niczego domyślnie. Czyta trailery commitów (`Generated-By: claude/sonnet-5`, `Session-Id: …`) i buduje dane pod pytanie „które narzędzie generuje nam najwięcej defektów" — bez tego to kwestia przeczuć, a to ona decyduje o wyborze narzędzi w zespole.

Żeby to działało, agent musi zostawiać trailer w commicie. Wklej do `AGENTS.md`/`CLAUDE.md` projektu:

```
Każdy commit kończ trailerem: `Generated-By: <narzędzie>/<model>`.
```

Brak trailera nie jest błędem — repozytorium, które dopiero zaczyna, nie ma ich nigdzie. Fakt `provenance.unknown_origin` jest dostępny w polityce, gdy zespół zdecyduje się go egzekwować.

### `G1.deps` — nowe zależności

Klasa defektu, której nie łapie żaden standardowy skaner, bo wszystkie zakładają, że pakiet wpisany do manifestu istnieje. Agent potrafi wymyślić nazwę biblioteki, a lockfile powstaje razem z kodem — więc CI instaluje dokładnie to, co agent zmyślił.

Czyta `pyproject.toml` (PEP 621, PEP 735, Poetry), `requirements*.txt` i `package.json`, porównuje wersję z gałęzi bazowej z wersją z PR-a i sprawdza **wyłącznie nowe** pakiety.

| Znalezisko | Kiedy | Waga |
|---|---|---|
| `deps.unknown_package` | pakietu nie ma w rejestrze | 🔴 blokuje |
| `deps.typosquat_suspect` | nazwa myląco podobna do popularnej, a pakiet młodszy niż rok | 🔴 blokuje |
| `deps.similar_name` | podobna nazwa, ale pakiet ustabilizowany — to raczej zbieg okoliczności | 🔵 informacja |
| `deps.too_young` | pakiet młodszy niż 90 dni | 🟠 do człowieka |
| `deps.no_source_repo` | brak repozytorium źródłowego | 🟡 informacja |

Podobieństwo nazw liczy się po zwinięciu homoglifów (`rn`→`m`, `1`→`l`, cyrylickie znaki), a dopuszczalny dystans zależy od długości nazwy — przy krótkich nazwach dystans 2 oznaczałby „prawie wszystko".

Pakiety z Waszego prywatnego rejestru wpisz raz w politykę jako `internal_prefixes`, zamiast dopisywać wyjątek przy każdym PR-ze.

### `G1.static` — ruff + mypy na zmienionych liniach

Typy w trybie strict wyłapują dużą część halucynacji API agenta: wywołanie metody, której nie ma, albo argumentu o innej nazwie. Tania bramka o wysokiej trafności.

Jedyna nietrywialna decyzja: raportuje **tylko znaleziska w zmienionych liniach** (+3 linie kontekstu). Bez tego pierwszy przebieg na starszym repo dawałby tysiące błędów mypy i projekt umierałby w dniu wdrożenia — dług istniejącego kodu to osobny temat, nie blokada tego PR-a.

| Fakt | Co znaczy |
|---|---|
| `static.high_severity_count` | realne defekty (rodziny ruffa F/B/S/ASYNC/PL, błędy mypy) — nie styl |
| `static.mypy_available` | `false`, gdy mypy nie jest skonfigurowany w repo — to nie jest błąd |

Reguły stylistyczne ruffa (import order, formatowanie) raportują się jako `low` — zgłoszenie stylistyczne udające błąd to najprostszy sposób na to, żeby zespół przestał czytać raporty.

### `G3.sast` — reguły „nigdy" (semgrep)

Zestaw reguł w `rules/semgrep/never.yaml`: wzorce, które **nie mają poprawnego zastosowania w tym repo** — wyłączona weryfikacja TLS, `eval`/`exec` na wejściu, SQL przez sklejanie stringów, `subprocess(shell=True)` z interpolacją, `pickle`/`yaml.load` niebezpieczne, nasłuch na `0.0.0.0`, polityka IAM z wildcardem. Trafienie oznacza błąd albo świadome obejście zabezpieczenia „żeby przeszło" — a to drugie w kodzie od agenta zdarza się częściej, niż się wydaje.

Każda reguła ma test pozytywny **i negatywny** (`semgrep --test`). Reguła bez testu negatywnego prędzej czy później zaczyna blokować poprawny kod i podkopuje zaufanie do całej bramy — dlatego to obowiązkowe, nie zalecane.

Podobnie jak `G1.static`, filtruje do zmienionych linii.

### `G3.sca` — podatności w nowych zależnościach (pip-audit)

Blokuje wyłącznie na podatnościach w pakietach, które ten PR **wprowadza** — dług w już zastanych zależnościach to osobny raport tygodniowy. Zakres na razie: tylko PyPI.

Jedyna bramka, która **musi** dostać sieć (pyta o znane podatności w PyPI/OSV) — jawnie przez `network=True`, nie domyślnie. Audytuje każdy nowy pakiet osobno: jeden nieistniejący/halucynowany pakiet w tym samym PR-ze (który i tak łapie `G1.deps`) nie ma prawa zgasić dowodu dla pozostałych.

### `G3.secrets` — sekrety w kodzie

Uruchamia gitleaks na całym drzewie i **dzieli znaleziska na dwie kategorie**:

| Kategoria | Waga | Dlaczego tak |
|---|---|---|
| `secrets.found_in_diff` — sekret w plikach z tego PR-a | 🔴 blokuje | od merge'a jest w historii każdego klona; rotacja klucza to jedyny skuteczny środek, samo usunięcie linii nie wystarczy |
| `secrets.preexisting` — sekret zastany w repo | 🟡 dług | nie jest winą tego PR-a; blokowanie wszystkiego przy pierwszym uruchomieniu na starszym repo kończy się wyłączeniem bramki |

Skanowane są **także pliki testowe i fixture'y** — to typowe miejsce wycieków w kodzie od agentów, a wiele konfiguracji skanerów je wyłącza.

**Sekret nigdy nie trafia do raportu w jawnej postaci** (`ghp_…(40 znaków)`). Komentarz w PR widzi więcej osób niż plik, z którego sekret pochodzi.

---

## Najważniejsza bramka: czy te testy w ogóle czegoś dowodzą

`G2.cross_verify` robi jedną rzecz, a wyłapuje najczęstszy defekt kodu z agenta:

> **bierze nowe testy z Twojej zmiany i uruchamia je przeciw kodowi sprzed zmiany.**

Test nowej funkcjonalności *musi* wtedy polec. Jeżeli przechodzi — nie testuje tego, co deklaruje. Zielony, bezużyteczny.

Bramka bierze pod uwagę wyłącznie testy **nowe albo zmienione** — porównanie idzie po strukturze kodu, więc przeformatowanie testu albo dopisanie komentarza nie czyni z niego nowego testu.

### Trzy sytuacje, w których test *ma prawo* przejść na starym kodzie

Czysty refaktor, dopisanie testów do istniejącego kodu, test regresyjny do buga naprawionego wcześniej. Deklarujesz je markerem:

```python
@pytest.mark.characterization   # albo test_backfill / refactor_only
def test_cena_bazowa():
    assert cena(100) == 123.0
```

Bramka wtedy nie blokuje, ale **liczy te deklaracje i pokazuje je w metrykach**. Nadużywanie markera jest widoczne w liczbach, zamiast po cichu wydrążać bramkę od środka.

### Kiedy bramka pomija się sama

| Sytuacja | Dlaczego |
|---|---|
| zmiana nie dotyka kodu produkcyjnego (sam dodany test) | stary i nowy kod są identyczne — nie ma czego dowodzić, a blokowanie oznaczałoby blokowanie każdego PR-a dokładającego testy |
| zmiana kodu bez nowych testów | nie ma czego uruchomić; brak testów to problem, ale innej bramki (pokrycie różnicowe — kamień 4) |
| zmiana wyłącznie dokumentacyjna | ścieżka szybka |

### Trzy wyniki, które zobaczysz

| Wynik testu na starym kodzie | Interpretacja |
|---|---|
| **polegał na asercji** | dowód mocny — test odróżnia kod przed od kodu po |
| **błąd importu** (nowy moduł jeszcze nie istniał) | dowód słaby — liczony osobno, nie blokuje |
| **przeszedł** | nie dowodzi niczego → znalezisko |

### Ograniczenie, o którym trzeba wiedzieć

Jeżeli Twój pakiet jest zainstalowany przez `pip install -e .`, import sięgnie po kod z katalogu roboczego zamiast z kopii kodu bazowego — i bramka porównywałaby nowy kod z nowym. Wykrywa to i zgłasza `error`, zamiast produkować bezwartościowy zielony wynik.

Bramka wchodzi domyślnie w trybie `warn_only`: przez pierwszy tydzień ostrzega, nie blokuje. Po przeglądzie fałszywych alarmów usuń ją z `warn_only` w `policy/gates.yaml`.

---

## Scenariusz B: niech się dzieje samo, przy każdym PR

Skopiuj do swojego repozytorium dwa pliki:

```bash
cp /ścieżka/do/llm-code-gatekeeper/.github/workflows/gatekeeper.yml ~/moj-projekt/.github/workflows/
cp /ścieżka/do/llm-code-gatekeeper/scripts/post_pr_comment.sh      ~/moj-projekt/scripts/
chmod +x ~/moj-projekt/scripts/post_pr_comment.sh
```

Od tej pory przy każdym PR-ze GitHub sam uruchomi bramę i doda **jeden komentarz z decyzją**, aktualizowany przy każdym pushu zamiast mnożenia komentarzy. Pełny raport ląduje jako artefakt przebiegu.

Trzy rzeczy do ustawienia:

1. **Zależności testowe projektu** — w workflow jest krok `pip install -e ".[dev]"`. Dostosuj go do swojego projektu, inaczej `G2.cross_verify` zgłosi błąd (co jest zamierzone: brak środowiska to brak dowodu, nie zielona bramka).
2. **Ochrona gałęzi** — „Require review from Code Owners", inaczej plik `CODEOWNERS` niczego nie egzekwuje i agent może zmienić `policy/`.
3. **PR-y z forków** — workflow działa na zdarzeniu `pull_request`, które nie daje uprawnień do komentowania PR-om z forków. Dla repozytorium publicznego trzeba rozdzielić przebieg na `pull_request` (liczenie) i `workflow_run` (komentowanie).

---

## Co możesz ustawić pod siebie

Wszystko siedzi w `policy/gates.yaml`:

```yaml
blocking:                          # dowolne trafienie => BLOCK
  - secrets.found_in_diff
  - deps.unknown_package
  - deps.typosquat_suspect
  - tests.pass_on_pre_change_code

thresholds:
  diff.effective_lines:
    max: 400                       # większy diff = BLOCK (lockfile'i się nie liczą)

human_review_required_when:
  - paths_match: ["**/auth/**", "**/payments/**"]

warn_only:
  - G2.cross_verify                # zdejmij po tygodniu obserwacji
  - G1.static
  - G3.sast
  - G3.sca

gates:
  G1.deps:
    min_age_days: 90
    internal_prefixes: ["acme-"]   # Wasze pakiety z prywatnego rejestru
  G1.static:
    require_ruff: true             # brak ruffa = błąd bramki
    require_mypy: false            # wiele repo nie ma mypy skonfigurowanego
  G2.cross_verify:
    python_path: ["src"]           # układ src/ — katalogi dokładane do PYTHONPATH
    timeout_s: 600
  G3.sca:
    require_tool: true             # `false` → `skipped` w CI bez dostępu do sieci
  G3.secrets:
    require_tool: true
```

Zakres ticketu (opcjonalnie) w `policy/scope_map.yaml`:

```yaml
components:
  AUTH:
    - "**/auth/**"      # ticket AUTH-123 dotykający czegoś spoza tej listy → flaga
```

Przydatne komendy:

```bash
gatekeeper policy lint     # literówki, złe progi, wygasłe wyjątki
gatekeeper policy facts    # lista rzeczy, o które wolno pytać w polityce
```

`policy lint` odrzuca politykę odwołującą się do nieistniejącego faktu. Literówka typu `secrets.found_in_dif` dawałaby regułę, która nigdy nie zadziała — a to gorsze niż brak reguły, bo daje złudzenie ochrony.

**Nową bramkę zawsze wprowadzaj przez `warn_only` na tydzień.** Zbierasz statystyki, sprawdzasz ile fałszywych alarmów, dopiero potem włączasz blokowanie.

### Czego (jeszcze) nie da się ustawić w polityce

Żeby nie szukać po dokumentacji opcji, których nie ma:

| Rzecz | Stan |
|---|---|
| lista wzorców plików generowanych (lockfile'i, snapshoty) | zaszyta w kodzie (`core/change.py`) — konfiguracja w polityce dochodzi w kamieniu 3 |
| mapowanie ticket → dozwolone ścieżki (`scope_map`) | kamień 3 |
| własne reguły semgrep | kamień 3 |
| progi per katalog (inny limit dla `infra/` niż dla `docs/`) | niezaplanowane — na razie jeden próg na repo |

---

## Czy brama w ogóle pomaga

System oceniający też wymaga oceny — inaczej po kwartale nikt nie wie, czy pomaga. Każdy przebieg zapisuje się do `.gatekeeper/runs.db` w Twoim repo (wyłączenie: `--no-store`, inna ścieżka: `--store`).

Gdy znalezisko okaże się trafne albo błędne, powiedz to bramie — fingerprint bierzesz wprost z raportu:

```bash
gatekeeper verdict 146ae7e603ba6a41 --true-positive  --author ty
gatekeeper verdict 9f1c02aa5b7d3e88 --false-positive --note "to nasz wewnętrzny pakiet"
```

Gdy przepuszczona zmiana wywoła incydent na produkcji (identyfikator przebiegu też jest w nagłówku raportu):

```bash
gatekeeper incident 103ae14b122a --note "rollback po 20 minutach"
```

I raz na jakiś czas:

```bash
gatekeeper metrics --days 30
```

```
Metryki bramy — ostatnie 30 dni, 1 przebiegów

  Zablokowane: 0%
  Bez ręcznego review: 0% (cel: rosnący, ale nie kosztem escape rate)
  Skierowane do człowieka: 100%
  Mediana czasu przejścia: 0.2s (cel: < 1200s)
  Precyzja bramki: 100% (cel: > 80%)
  Escape rate: brak danych (żaden przebieg nie jest oznaczony jako incydent)
  Testy zwolnione z cross-verify: 0

  Reguły wg liczby znalezisk:
    tests.pass_on_pre_change_code    1 znalezisk, ocenionych 1, precyzja 100%
```

Dwie rzeczy, które ten raport robi celowo:

- **Metryka bez danych mówi „brak danych", a nie „0%".** To dwie różne rzeczy i mylenie ich jest najprostszym sposobem na fałszywy wniosek („escape rate zero, super!" kontra „nikt nie oznaczył ani jednego incydentu").
- **Tabela reguł służy do kasowania reguł o niskiej trafności.** Reguła, która myli się w połowie przypadków, uczy zespół klikać „override" na wszystkim — i tym samym unieważnia także te reguły, które działają.

---

## Współpraca z agentem

### Raport jako zadanie naprawcze

Blok do wklejenia agentowi, gdy brama zablokuje zmianę:

```
Brama jakości zablokowała tę zmianę. Napraw dokładnie to, co poniżej,
i nie zmieniaj przy okazji niczego innego.

<wklej sekcję „Dlaczego" i „Znaleziska" z raportu>

Zasady:
- nie modyfikuj katalogu policy/ ani konfiguracji CI — to nie jest część zadania,
- nie obchodź reguły przez oznaczenie testu markerem, chyba że to naprawdę
  refaktor albo test charakteryzujący istniejące zachowanie,
- jeżeli uważasz, że znalezisko jest błędne, napisz dlaczego — nie zmieniaj kodu.
```

Ostatni punkt jest ważniejszy, niż wygląda. Agent postawiony przed regułą, której nie rozumie, chętnie „naprawi" ją tak, żeby reguła przestała trafiać — a nie tak, żeby problem zniknął.

### Wpis do `AGENTS.md` / `CLAUDE.md` Twojego projektu

Żeby agent znał kryteria **zanim** zacznie pisać, a nie dopiero z raportu:

```markdown
## Kryteria akceptacji zmian (egzekwowane automatycznie)

- Zmiana mieści się w 400 liniach i 15 plikach. Większe zadanie rozbij na kilka PR-ów.
- Każdy nowy pakiet musi istnieć w oficjalnym rejestrze, mieć co najmniej 90 dni
  i uzasadnienie w opisie PR. Nie wymyślaj nazw bibliotek — sprawdź, że istnieją.
- Nowy test musi polec na kodzie sprzed zmiany. Test, który przechodzi zarówno
  przed, jak i po, niczego nie dowodzi i zostanie odrzucony.
  Wyjątek: refaktor i testy dopisywane do istniejącego kodu — oznacz je
  `@pytest.mark.characterization`.
- Żadnych sekretów w kodzie ani w fixture'ach — także tych „testowych".
- Nie modyfikuj katalogu `policy/` ani `.github/workflows/`.
```

Ostatnia linijka to nie kwestia grzeczności. **Agent nie może mieć uprawnień do zmiany kryteriów, według których jest oceniany** — egzekwuj to przez CODEOWNERS i ochronę gałęzi, bo sam wpis w `AGENTS.md` jest tylko prośbą.

---

## Rytm pracy: co robić i jak często

| Kiedy | Co |
|---|---|
| przy każdym PR | `gatekeeper run` (ręcznie albo z CI) |
| gdy odrzucasz znalezisko | `gatekeeper verdict … --false-positive` — bez tego precyzja jest niepoliczalna |
| po incydencie na produkcji | `gatekeeper incident <run-id>` |
| raz w tygodniu | `gatekeeper metrics --days 30`, `gatekeeper policy lint` (wygasające wyjątki) |
| po tygodniu obserwacji nowej bramki | zdejmij ją z `warn_only` albo popraw progi |
| raz w miesiącu | przegląd reguł o niskiej precyzji; odświeżenie list pakietów: `python scripts/refresh_top_packages.py` |
| przy zmianie w `policy/gates.yaml` albo w regułach | `gatekeeper calibrate` — łapie regresję, zanim złapie ją produkcja |

---

## Zestaw kalibracyjny: czy polityka nadal robi to, co ma robić

`gatekeeper calibrate` uruchamia celowo zepsute (i celowo czyste) PR-y przeciw **realnej polityce tego repo** i porównuje wynik z oczekiwaniem — regresja w regule (literówka w progu, zdjęty `warn_only` bez sprawdzenia, źle zmergowany wyjątek) wychodzi na jaw od razu, nie po pierwszym przepuszczonym PR-ze.

Przypadek to **dane, nie kod Pythona** — para katalogów `calibration/fixtures/<nazwa>/{base,head}/` (stan repo przed i po zmianie) plus wpis w `calibration/cases.yaml`:

```yaml
- name: halucynowany-pakiet
  fixture: halucynowany-pakiet
  expect:
    verdict: BLOCK
    blocking_rules: [deps.unknown_package]
```

Żeby dodać przypadek z prawdziwego PR-a: skopiuj drzewo repo sprzed i po zmianie do `base/`/`head/`, nazwij fixture, dopisz wpis. Żadnego Pythona. To jest też dokładnie ten mechanizm, o którym mówi PLAN.md §6 („Faza 0" — zbierz 30–50 historycznych PR-ów, zanim dobierzesz progi do wyobrażonych problemów).

Przypadek, którego narzędzie nie jest zainstalowane (`requires_tools: [semgrep]`), jest **pomijany**, nie failuje — ta sama zasada co w bramkach: brak narzędzia to brak dowodu, nie powód, żeby czerwienić CI repozytoriom bez semgrepa czy gitleaksa.

---

## Ściąga komend

```bash
gatekeeper run --base main                       # ocena zmiany
gatekeeper run --base main --format json         # pełny raport maszynowy
gatekeeper run --base main --gate G1.deps        # tylko wybrana bramka
gatekeeper run --base main --fail-on review      # także PASS-WITH-REVIEW zatrzymuje skrypt
gatekeeper run --base main --no-store            # bez zapisu do bazy

gatekeeper policy lint                           # walidacja polityki
gatekeeper policy facts                          # fakty dozwolone w polityce
gatekeeper calibrate                             # celowo zepsute/czyste PR-y przeciw polityce

gatekeeper verdict <fingerprint> --false-positive
gatekeeper incident <run-id>
gatekeeper metrics --days 30
```

---

## Bezpieczeństwo i prywatność

Trzy pytania, które padają, gdy ktoś chce wpuścić narzędzie do firmowego repo.

### Czy mój kod gdzieś wyjeżdża?

Prawie nigdzie. Ruch na zewnątrz jest **jawny i policzalny**, nie domyślny:

- **nazwy nowych pakietów** do `pypi.org`/`registry.npmjs.org` przy sprawdzaniu, czy pakiet istnieje (`G1.deps`) — odpowiedzi buforowane w `~/.cache/gatekeeper/registry` na dobę,
- **nazwy i wersje nowo dodanych zależności PyPI** do bazy OSV/PyPI przy sprawdzaniu podatności (`G3.sca`) — jedyna bramka z jawnym dostępem do sieci (`network: true`), pozostałe biegną bez niej.

Kod, diff, testy i sekrety **nie opuszczają Twojej maszyny**. Gitleaks, ruff, mypy, semgrep i cross-verify działają lokalnie, bez sieci — żaden model językowy nie jest wołany (panel LLM, G4, to kamień 5 i dziś nie istnieje).

Chcesz odciąć sieć całkowicie: pomiń `G1.deps` i `G3.sca` (`gatekeeper run --gate G0.scope --gate G3.secrets --gate G3.sast`) albo ustaw `require_tool: false` na `G3.sca`, żeby dostać `skipped` zamiast prób połączenia.

### Brama uruchamia kod z PR-a

`G2.cross_verify` wykonuje testy napisane przez agenta, a `G1.static`/`G3.sast` uruchamiają linter/semgrep na tym kodzie. To jest **wykonanie niezaufanego kodu** — traktuj to tak samo poważnie jak uruchomienie `npm install` z cudzego repozytorium.

Co robi `core/runner.py`, jedyne miejsce w systemie, które uruchamia podprocesy:

- **sieć jest domyślnie odcięta** (`unshare --user --net`) — bez roota i bez kontenera, na Linuksie z przestrzeniami nazw użytkownika. Gdy izolacja jest niedostępna, raport mówi o tym wprost w sekcji „czego brama nie sprawdza", zamiast milcząco udawać, że jest bezpiecznie,
- **zmienne wyglądające na poświadczenia są usuwane** (`*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*_KEY*`…) — w CI oznacza to, że testy/linter z PR-a nie widzą tokena z prawem zapisu do repozytorium,
- **limit pamięci i czasu**, z ubiciem całej grupy procesów po przekroczeniu — nie tylko głównego procesu,
- testy `G2.cross_verify` dodatkowo działają w osobnej kopii kodu (`git worktree`) w katalogu tymczasowym.

Czego **nie** ma jeszcze: pełnego kontenera z systemem plików tylko-do-odczytu (opcjonalne, wymaga dockera/podmana — dziś nie jest włączone domyślnie).

Jeżeli Twoje testy naprawdę potrzebują jakiegoś tokena, dopisz go jawnie:

```yaml
gates:
  G2.cross_verify:
    keep_env: ["TEST_STRIPE_KEY"] # świadoma decyzja, nie przypadek
```

### Co ląduje na dysku

`.gatekeeper/runs.db` w Twoim repozytorium — historia przebiegów, znaleziska i werdykty. **Dopisz `.gatekeeper/` do `.gitignore`**; baza jest lokalna i nie ma powodu, żeby trafiała do repo. Sekrety w niej nie lądują (znaleziska są zredagowane), ale ścieżki plików i tytuły znalezisk już tak.

---

## Słownik

Pojęcia, które wracają w raportach i w polityce.

| Pojęcie | Znaczenie |
|---|---|
| **bramka** | jeden sprawdzian, np. `G1.deps`. Ma budżet czasowy, wystawia fakty i znaleziska |
| **fakt** | liczba albo flaga opisująca zmianę, np. `diff.effective_lines = 812`. Polityka operuje **wyłącznie** na faktach. Pełną listę daje `gatekeeper policy facts` |
| **znalezisko** | konkretny problem w konkretnym miejscu, z wagą i scenariuszem awarii. To czyta człowiek |
| **powód** | wiersz w sekcji „Dlaczego": reguła polityki + fakt, który ją wyzwolił. Decyzja bez powodu jest bezużyteczna, więc nie da się jej utworzyć |
| **fingerprint** | identyfikator znaleziska liczony z treści, nie z numeru linii — przeżywa rebase. Argument do `gatekeeper verdict` |
| **przebieg** (run-id) | jedno uruchomienie bramy. Argument do `gatekeeper incident` |
| **`warn_only`** | bramka liczy i raportuje, ale nie blokuje. Tryb, w którym wchodzi każda nowa bramka |
| **wyjątek** | świadome wyciszenie reguły, zawsze z właścicielem i datą wygaśnięcia (`policy/exceptions.yaml`) |
| **ścieżka szybka** | zmiana wyłącznie dokumentacyjna pomija bramki, które nie mają czego sprawdzać |

---

## Kiedy coś nie działa

| Komunikat | Co znaczy | Co zrobić |
|---|---|---|
| `gitleaks niedostępny` | brak binarki w `PATH` | krok 2 albo `gates: {G3.secrets: {require_tool: false}}` |
| `polityka: [Errno 2] ... policy/gates.yaml` | uruchamiasz spoza katalogu projektu albo brak skopiowanej polityki | krok 4 albo `--policy /pełna/ścieżka/gates.yaml` |
| `rejestr pakietów nieosiągalny` | brak sieci lub limit zapytań PyPI/npm/NuGet | bramka celowo daje `error`, nie „przeszło" — powtórz przebieg |
| `pytest nie jest zainstalowany w tym środowisku` | `G2.cross_verify` nie ma czym uruchomić testów | zainstaluj zależności testowe projektu w tym samym środowisku |
| `moduł X importuje się z …, spoza kopii kodu bazowego` | pakiet zainstalowany przez `pip install -e .` przesłania kod bazowy | uruchom bramę w środowisku bez takiej instalacji albo ustaw `python_path` w polityce |
| `reguła odwołuje się do faktu … którego nie deklaruje żadna bramka` | literówka w `gates.yaml` | `gatekeeper policy facts` i popraw nazwę |
| `wyjątek … wygasł` | minęła data ważności wpisu w `exceptions.yaml` | usuń wpis albo przedłuż świadomie |
| `nie znam znaleziska o fingerprincie …` | fingerprint z przebiegu, który nie trafił do bazy | uruchom bez `--no-store` albo wskaż właściwą bazę przez `--store` |
| `przekroczony budżet czasowy` | bramka działała dłużej niż jej limit | dopisek informacyjny, nie awaria; przy cross-verify zwykle znaczy wolne testy — zawęź `pytest_args` |
| testy w cross-verify padają na brak zmiennej środowiskowej | usunęliśmy ją jako podejrzaną o bycie sekretem | `gates: {G2.cross_verify: {keep_env: ["NAZWA"]}}` |
| decyzja `PASS`, ale zmiana jest zła | brama nie sprawdza jeszcze wszystkiego | patrz niżej |

---

## FAQ

**Czy muszę mieć testy, żeby to uruchomić?**
Nie. Bez testów `G2.cross_verify` po prostu się pomija, a pozostałe trzy bramki działają normalnie. Brak testów wykryje dopiero pokrycie różnicowe (kamień 4).

**Działa dla JavaScriptu, TypeScriptu i C#?**
Tak dla G0–G3, z jednym świadomym wyjątkiem — i warto to wiedzieć zawczasu:

| Bramka | TS/JS | C# |
|---|---|---|
| `G0.scope` | tak — niezależna od języka | tak — niezależna od języka |
| `G1.deps` | tak — czyta `package.json`, pyta rejestr npm | tak — czyta `.csproj`/`Directory.Packages.props`/`packages.config`, pyta rejestr NuGet |
| `G1.static` | tak — `tsc --noEmit` (wymaga `tsconfig.json`) + `eslint` (wymaga configu) | tak — `dotnet build` (kompilator *jest* kontrolą typów w trybie strict) |
| `G3.secrets` | tak — gitleaks jest niezależny od języka | tak — gitleaks jest niezależny od języka |
| `G3.sast` | tak — reguły „nigdy” dla eval/shell-injection/TLS (`rules/semgrep/never.yaml`) | tak — reguły „nigdy” dla TLS/SQLi/shell-injection/deserializacji |
| `G3.sca` | tak — `npm audit` na nowo dodanych zależnościach | tak — `dotnet list package --vulnerable` na nowo dodanych zależnościach |
| `G2.cross_verify` | **nie** — dziś tylko Python/pytest. Adapter dla vitest/jest w planie | **nie** — dziś tylko Python/pytest. Adapter dla `dotnet test` w planie |

`G1.static` pomija język cicho (status `pass`, bez wołania narzędzia), gdy w repo brakuje configu, którego to narzędzie wymaga — `tsconfig.json` dla tsc, `.eslintrc*`/`eslint.config.*` dla eslinta, `.csproj` dla `dotnet build`. To nie jest defekt, tylko brak przedmiotu do sprawdzenia; fakty `static.tsconfig_found`/`static.eslint_config_found`/`static.csproj_found` mówią wprost, co się stało.

**Czy to zastępuje code review?**
Nie i nie ma zastępować. Celem jest przesunięcie uwagi człowieka tam, gdzie jest naprawdę potrzebna, i odsianie klas błędów, które maszyna wyłapie taniej. Werdykt `PASS-WITH-REVIEW` istnieje właśnie po to, żeby powiedzieć: *popatrz tutaj, i to z tego powodu*.

**Ile to trwa?**
G0 i G1 to sekundy (G1 z zimnym cache rejestru: kilka sekund na pakiet). G3 zależy od wielkości repo, zwykle poniżej minuty. G2 to czas uruchomienia **tylko nowych testów**, nie całego zestawu. W małym projekcie cała brama schodzi poniżej sekundy.

**Mogę uruchomić na czymś, co już jest zmerdżowane?**
Tak, `--base` przyjmuje dowolny commit: `gatekeeper run --base abc1234 --head def5678`. Przydaje się do zbudowania zestawu kalibracyjnego z historycznych PR-ów.

**Mam monorepo — jak to ustawić?**
Jedna polityka na repozytorium, uruchamiana z jego korzenia. Progi rozmiaru dotyczą całego diffa, więc w dużym monorepo prawdopodobnie trzeba je podnieść. Progi per katalog to na razie brak (patrz [Czego nie da się ustawić](#czego-jeszcze-nie-da-się-ustawić-w-polityce)).

**Brama zablokowała coś słusznie, ale muszę to wypuścić teraz.**
Dopisz wyjątek do `policy/exceptions.yaml` z krótką datą wygaśnięcia i swoim nazwiskiem. Nie usuwaj reguły — wyjątek wygaśnie sam i wróci do rozmowy, usunięta reguła nie wróci nigdy.

**Skąd wziąć fingerprint i run-id?**
Oba są w raporcie: run-id w nagłówku, fingerprint na końcu wiersza pod tytułem znaleziska. W formacie JSON: pola `run_id` i `fingerprint`.

---

## Uczciwe zastrzeżenie

Dzisiaj bramkarz umie:

- **pilnować rozmiaru i higieny zmiany**, w tym zakresu ticketu (`scope_map`) — duży diff od agenta jest nierecenzowalny,
- **wiedzieć, co wyprodukowało zmianę** (`G0.provenance`) — model, agent, sesja, z trailerów commitów,
- **sprawdzać, czy nowe pakiety naprawdę istnieją**, czy nie podszywają się pod popularne (typosquat/slopsquat) i czy nie mają znanych podatności (`G1.deps` + `G3.sca`),
- **łapać halucynacje API i realne błędy statyczne** (ruff + mypy, `G1.static`) na zmienionych liniach,
- **weryfikować, czy nowe testy czegokolwiek dowodzą** (cross-verify),
- **szukać sekretów** — również w plikach testowych i fixture'ach,
- **blokować wzorce bez poprawnego zastosowania w kodzie** — wyłączony TLS, `eval` na wejściu, SQLi, `shell=True`, niebezpieczna deserializacja (`G3.sast`),
- **uruchamiać to wszystko w izolacji** — bez sieci domyślnie, bez sekretów w środowisku, z limitem czasu i pamięci (`core/runner.py`),
- **łapać własną regresję** przed produkcją — zestaw kalibracyjny (`gatekeeper calibrate`).

Nie sprawdza jeszcze:

- pokrycia różnicowego i testów mutacyjnych (reszta G2 — kamień 4),
- IaC, licencji i podatności poza ekosystemem PyPI (reszta G3 — kamień 3 w toku),
- czy implementacja robi to, co było w zadaniu (G4 — kamień 5),
- gotowości wdrożeniowej: migracji, rollbacku, obserwowalności (G6 — kamień 6).

Brama wypisuje tę listę na końcu **każdego** raportu. Zielony wynik znaczy „nie znalazłem tego, czego szukam", a nie „przejrzane i bezpieczne". Mylenie tych dwóch rzeczy jest głównym ryzykiem takich systemów (PLAN.md §9).
