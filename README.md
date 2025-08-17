# Losovačka (auditovatelný los) – NIST + drand + Bitcoin

Deterministický, **auditovatelný** los pořadí účastníků.  
Entropie = kombinace tří veřejně ověřitelných zdrojů:

- **NIST Randomness Beacon v2**
- **drand** (League of Entropy)
- **Bitcoin block** ≤ zadanému času (Blockstream Esplora API)

Bez lokálního tajného seedu. **Stejné vstupy ⇒ vždy stejný výsledek.**  
Funguje jako **CLI skript** i jako **Django web** (UI + JSON API). Výstup vždy obsahuje **audit JSON**, **CLI příkaz** a **webový odkaz** pro reprodukci.

---

## Doporučené použití (férový proces)

Zveřejni **předem**:
1) pevný CSV seznam účastníků (bez duplicit, pořadí vstupu např. `1,2,3,4,5` či `Adam,Dana,Karel,Lada,Michal`)  
2) **jednu** z možností:
   - **přesnou UTC minutu** losu (např. `2025-10-17T17:00:00Z` - rok-měsíc-den), _nebo_
   - **fair režim** (bere **předchozí** celou minutu, tedy "aktuální čas") – **ihned publikuj `commit`** z auditu v append-only kanálu, jinak můžeš technicky „zkoušet znovu“.

---

## Co je v repozitáři

```
project/                  # Django projekt (settings/urls/wsgi/asgi)
los/                      # Django app (UI, JSON API, jádro)
  forms.py
  views.py
  urls.py
  los_core.py             # sdílené jádro pro web i CLI (NIST + drand + BTC)
templates/
  los/index.html          # jednoduché UI (spuštění + ověření)
auditable_losovacka.py    # CLI skript (stejná logika jako web)
requirements.txt
README.md
```

- **`los_core.py`** – čisté jádro; počítá výsledek a vrací **plný audit** (žádné `print`/`sys.exit`).  
- **`auditable_losovacka.py`** – CLI wrapper (self-test, fair/when, audit výstup, repro URL).  
- **Django** – `/` (UI) a `/draw/` (JSON API). Ověřování umí audit z **URL** i **vloženého JSONu**. U lokální `/draw` URL se obchází HTTP, aby nehrozil self-request timeout.

---

## Funkčnost

### Losování
Vstup:
- `items` = CSV (např. `Alice,Bob,Carol`), bez duplicit, min. 2 položky.
- **buď** `when` = přesná **UTC minuta** (ISO 8601 - rok-měsíc-den), **nebo** `fair` (bere předchozí minutu).

Výstup:
- Pořadí položek.
- **Audit JSON**: URL zdrojů (NIST/drand/BTC), seed preview, `invocation.cli_verify` (spustitelný příkaz), `invocation.repro_url` (klikací odkaz na `/draw/?…`), u fair navíc `commit`.

### Ověření
- Web UI: vlož `/draw` URL nebo celý audit JSON → interně se los přepočte a porovná **výsledek i zdroje**.  
- CLI/Web: z auditu vezmi `items` a `when`, spusť znovu – výsledek musí sedět.

---

## Instalace

**Základní deployment je pro testovací účely, produkční doporuční jsou níže.**
**Požadavky:** Python 3.9+, `requests>=2.31`, pro web `Django>=4.2`.

### 1) Stažení zdrojů (git clone + checkout)
```bash
git clone git@github.com:djz88/losovacka.git
cd losovacka

# (volitelné) přepnutí na konkrétní verzi/větev
git fetch --all --tags
git checkout <tag-nebo-vetvev>   # např. v1.0.0 nebo main
```

### 2) Virtuální prostředí a instalace závislostí
```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 3) Spuštění webu (Django)
```bash
python manage.py runserver 0.0.0.0:8000
# otevři: http://127.0.0.1:8000/
```

### 4) Rychlý self-test (CLI)
```bash
python auditable_losovacka.py --check --verbose
```

---

## Spuštění – Web (Django)

```bash
python manage.py runserver 0.0.0.0:8000
# otevři http://127.0.0.1:8000/
```

### UI
- `/` – formulář **Spustit losování** (items + when/fair) a **Ověřit audit** (URL nebo JSON).
- Po úspěchu uvidíš **pořadí**, **CLI příkaz**, **web odkaz** a **plný audit**.

### JSON API
- `GET /draw/?items=Karel,Tomas,Lida&when=2025-01-17T17:00:00Z&pretty=1`
- `GET /draw/?items=1,2,3,4,5&fair=1&pretty=1`

Parametry:
- `items` – CSV (povinné)  
- `when` **nebo** `fair=1`  
- `pretty=1` – hezčí JSON (volitelné)

---

## Spuštění – CLI

**Fair (předchozí minuta) + odkaz na web:**
```bash
python auditable_losovacka.py \
  --items Karel,Tomas,Lida,Katka,Milada,Flyn \
  --fair \
  --base-url http://127.0.0.1:8000
```

**Konkrétní minuta (UTC):**
```bash
python auditable_losovacka.py \
  --items Alice,Bob,Věra,Bedřich \
  --when 2025-10-17T17:00:00Z
```

**Self-test konektivity (NIST/drand/BTC):**
```bash
python auditable_losovacka.py --check --verbose
```

**CLI výstup obsahuje:**
- `POŘADÍ ÚČASTNÍKŮ: ...`
- `Pro ověření (CLI): python auditable_losovacka.py --when ... --items ...`
- `Pro ověření ve webu: http(s)://.../draw/?items=...&when=...&pretty=1`
- `--- JSON AUDIT --- {...}`

> Pozn.: `--items` je **CSV** (čárky). `--when` je **UTC** minuta.

---

## Produkční nastavení (netestované)
**Cíl:** bezpečně spustit web veřejně (HTTPS), vypnout debug, nastavit klíče/hosty a omezit ověřování cizích URL.

### 1) Proměnné prostředí (doporučené)
```bash
export DJANGO_DEBUG=0
export DJANGO_SECRET_KEY="$(python - <<'PY'\nimport secrets; print(secrets.token_urlsafe(50))\nPY)"
export DJANGO_ALLOWED_HOSTS="example.com,www.example.com"
export DJANGO_CSRF_TRUSTED="https://example.com,https://www.example.com"
export ALLOW_EXTERNAL_VERIFY_URLS=0        # vypnout stahování auditů z cizích domén (SSRF)
export DJANGO_BEHIND_PROXY=1               # pokud běží za reverse proxy (nginx/traefik)
export DJANGO_HSTS_SECONDS=31536000        # HSTS po zapnutí HTTPS
```

### 2) Příprava aplikace
```bash
python manage.py collectstatic --noinput
python manage.py migrate
```

### 3) Spuštění aplikačního serveru
ASGI (doporučeno):
```bash
uvicorn project.asgi:application --host 0.0.0.0 --port 8000 --workers 2
```
nebo WSGI:
```bash
gunicorn project.wsgi:application --workers 2 --threads 2 --bind 0.0.0.0:8000
```

### 4) Reverse proxy a HTTPS
- Dejte před aplikaci nginx/traefik (TLS/HTTP→HTTPS redirect, `X-Forwarded-Proto`).
- Zapněte HSTS (viz proměnné výše).
- Omezte přístup na `/admin/` (nebo ho vypněte, pokud ho nechcete).

### 5) Bezpečnost ověřování auditů
- **Default** v produkci: `ALLOW_EXTERNAL_VERIFY_URLS=0` (ověření jen z vloženého JSONu nebo lokální `/draw` URL).
- Pokud nutně potřebujete externí URL, zvažte allowlist domén a blokování privátních IP (ochrana proti SSRF).

### 6) Kontrola
```bash
python auditable_losovacka.py --check --verbose
```
- Zkontrolujte také, že `DEBUG=False`, `ALLOWED_HOSTS` a `CSRF_TRUSTED_ORIGINS` odpovídají vaší doméně.

## Princip (stručně, technicky)

- **Seed** = HKDF(SHA-256) z:
  - `nist.outputValue`
  - `drand.randomness`
  - `{"btc_height": H, "btc_hash": HASH}`
- **Salt** = SHA-256 z `{"when": ISO_UTC_MINUTE, "drand_round": ROUND}`  
- **Mix** = Fisher–Yates s 64bit uniformními hodnotami, **odmítací metoda** (bez modulo biasu).  
- **Audit** = kompletní metadata a URL k ověření (NIST/drand/BTC), prefixy hex („seed preview“), CLI i web odkaz.

---

## Fair režim & prevence manipulace

- `--fair` bere **předchozí minutu** (bez čekání).  
- Aby se předešlo „zkoušení vícekrát“, **okamžitě publikuj `commit`** (`commit.id` a `commit.json`) do append-only kanálu (git tag, tweet, …) před zveřejněním výsledku.  
- Striktní varianta: vyhlásit předem `items` + přesný `when` (UTC), pak už jen verifikovat.

---

## Známé limity

- Vyžaduje internet: NIST, drand a Blockstream API musí být dostupné.
- Ověřování lokální `/draw` URL UI řeší **bez HTTP** (vyhne se self-request timeoutu).  
- Čas je vždy **UTC**.

---

## Odkazy (zdroje)

- NIST Randomness Beacon v2 – <https://beacon.nist.gov/beacon/2.0>  
- drand HTTP API – <https://drand.cloudflare.com/info>  
- Blockstream Explorer API (Bitcoin) – <https://blockstream.info/api>

---

## Licence

**GPL-3.0-or-later** (GNU General Public License v3.0 nebo novější).  
SPDX: `GPL-3.0-or-later`

### Kompatibilita závislostí
- `Django` – BSD-3-Clause (kompatibilní s GPL-3.0)  
- `requests` – Apache-2.0 (kompatibilní s GPL-3.0)  

---

## Poděkování / Attribution

Vytvořeno s pomocí **ChatGPT 5**.

```
