#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
auditable_losovacka.py (BTC-only)

Deterministický a auditovatelný los pořadí účastníků:
  – NIST Randomness Beacon v2
  – drand (League of Entropy)
  – Bitcoin block ≤ danému času (Blockstream Esplora API)
Bez počasí/MOSMIX. Shodné se serverovou verzí (los_core.py).

Vstupy (publikovat předem):
  1) pevný CSV seznam účastníků (--items), bez duplicit,
  2) přesná UTC minuta (--when) NEBO --fair (předchozí minuta, bez čekání).

Self-test: --check ověří Python/requests a konektivitu (NIST/drand/BTC).
"""

import argparse
import datetime as dt
import hashlib
import hmac
import json
import os
import shlex
import sys
from hashlib import sha256
import time
from typing import Any, Dict, List, Tuple

# ------------------ minimální ověření prostředí ------------------

MIN_PY = (3, 9)
REQ_REQUESTS_VER = "2.31.0"
# Sjednoceni timeoutu při žádosti pro rúzné verze urllib3 či pomalé připojení
HTTP_CONNECT_TIMEOUT = float(os.getenv("LOS_HTTP_CONNECT_TIMEOUT", "5"))
HTTP_READ_TIMEOUT    = float(os.getenv("LOS_HTTP_READ_TIMEOUT", "45"))
HTTP_RETRIES         = int(os.getenv("LOS_HTTP_RETRIES", "3"))
HTTP_BACKOFF         = float(os.getenv("LOS_HTTP_BACKOFF", "0.75"))

def _fail(msg: str, exit_code: int = 2) -> None:
    sys.stderr.write(f"Chyba: {msg}\n")
    sys.stderr.flush()
    sys.exit(exit_code)

def _parse_ver(v: str) -> Tuple[int, ...]:
    parts = []
    for chunk in v.split("."):
        num = ""
        for ch in chunk:
            if ch.isdigit():
                num += ch
            else:
                break
        parts.append(int(num) if num else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])

def _check_python_version() -> None:
    if sys.version_info < MIN_PY:
        _fail(f"Python {MIN_PY[0]}.{MIN_PY[1]}+ je povinný. "
              f"Nyní běží {sys.version.split()[0]}.")

def _check_requests():
    try:
        import requests  # type: ignore
    except Exception:
        _fail("Chybí balík 'requests'. Nainstaluj: pip install 'requests>=2.31'")
    ver = getattr(requests, "__version__", "0.0.0")
    if _parse_ver(ver) < _parse_ver(REQ_REQUESTS_VER):
        _fail(f"'requests' je zastaralý ({ver}). Potřebuji ≥ {REQ_REQUESTS_VER}. "
              "Aktualizuj: pip install -U 'requests>=2.31'")
    return requests  # type: ignore

_check_python_version()
requests = _check_requests()

# ------------------ konstanty a log ------------------

INFO_TAG = b"auditable-draw-v2"

NIST_BASE   = "https://beacon.nist.gov/beacon/2.0"
DRAND_INFO  = "https://drand.cloudflare.com/info"
DRAND_ROUND = "https://drand.cloudflare.com/public/{round}"

BLOCKSTREAM_API = "https://blockstream.info/api"

def log(msg: str, enabled: bool) -> None:
    if not enabled:
        return
    ts = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    sys.stderr.write(f"[{ts}] {msg}\n")
    sys.stderr.flush()

# ------------------ pomocné funkce s lepšími chybami ------------------

def _get_json(url: str, timeout: int = 15):
    r = _http_get(url, timeout=timeout)
    try:
        r.raise_for_status()
    except Exception as e:
        raise RuntimeError(f"HTTP {r.status_code} při GET {url}: {e}") from e
    try:
        return r.json()
    except Exception as e:
        preview = (r.text or "")[:200].replace("\n", " ")
        raise RuntimeError(f"Neplatná JSON odpověď z {url}. Začátek: {preview!r}") from e

def _get_text(url: str, timeout: int = 15) -> str:
    r = _http_get(url, timeout=timeout)
    r.raise_for_status()
    return (r.text or "").strip()

def _http_get(url: str, timeout=None):
    tout = timeout or (HTTP_CONNECT_TIMEOUT, HTTP_READ_TIMEOUT)
    last = None
    for attempt in range(HTTP_RETRIES):
        try:
            return requests.get(url, timeout=tout)
        except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError) as e:
            last = e
            if attempt < HTTP_RETRIES - 1:
                time.sleep(HTTP_BACKOFF * (2 ** attempt))
            else:
                raise

def _canon_json(obj) -> str:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True)

# ------------------ čas a vstupy ------------------

def parse_when(s: str) -> dt.datetime:
    """ISO 8601 → UTC na celou minutu."""
    t = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    if t.tzinfo is None:
        t = t.replace(tzinfo=dt.timezone.utc)
    return t.astimezone(dt.timezone.utc).replace(second=0, microsecond=0)

def prev_full_minute(now_utc: dt.datetime) -> dt.datetime:
    """Předchozí celá minuta (UTC)."""
    return (now_utc.replace(second=0, microsecond=0) - dt.timedelta(minutes=1)).astimezone(dt.timezone.utc)

def parse_items_csv(s: str) -> List[str]:
    """--items jen CSV (čárky), min. 2 položky, bez duplicit."""
    if "," not in s:
        _fail("--items: použij CSV, např. '1,2,3' nebo 'Alice,Bob'")
    parts = [p.strip() for p in s.split(",")]
    if any(p == "" for p in parts) or len(parts) < 2:
        _fail("--items: prázdná nebo příliš krátká sada položek.")
    if len(set(parts)) != len(parts):
        _fail("Duplicitní položky v --items nejsou povoleny.")
    return parts

def build_cli_verify(script: str, when_iso: str, items: List[str]) -> str:
    """Postaví ověřovací příkaz (CSV je jeden shell argument)."""
    items_csv = ",".join(items)
    cmd = ["python", script, "--when", when_iso, "--items", items_csv]
    return " ".join(shlex.quote(c) for c in cmd)

# ------------------ zdroje entropie ------------------

def nist_pulse_at_minute(t_utc: dt.datetime, verbose: bool=False) -> Tuple[Dict[str, Any], str]:
    """NIST Beacon pulse pro danou minutu (příp. previous)."""
    ms = int(t_utc.timestamp() * 1000)
    url = f"{NIST_BASE}/pulse/time/{ms}"
    log(f"NIST: {url}", verbose)
    r = requests.get(url, timeout=15)
    if r.status_code == 404:
        url = f"{NIST_BASE}/pulse/time/previous/{ms}"
        log(f"NIST previous: {url}", verbose)
        j = _get_json(url, timeout=15)
        return j, url
    try:
        r.raise_for_status()
        return r.json(), url
    except Exception as e:
        preview = (r.text or "")[:200].replace("\n", " ")
        raise RuntimeError(f"NIST selhal pro {url}: {e}. Odpověď: {preview!r}") from e

def drand_randomness_for_time(t_utc: dt.datetime, verbose: bool=False) -> Tuple[Dict[str, Any], str, Dict[str, Any]]:
    """drand randomness pro kolo odvozené z času (genesis+period)."""
    log("drand: info", verbose)
    info = _get_json(DRAND_INFO, timeout=15)
    try:
        genesis = int(info["genesis_time"])
        period = int(info["period"])
    except Exception as e:
        raise RuntimeError(f"drand INFO má nečekaný tvar: {info}") from e
    round_no = max(1, (int(t_utc.timestamp()) - genesis)//period + 1)
    url = DRAND_ROUND.format(round=round_no)
    log(f"drand: round {round_no}", verbose)
    rnd = _get_json(url, timeout=15)
    return rnd, url, {"round": round_no, "info": {"period": period, "genesis_time": genesis}}

def btc_block_at_or_before(t_utc: dt.datetime, verbose: bool=False):
    """
    Poslední Bitcoin blok s timestampem ≤ t_utc (binární hledání přes výšku bloků).
    Vrací (meta dict, URL na explorer).
    """
    target = int(t_utc.timestamp())
    tip_h = int(_get_text(f"{BLOCKSTREAM_API}/blocks/tip/height", timeout=15))
    log(f"BTC tip height: {tip_h}", verbose)

    low, high = 0, tip_h
    best = None  # (height, hash, ts)
    while low <= high:
        mid = (low + high) // 2
        hsh = _get_text(f"{BLOCKSTREAM_API}/block-height/{mid}", timeout=15)
        bj  = _get_json(f"{BLOCKSTREAM_API}/block/{hsh}", timeout=15)
        ts  = int(bj.get("timestamp", 0))
        if ts <= target:
            best = (mid, hsh, ts)
            low = mid + 1
        else:
            high = mid - 1

    if best is None:
        # čas před genesis → vezmi genesis blok
        h0 = _get_text(f"{BLOCKSTREAM_API}/block-height/0", timeout=15)
        b0 = _get_json(f"{BLOCKSTREAM_API}/block/{h0}", timeout=15)
        best = (0, h0, int(b0.get("timestamp", 0)))

    height, hsh, ts = best
    meta = {"height": height, "hash": hsh, "timestamp": ts}
    url  = f"https://blockstream.info/block/{hsh}"
    log(f"BTC chosen: height={height}", verbose)
    return meta, url

# ------------------ HKDF + nestranné míchání ------------------

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""; T = b""; c = 1
    while len(out) < length:
        T = hmac.new(prk, T + info + bytes([c]), hashlib.sha256).digest()
        out += T; c += 1
    return out[:length]

def _next_u64(ks: bytes, pos: int) -> Tuple[int,int]:
    if pos+8 > len(ks): _fail("Keystream too short")
    return int.from_bytes(ks[pos:pos+8],"big"), pos+8

def _unbiased_upto(n_inclusive: int, ks: bytes, pos: int) -> Tuple[int,int]:
    m = n_inclusive + 1
    limit = (1<<64) - ((1<<64) % m) - 1
    while True:
        r, pos = _next_u64(ks, pos)
        if r <= limit:
            return r % m, pos

def shuffle_items(items: List[str], keystream: bytes) -> List[str]:
    arr = list(items); i = len(arr)-1; pos = 0
    while i > 0:
        j, pos = _unbiased_upto(i, keystream, pos)
        arr[i], arr[j] = arr[j], arr[i]
        i -= 1
    return arr

# ------------------ self-test ------------------

def quick_connectivity_check(verbose: bool=False) -> int:
    problems = 0
    try:
        _ = _get_json(DRAND_INFO, timeout=10)
        log("CHECK drand OK", verbose)
    except Exception as e:
        problems += 1
        sys.stderr.write(f"VAROVÁNÍ: drand INFO: {e}\n")
    try:
        now = dt.datetime.now(dt.timezone.utc).replace(second=0, microsecond=0)
        _ = nist_pulse_at_minute(now, verbose=False)
        log("CHECK NIST OK", verbose)
    except Exception as e:
        problems += 1
        sys.stderr.write(f"VAROVÁNÍ: NIST: {e}\n")
    try:
        tip = _get_text(f"{BLOCKSTREAM_API}/blocks/tip/height", timeout=10)
        _ = int(tip)
        log("CHECK BTC OK", verbose)
    except Exception as e:
        problems += 1
        sys.stderr.write(f"VAROVÁNÍ: BTC: {e}\n")
    return problems

# ------------------ hlavní běh ------------------

def main() -> None:
    epilog = """
Příklady:
  # Fair (předchozí minuta, žádné čekání)
  python auditable_losovacka.py --items 1,2,3,4,5 --fair

  # Reprodukce minulosti (minulý čas je povolen automaticky)
  python auditable_losovacka.py --items Alice,Bob,Carol --when 2025-10-17T17:00:00Z

  # Self-test prostředí a konektivity
  python auditable_losovacka.py --check --verbose
"""
    ap = argparse.ArgumentParser(
        description="Auditovatelný los (NIST + drand + Bitcoin block) – BTC-only.",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    ap.add_argument("--check", action="store_true", help="Self-test prostředí a konektivity a konec.")
    ap.add_argument("--verbose", action="store_true", help="Logy na STDERR.")

    ap.add_argument("--items", help="CSV seznam účastníků, např. '1,2,3,4,5' nebo 'Alice,Bob Carol,Dan'")
    grp = ap.add_mutually_exclusive_group()
    grp.add_argument("--when", help="Přesná UTC minuta, např. 2025-10-17T17:00:00Z")
    grp.add_argument("--fair", action="store_true", help="Fair BEZ čekání: použije PŘEDCHOZÍ minutu.")

    ap.add_argument("--commit-file", help="Ve fair režimu uloží COMMIT JSON do souboru.")
    ap.add_argument("--commit-stdout", action="store_true", help="Vypíše COMMIT ID/JSON i na stdout (default: ne).")
    ap.add_argument("--base-url", help="Základ webu pro generování repro URL, např. 'https://mojedomena.tld'.") 

    args = ap.parse_args()

    if args.check:
        print("Self-test prostředí…", flush=True)
        print(f"- Python: {sys.version.split()[0]} (≥ {MIN_PY[0]}.{MIN_PY[1]})")
        print(f"- requests: {requests.__version__} (≥ {REQ_REQUESTS_VER})")
        problems = quick_connectivity_check(verbose=args.verbose)
        print("OK" if problems == 0 else f"Hotovo: {problems} varování (viz výše).")
        sys.exit(0 if problems == 0 else 1)

    if not args.items:
        ap.print_help(sys.stderr)
        _fail("\nChybí --items (CSV).")
    if not (args.when or args.fair):
        ap.print_help(sys.stderr)
        _fail("\nMusíš zadat buď --when, nebo --fair.")

    items = parse_items_csv(args.items)
    now_utc = dt.datetime.now(dt.timezone.utc)

    commit_id = None
    commit_obj = None

    # Čas losu
    if args.fair:
        when_used_dt = prev_full_minute(now_utc)
        when_used_iso = when_used_dt.isoformat().replace("+00:00", "Z")
        when_is_past = True  # vždy minulost

        commit_obj = {
            "mode": "items",
            "params": {"items": items},
            "policy": {
                "info_tag": INFO_TAG.decode("ascii"),
                "fair_previous_minute": True,
                "third_source": "btc_block",
            },
            "when_utc_minute": when_used_iso,
            "created_at_utc": now_utc.isoformat().replace("+00:00", "Z"),
            "note": "COMMIT pro PŘEDCHOZÍ minutu (bez čekání).",
        }
        commit_json = json.dumps(commit_obj, separators=(",", ":"), ensure_ascii=False)
        commit_id = sha256(commit_json.encode("utf-8")).hexdigest()
        if args.commit_file:
            with open(args.commit_file, "w", encoding="utf-8") as f:
                f.write(commit_json)
        if args.commit_stdout:
            print(f"COMMIT ID: {commit_id}", flush=True)
            print("COMMIT JSON:", commit_json, flush=True)
    else:
        when_used_dt = parse_when(args.when)  # type: ignore[arg-type]
        when_used_iso = when_used_dt.isoformat().replace("+00:00", "Z")
        when_is_past = (when_used_dt <= now_utc)

    # Zdroje
    nist_json, nist_url = nist_pulse_at_minute(when_used_dt, verbose=args.verbose)
    drand_json, drand_url, drand_meta = drand_randomness_for_time(when_used_dt, verbose=args.verbose)
    btc_meta, btc_url = btc_block_at_or_before(when_used_dt, verbose=args.verbose)

    # Seed (HKDF: NIST + drand + BTC)
    nist_hex = (nist_json.get("pulse", {}) or nist_json).get("outputValue")
    if not isinstance(nist_hex, str):
        _fail("NIST outputValue missing")
    drand_hex = drand_json.get("randomness")
    if not isinstance(drand_hex, str):
        _fail("drand randomness missing")

    extra_entropy = _canon_json({"btc_height": btc_meta["height"], "btc_hash": btc_meta["hash"]})

    ikm = "|".join([
        nist_hex.lower(),
        drand_hex.lower(),
        extra_entropy,
    ]).encode("utf-8")

    salt = hashlib.sha256(
        _canon_json({"when": when_used_iso, "drand_round": str(drand_meta["round"])}).encode("utf-8")
    ).digest()

    prk = hkdf_extract(salt, ikm)
    ks = hkdf_expand(prk, INFO_TAG, (len(items) * 8) + 64)
    ordering = shuffle_items(items, ks)

    # Ověřovací příkaz
    cli_verify = build_cli_verify(os.path.basename(sys.argv[0]) or "auditable_losovacka.py",
                                  when_used_iso, items)

    # web URL (relativní /draw/ pokud není base-url)
    import urllib.parse as _u
    items_csv = ",".join(items)
    qs = _u.urlencode({"items": items_csv, "when": when_used_iso, "pretty": "1"})
    web_verify = (f"{args.base_url.rstrip('/')}/draw/?{qs}") if args.base_url else (f"/draw/?{qs}")


    # Audit JSON (shodně s Django los_core.py)
    audit: Dict[str, Any] = {
        "version": 2,
        "mode": "items",
        "requirements": {
            "must_publish": [
                "pevný seznam účastníků (--items) včetně pořadí",
                "přesná UTC minuta losu (--when) NEBO použití --fair s COMMITem",
            ],
        },
        "policy": {
            "info_tag": INFO_TAG.decode("ascii"),
            "third_source": "btc_block",
            "past_time_handling": "auto-allow",
            "when_is_past": when_is_past,
        },
        "params": {
            "items": items,
            "when_utc_minute": when_used_iso,
        },
        "sources": {
            "nist": {"url": nist_url, "timeStamp": (nist_json.get("pulse", {}) or nist_json).get("timeStamp")},
            "drand": {"url": drand_url, "round": drand_meta["round"]},
            "drand_info": {"url": DRAND_INFO, "period": drand_meta["info"]["period"], "genesis_time": drand_meta["info"]["genesis_time"]},
            "btc_block": {"url": btc_url, "meta": btc_meta},
        },
        "seed_material_preview": {
            "nist_outputValue_hex_prefix": nist_hex[:32] + "...",
            "drand_randomness_hex_prefix": drand_hex[:32] + "...",
            "btc_hash_prefix": btc_meta["hash"][:32] + "...",
        },
        "invocation": {
            "cli_verify": cli_verify,
            "repro_url": web_verify
        },
        "result": ordering,
    }
    if commit_id and commit_obj:
        audit["commit"] = {"id": commit_id, "json": commit_obj}

    # Výstup pro člověka + audit JSON
    print("POŘADÍ ÚČASTNÍKŮ:", " | ".join(ordering), flush=True)
    print("Pro ověření v CLI (skript):", flush=True)
    print(" ", cli_verify, flush=True)
    print("Pro ověření ve webu:", flush=True)
    print(" ", web_verify, flush=True)
    print("\n--- JSON AUDIT ---", flush=True)
    print(json.dumps(audit, ensure_ascii=False, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    main()

