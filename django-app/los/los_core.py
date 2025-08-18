# -*- coding: utf-8 -*-
"""
los_core.py

Jádro losování: NIST + drand + Bitcoin block (bez počasí/MOSMIX).
- items se vždy berou jako CSV (čárkami).
- fair=True => použije PŘEDCHOZÍ celou minutu (bez čekání), commit je v auditu.
- deterministické, auditovatelné, shodné výstupy napříč běhy při stejných vstupech.
"""

import datetime as dt
import hashlib
import hmac
import json
import os
import requests
import shlex
import urllib.parse
import time
from typing import Any, Dict, List, Tuple, Optional


INFO_TAG = b"auditable-draw-v2"
# Sjednoceni timeoutu při žádosti pro rúzné verze urllib3 či pomalé připojení
HTTP_CONNECT_TIMEOUT = float(os.getenv("LOS_HTTP_CONNECT_TIMEOUT", "5"))
HTTP_READ_TIMEOUT    = float(os.getenv("LOS_HTTP_READ_TIMEOUT", "45"))  # bývalo 15
HTTP_RETRIES         = int(os.getenv("LOS_HTTP_RETRIES", "3"))
HTTP_BACKOFF         = float(os.getenv("LOS_HTTP_BACKOFF", "0.75"))     # expo backoff základ

# Endpoints
NIST_BASE   = "https://beacon.nist.gov/beacon/2.0"
DRAND_INFO  = "https://drand.cloudflare.com/info"
DRAND_ROUND = "https://drand.cloudflare.com/public/{round}"

# Bitcoin (Blockstream Esplora API)
BLOCKSTREAM_API = "https://blockstream.info/api"


# ---------- Pomocné funkce s rozumnými chybami ----------

def _get_json(url: str, timeout: int = 15):
    r = _http_get(url, timeout)
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
    r = _http_get(url, timeout)
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

def _canon_json(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True)

# ---------- Čas a vstupy ----------

def parse_when_iso(s: str) -> dt.datetime:
    """ISO 8601 → UTC datetime na celou minutu."""
    t = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    if t.tzinfo is None:
        t = t.replace(tzinfo=dt.timezone.utc)
    return t.astimezone(dt.timezone.utc).replace(second=0, microsecond=0)

def prev_full_minute(now_utc: dt.datetime) -> dt.datetime:
    """Předchozí celá minuta (UTC)."""
    return (now_utc.replace(second=0, microsecond=0) - dt.timedelta(minutes=1)).astimezone(dt.timezone.utc)

def parse_items_csv(s: str) -> List[str]:
    """Povinné CSV (čárkami), bez duplicit, min. 2 položky."""
    if "," not in s:
        raise ValueError("--items musí být CSV (např. '1,2,3' nebo 'Alice,Bob Carol').")
    parts = [p.strip() for p in s.split(",")]
    if any(p == "" for p in parts) or len(parts) < 2:
        raise ValueError("--items: prázdná nebo příliš krátká sada položek.")
    if len(set(parts)) != len(parts):
        raise ValueError("--items: duplicity nejsou povoleny.")
    return parts


# ---------- Zdroje entropie ----------

def nist_pulse_at_minute(t_utc: dt.datetime) -> Tuple[Dict[str, Any], str]:
    """NIST Beacon pulse pro danou minutu (případně previous)."""
    ms = int(t_utc.timestamp() * 1000)
    url = f"{NIST_BASE}/pulse/time/{ms}"
    r = requests.get(url, timeout=15)
    if r.status_code == 404:
        url = f"{NIST_BASE}/pulse/time/previous/{ms}"
        j = _get_json(url, timeout=15)
        return j, url
    try:
        r.raise_for_status()
        return r.json(), url
    except Exception as e:
        preview = (r.text or "")[:200].replace("\n", " ")
        raise RuntimeError(f"NIST selhal pro {url}: {e}. Odpověď: {preview!r}") from e

def drand_randomness_for_time(t_utc: dt.datetime) -> Tuple[Dict[str, Any], str, Dict[str, Any]]:
    """drand randomness pro kolo odvozené z času (genesis+period)."""
    info = _get_json(DRAND_INFO, timeout=15)
    try:
        genesis = int(info["genesis_time"])
        period = int(info["period"])
    except Exception as e:
        raise RuntimeError(f"drand INFO má nečekaný tvar: {info}") from e

    round_no = max(1, (int(t_utc.timestamp()) - genesis) // period + 1)
    url = DRAND_ROUND.format(round=round_no)
    rnd = _get_json(url, timeout=15)
    return rnd, url, {"round": round_no, "info": {"period": period, "genesis_time": genesis}}

def btc_block_at_or_before(t_utc: dt.datetime):
    """
    Najde poslední Bitcoin blok s timestampem <= t_utc.
    Použije binární hledání přes výšku bloků (O(log N)).
    Vrací (meta dict, lidská URL na explorer).
    """
    target = int(t_utc.timestamp())
    tip_h = int(_get_text(f"{BLOCKSTREAM_API}/blocks/tip/height", timeout=15))

    low, high = 0, tip_h
    best = None  # (height, hash, timestamp)
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
        # čas je před genesis – použijeme genesis blok (0)
        h0 = _get_text(f"{BLOCKSTREAM_API}/block-height/0", timeout=15)
        b0 = _get_json(f"{BLOCKSTREAM_API}/block/{h0}", timeout=15)
        best = (0, h0, int(b0.get("timestamp", 0)))

    height, hsh, ts = best
    meta = {"height": height, "hash": hsh, "timestamp": ts}
    url  = f"https://blockstream.info/block/{hsh}"
    return meta, url


# ---------- HKDF + nestranné míchání ----------

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""; T = b""; c = 1
    while len(out) < length:
        T = hmac.new(prk, T + info + bytes([c]), hashlib.sha256).digest()
        out += T; c += 1
    return out[:length]

def _next_u64(ks: bytes, pos: int) -> Tuple[int,int]:
    if pos+8 > len(ks): raise RuntimeError("Keystream too short")
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


# ---------- Builders pro CLI a WEB ověření ----------

def build_cli_verify(script_name: str, when_used_iso: str, items: List[str]) -> str:
    """Postaví spustitelný příkaz pro shell (CSV je jeden argument)."""
    items_csv = ",".join(items)
    cmd = ["python", script_name, "--when", when_used_iso, "--items", items_csv]
    return " ".join(shlex.quote(c) for c in cmd)

def build_web_verify_url(base_url: Optional[str], when_used_iso: str, items: List[str]) -> str:
    """
    Postaví URL na webový endpoint /draw/ (relativní nebo absolutní).
    Používá 'when' (i když běželo fair), aby bylo jednoznačné.
    """
    items_csv = ",".join(items)
    qs = urllib.parse.urlencode({"items": items_csv, "when": when_used_iso, "pretty": "1"})
    base = (base_url.rstrip("/") if base_url else "")
    return (f"{base}/draw/?{qs}") if base else (f"/draw/?{qs}")


# ---------- Hlavní výpočet (pro Django/CLI) ----------

def compute_draw(
    items_csv: str,
    when_used_iso: str | None,
    fair: bool,
    script_name_for_cli: str = "auditable_losovacka.py",
    base_url: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Spočítá los (pořadí) + vrátí plný auditní JSON.
    - items_csv: povinné CSV položek
    - when_used_iso: ISO čas minuty; pokud None a fair=True → použije PŘEDCHOZÍ minutu
    - fair: True = commit pro předchozí minutu (bez čekání)
    - base_url: volitelné; pokud zadáno, 'repro_url' bude absolutní
    """
    items = parse_items_csv(items_csv)
    now_utc = dt.datetime.now(dt.timezone.utc)

    # Čas losu
    if fair:
        when_dt = prev_full_minute(now_utc)
    else:
        if not when_used_iso:
            raise ValueError("Chybí 'when' (ISO) nebo 'fair=1'.")
        when_dt = parse_when_iso(when_used_iso)
    when_used_iso = when_dt.isoformat().replace("+00:00","Z")
    when_is_past = when_dt <= now_utc

    # Zdroje: NIST + drand + BTC blok ≤ when
    nist_json, nist_url = nist_pulse_at_minute(when_dt)
    drand_json, drand_url, drand_meta = drand_randomness_for_time(when_dt)
    btc_meta, btc_url = btc_block_at_or_before(when_dt)

    # Seed: HKDF z NIST + drand + BTC
    nist_hex = (nist_json.get("pulse", {}) or nist_json).get("outputValue")
    if not isinstance(nist_hex, str): raise RuntimeError("NIST outputValue missing")
    drand_hex = drand_json.get("randomness")
    if not isinstance(drand_hex, str): raise RuntimeError("drand randomness missing")

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
    ks = hkdf_expand(prk, INFO_TAG, (len(items)*8)+64)

    ordering = shuffle_items(items, ks)
    cli_verify = build_cli_verify(script_name_for_cli, when_used_iso, items)
    web_verify = build_web_verify_url(base_url, when_used_iso, items)

    # Audit JSON
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

    if fair:
        commit_obj = {
            "mode": "items",
            "params": {"items": items},
            "policy": {
                "info_tag": INFO_TAG.decode("ascii"),
                "fair_previous_minute": True,
                "third_source": "btc_block",
            },
            "when_utc_minute": when_used_iso,
            "created_at_utc": now_utc.isoformat().replace("+00:00","Z"),
            "note": "COMMIT pro PŘEDCHOZÍ minutu (bez čekání).",
        }
        commit_json = json.dumps(commit_obj, separators=(",",":"), ensure_ascii=False)
        commit_id = hashlib.sha256(commit_json.encode("utf-8")).hexdigest()
        audit["commit"] = {"id": commit_id, "json": commit_obj}

    return audit

