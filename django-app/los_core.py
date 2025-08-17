# los_core.py
# -*- coding: utf-8 -*-
"""
Jádro losování: NIST + drand + DWD MOSMIX-S.
- Bez side-effectů (neprintuje, nekončí proces), vhodné pro Django i CLI.
- items se vždy berou jako CSV (čárky).
- fair=True => použije PŘEDCHOZÍ celou minutu (bez čekání), vloží COMMIT do auditu.
"""

import datetime as dt
import hashlib
import hmac
import json
import os
import shlex
from typing import Any, Dict, List, Tuple

try:
    import requests
except Exception as e:
    raise ImportError("Chybí balík 'requests' (pip install 'requests>=2.31').") from e

# Konstanta – stejná jako ve skriptu
INFO_TAG = b"auditable-draw-v2"

# Endpoints (stejné jako ve skriptu)
NIST_BASE   = "https://beacon.nist.gov/beacon/2.0"
DRAND_INFO  = "https://drand.cloudflare.com/info"
DRAND_ROUND = "https://drand.cloudflare.com/public/{round}"
DWD_MOSMIX_S_ALL_KML = "https://opendata.dwd.de/weather/local_forecasts/mos/MOSMIX_S/all_stations/kml"

# ---------- Pomocné funkce (čas / parsování) ----------

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
        r = requests.get(url, timeout=15)
    r.raise_for_status()
    return r.json(), url

def drand_randomness_for_time(t_utc: dt.datetime) -> Tuple[Dict[str, Any], str, Dict[str, Any]]:
    """drand randomness pro kolo odvozené z času (genesis+period)."""
    info = requests.get(DRAND_INFO, timeout=15).json()
    genesis = int(info["genesis_time"])
    period = int(info["period"])
    round_no = max(1, (int(t_utc.timestamp()) - genesis)//period + 1)
    url = DRAND_ROUND.format(round=round_no)
    rnd = requests.get(url, timeout=15).json()
    return rnd, url, {"round": round_no, "info": {"period": period, "genesis_time": genesis}}

def mosmix_pick_run_and_hash(t_utc_hour: dt.datetime, backtrack_hours: int) -> Tuple[Dict[str, Any], str]:
    """
    Najde KMZ 'MOSMIX_S_YYYYMMDDHH_240.kmz' pro danou hodinu nebo nejbližší předchozí
    (až 'backtrack_hours' hodin), vrátí meta + URL.
    """
    tried = []
    for k in range(backtrack_hours + 1):
        cand = t_utc_hour - dt.timedelta(hours=k)
        fname = f"MOSMIX_S_{cand.strftime('%Y%m%d%H')}_240.kmz"
        url = f"{DWD_MOSMIX_S_ALL_KML}/{fname}"
        r = requests.get(url, timeout=45)
        if r.status_code == 200:
            blob = r.content
            meta = {
                "run_hour_utc": cand.replace(minute=0, second=0, microsecond=0).isoformat().replace("+00:00","Z"),
                "sha256": hashlib.sha256(blob).hexdigest(),
                "bytes": len(blob),
                "filename": fname,
            }
            return meta, url
        tried.append(url)
    raise RuntimeError(f"MOSMIX run nenalezen (zkoušeno): {', '.join(tried)}")

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

# ---------- CLI verify builder ----------

def build_cli_verify(script_name: str, when_iso: str, items: List[str], mosmix_backtrack_hours: int) -> str:
    """
    Postaví spustitelný příkaz pro shell (CSV je jeden argument).
    """
    items_csv = ",".join(items)
    cmd = ["python", script_name, "--when", when_iso, "--items", items_csv,
           "--mosmix-backtrack-hours", str(mosmix_backtrack_hours)]
    return " ".join(shlex.quote(c) for c in cmd)

# ---------- Hlavní výpočet pro Django/CLI ----------

def compute_draw(
    items_csv: str,
    when_iso: str | None,
    fair: bool,
    mosmix_backtrack_hours: int,
    script_name_for_cli: str = "auditable_losovacka.py",
) -> Dict[str, Any]:
    """
    Spočítá los (pořadí) + vrátí plný auditní JSON (stejný jako CLI).
    - items_csv: povinné CSV položek
    - when_iso: ISO čas minuty; pokud None a fair=True → použije PŘEDCHOZÍ minutu
    - fair: True = commit pro předchozí minutu (bez čekání), commit je v auditu
    - mosmix_backtrack_hours: kolik hodin zpět může sáhnout MOSMIX

    Vrací JSON-serializable dict.
    """
    items = parse_items_csv(items_csv)
    now_utc = dt.datetime.now(dt.timezone.utc)

    # Čas losu
    if fair:
        when_dt = prev_full_minute(now_utc)
    else:
        if not when_iso:
            raise ValueError("Chybí 'when' (ISO) nebo 'fair=1'.")
        when_dt = parse_when_iso(when_iso)
    when_iso = when_dt.isoformat().replace("+00:00","Z")
    when_is_past = when_dt <= now_utc

    # Zdroje
    nist_json, nist_url = nist_pulse_at_minute(when_dt)
    drand_json, drand_url, drand_meta = drand_randomness_for_time(when_dt)
    t_hour = when_dt.replace(minute=0)
    mosmix_meta, mosmix_url = mosmix_pick_run_and_hash(t_hour, int(mosmix_backtrack_hours))

    # HKDF seed
    nist_hex = (nist_json.get("pulse", {}) or nist_json).get("outputValue")
    if not isinstance(nist_hex, str): raise RuntimeError("NIST outputValue missing")
    drand_hex = drand_json.get("randomness")
    if not isinstance(drand_hex, str): raise RuntimeError("drand randomness missing")

    ikm = "|".join([
        nist_hex.lower(),
        drand_hex.lower(),
        json.dumps({"mosmix_run": mosmix_meta["run_hour_utc"], "sha256": mosmix_meta["sha256"]},
                   separators=(",",":")),
    ]).encode("utf-8")
    salt = hashlib.sha256(json.dumps({
        "when": when_iso,
        "drand_round": str(drand_meta["round"]),
    }, separators=(",",":")).encode("utf-8")).digest()
    prk = hkdf_extract(salt, ikm)
    ks = hkdf_expand(prk, INFO_TAG, (len(items)*8)+64)

    ordering = shuffle_items(items, ks)

    # CLI verify
    cli_verify = build_cli_verify(script_name_for_cli, when_iso, items, int(mosmix_backtrack_hours))

    # Audit JSON (stejný tvar jako CLI)
    audit: Dict[str, Any] = {
        "version": 2,
        "mode": "items",
        "requirements": {
            "must_publish": [
                "pevný seznam účastníků (--items) včetně pořadí",
                "přesná UTC minuta losu (--when) NEBO použití --fair s COMMITem",
                "pravidlo MOSMIX backtrack (--mosmix-backtrack-hours)",
            ],
        },
        "policy": {
            "mosmix_backtrack_hours": int(mosmix_backtrack_hours),
            "info_tag": INFO_TAG.decode("ascii"),
            "past_time_handling": "auto-allow",
            "when_is_past": when_is_past,
        },
        "params": {
            "items": items,
            "when_utc_minute": when_iso,
        },
        "sources": {
            "nist": {"url": nist_url, "timeStamp": (nist_json.get("pulse", {}) or nist_json).get("timeStamp")},
            "drand": {"url": drand_url, "round": drand_meta["round"]},
            "drand_info": {"url": DRAND_INFO, "period": drand_meta["info"]["period"], "genesis_time": drand_meta["info"]["genesis_time"]},
            "mosmix": {"url": mosmix_url, "meta": mosmix_meta},
        },
        "seed_material_preview": {
            "nist_outputValue_hex_prefix": nist_hex[:32] + "...",
            "drand_randomness_hex_prefix": drand_hex[:32] + "...",
            "mosmix_sha256_prefix": mosmix_meta["sha256"][:32] + "...",
        },
        "invocation": {
            "cli_verify": cli_verify,
            "repro_url": None
        },
        "result": ordering,
    }

    # Commit sekce (jen pro fair)
    if fair:
        commit_obj = {
            "mode": "items",
            "params": {"items": items},
            "policy": {
                "mosmix_backtrack_hours": int(mosmix_backtrack_hours),
                "info_tag": INFO_TAG.decode("ascii"),
                "fair_previous_minute": True,
            },
            "when_utc_minute": when_iso,
            "created_at_utc": now_utc.isoformat().replace("+00:00","Z"),
            "note": "COMMIT pro PŘEDCHOZÍ minutu (bez čekání). Umožňuje 'grind' – zveřejňuj commit v append-only kanálu.",
        }
        commit_json = json.dumps(commit_obj, separators=(",",":"), ensure_ascii=False)
        commit_id = hashlib.sha256(commit_json.encode("utf-8")).hexdigest()
        audit["commit"] = {"id": commit_id, "json": commit_obj}

    return audit

