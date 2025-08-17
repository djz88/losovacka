# -*- coding: utf-8 -*-
"""
los/views.py

UI + JSON endpoint pro losovačku (NIST + drand + Bitcoin block).
"""

import json
import requests
from urllib.parse import urlparse, parse_qs
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_GET, require_http_methods
from . import los_core
from .forms import RunDrawForm, VerifyForm


@require_GET
def draw(request):
    """
    JSON endpoint (bez UI):
      /draw/?items=1,2,3,4,5&fair=1
      /draw/?items=Alice,Bob,Carol&when=2025-10-17T17:00:00Z
      Volitelně: &pretty=1
    """
    items = request.GET.get("items")
    when = request.GET.get("when")
    fair = request.GET.get("fair")
    pretty = request.GET.get("pretty")

    if not items:
        return JsonResponse({"error": "Chybí 'items' (CSV)."}, status=400)
    if not when and not fair:
        return JsonResponse({"error": "Zadej buď 'when=ISO', nebo 'fair=1'."}, status=400)

    base = request.build_absolute_uri("/").rstrip("/")

    try:
        audit = los_core.compute_draw(
            items_csv=items,
            when_iso=when,
            fair=bool(int(fair)) if fair is not None else False,
            script_name_for_cli="auditable_losovacka.py",
            base_url=base,
        )
    except ValueError as e:
        return JsonResponse({"error": str(e)}, status=400)
    except Exception as e:
        return JsonResponse({"error": f"{type(e).__name__}: {e}"}, status=500)

    params = {"ensure_ascii": False}
    if pretty:
        params["indent"] = 2
    return JsonResponse(audit, json_dumps_params=params)


@require_http_methods(["GET", "POST"])
def index(request):
    """
    Webové UI:
      - Spustit losování (RunDrawForm)
      - Ověřit audit (VerifyForm) – URL nebo vložený JSON
    """
    run_form = RunDrawForm(request.POST or None)
    verify_form = VerifyForm(request.POST or None)

    run_result = None
    run_result_pretty = None

    verify_result = None
    verify_result_pretty = None
    verify_status = None
    verify_details = None
    verify_details_pretty = None

    error_msg = None

    if request.method == "POST":
        # Urči, který formulář se poslal
        if "items" in request.POST:
            action = "run"
        elif ("audit_url" in request.POST) or ("audit_json" in request.POST):
            action = "verify"
        else:
            action = None

        if action == "run":
            if run_form.is_valid():
                cd = run_form.cleaned_data
                try:
                    base = request.build_absolute_uri("/").rstrip("/")
                    audit = los_core.compute_draw(
                        items_csv=cd["items"],
                        when_iso=cd["when"] if not cd["fair"] else None,
                        fair=bool(cd["fair"]),
                        script_name_for_cli="auditable_losovacka.py",
                        base_url=base,
                    )
                    run_result = audit
                    run_result_pretty = json.dumps(audit, ensure_ascii=False, indent=2)
                except Exception as e:
                    error_msg = f"{type(e).__name__}: {e}"

        elif action == "verify":
            if verify_form.is_valid():
                raw_json = None
                try:
                    if verify_form.cleaned_data["audit_url"]:
                        url = verify_form.cleaned_data["audit_url"]
                        pu = urlparse(url)
                        same_host = (pu.netloc == request.get_host()) or (pu.hostname in {"127.0.0.1", "localhost"})
                        is_draw_endpoint = pu.path.rstrip("/") == "/draw"

                        if same_host and is_draw_endpoint:
                            # Bez HTTP: rozparsuj query a zavolej přímo jádro
                            qs = parse_qs(pu.query)
                            items_q = qs.get("items", [""])[0]
                            when_q  = qs.get("when", [None])[0]
                            fair_q  = qs.get("fair", [None])[0]
                            base    = request.build_absolute_uri("/").rstrip("/")

                            stated = los_core.compute_draw(
                                items_csv=items_q,
                                when_iso=when_q,
                                fair=bool(int(fair_q)) if fair_q not in (None, "",) else False,
                                script_name_for_cli="auditable_losovacka.py",
                                base_url=base,
                            )
                            raw_json = json.dumps(stated, ensure_ascii=False)
                        else:
                            # Externí URL – normálně stáhni
                            r = requests.get(url, timeout=20)
                            r.raise_for_status()
                            raw_json = r.text
                    else:
                        raw_json = verify_form.cleaned_data["audit_json"] or ""


                    raw = raw_json.strip()
                    if not raw:
                        raise ValueError("Audit JSON je prázdný.")

                    try:
                        stated = json.loads(raw)
                    except json.JSONDecodeError as je:
                        preview = raw[:200].replace("\n", " ")
                        raise ValueError(f"Neplatný JSON (začátek: {preview!r})") from je

                    # Validace: očekáváme BTC jako třetí zdroj
                    sources = stated.get("sources", {})
                    if "btc_block" not in sources:
                        raise ValueError("Tento audit nepoužívá Bitcoin block – nelze ověřit touto verzí.")

                    items_list = stated["params"]["items"]
                    when_iso = stated["params"]["when_utc_minute"]

                    base = request.build_absolute_uri("/").rstrip("/")
                    recomputed = los_core.compute_draw(
                        items_csv=",".join(items_list),
                        when_iso=when_iso,
                        fair=False,
                        script_name_for_cli="auditable_losovacka.py",
                        base_url=base,
                    )

                    # Porovnání klíčových věcí
                    same_result = (recomputed.get("result") == stated.get("result"))
                    same_nist = (recomputed["sources"]["nist"]["url"] == sources["nist"]["url"])
                    same_drand = (recomputed["sources"]["drand"]["url"] == sources["drand"]["url"])
                    same_btc = (recomputed["sources"]["btc_block"]["url"] == sources["btc_block"]["url"])
                    ok = all([same_result, same_nist, same_drand, same_btc])

                    verify_status = "VERIFIED" if ok else "MISMATCH [unverified]"
                    verify_details = {
                        "same_result": same_result,
                        "same_nist_url": same_nist,
                        "same_drand_url": same_drand,
                        "same_btc_url": same_btc,
                        "recomputed": recomputed,
                        "stated": stated,
                    }

                    verify_result = stated
                    verify_result_pretty = json.dumps(stated, ensure_ascii=False, indent=2)
                    verify_details_pretty = json.dumps(verify_details, ensure_ascii=False, indent=2)

                except Exception as e:
                    error_msg = f"{type(e).__name__}: {e}"

    return render(request, "los/index.html", {
        "run_form": run_form,
        "verify_form": verify_form,
        "run_result": run_result,
        "run_result_pretty": run_result_pretty,
        "verify_result": verify_result,
        "verify_result_pretty": verify_result_pretty,
        "verify_status": verify_status,
        "verify_details": verify_details,
        "verify_details_pretty": verify_details_pretty,
        "error_msg": error_msg,
    })

