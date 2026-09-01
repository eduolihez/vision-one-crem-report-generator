#!/usr/bin/env python3
"""
debug_api.py — Prueba exhaustiva de endpoints Vision One
Uso: python debug_api.py --empresa ACME
Muestra exactamente qué responde cada endpoint y qué datos tiene.
"""
import json, sys, time, argparse
from pathlib import Path

def load_env(empresa):
    p = Path(f"../CLIENTES/{empresa}/.env")
    if not p.exists():
        print(f"✗ No existe {p}")
        sys.exit(1)
    cfg = {}
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line: continue
        k, _, v = line.partition("=")
        cfg[k.strip()] = v.strip().strip('"').strip("'")
    return cfg

def req(base, key, method, path, params=None, body=None):
    import urllib.request, urllib.parse, urllib.error
    url = base + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json;charset=utf-8",
        "Accept": "application/json",
    }
    data = json.dumps(body).encode("utf-8") if body else None
    r = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as e:
        body_e = ""
        try: body_e = e.read().decode("utf-8")[:200]
        except: pass
        return e.code, {"_error": body_e}

parser = argparse.ArgumentParser()
parser.add_argument("--empresa", required=True)
parser.add_argument("--mes", default="Mayo 2026")
args = parser.parse_args()

cfg = load_env(args.empresa)
KEY    = cfg["TRENDAI_API_KEY"]
REGION = cfg.get("TRENDAI_REGION", "EU")
REGIONS = {
    "EU":"https://api.eu.xdr.trendmicro.com",
    "US":"https://api.xdr.trendmicro.com",
    "AU":"https://api.au.xdr.trendmicro.com",
}
BASE = REGIONS.get(REGION, REGIONS["EU"])

# Parse mes
MESES = {"Enero":1,"Febrero":2,"Marzo":3,"Abril":4,"Mayo":5,"Junio":6,
         "Julio":7,"Agosto":8,"Septiembre":9,"Octubre":10,"Noviembre":11,"Diciembre":12}
parts = args.mes.split()
m = MESES.get(parts[0], 5)
y = int(parts[1]) if len(parts) > 1 else 2026
from datetime import datetime, timezone
start = datetime(y, m, 1, tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
end_m = 1 if m == 12 else m + 1
end_y = y + 1 if m == 12 else y
end   = datetime(end_y, end_m, 1, tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

print(f"\n{'═'*70}")
print(f"  DEBUG Vision One API — {args.empresa}")
print(f"  Base: {BASE}")
print(f"  Período: {start} → {end}")
print(f"{'═'*70}\n")

# ── Todos los endpoints a probar ─────────────────────────────────────────────
TESTS = [
    # (label, method, path, params_or_body)
    # Core
    ("Workbench Alerts",             "GET",  "/v3.0/workbench/alerts",
        {"startDateTime":start,"endDateTime":end,"top":5}),
    ("Workbench Alerts (sin fecha)",  "GET",  "/v3.0/workbench/alerts",
        {"top":5}),
    ("OAT Detections",               "GET",  "/v3.0/workbench/detections",
        {"startDateTime":start,"endDateTime":end,"top":5}),
    ("Search Detections (POST)",     "POST", "/v3.0/search/detections",
        {"query":"*","from":start,"to":end,"source":"detections"}),
    ("Search Endpoint Activity",     "POST", "/v3.0/search/endpointActivities",
        {"query":"*","from":start,"to":end}),

    # Endpoint Security
    ("Endpoint Inventory v3",        "GET",  "/v3.0/endpointSecurity/endpoints",
        {"top":5}),
    ("Endpoint EIQS",                "GET",  "/v3.0/eiqs/endpoints",
        {"top":5}),
    ("Endpoint Agent Health",        "GET",  "/v3.0/endpointSecurity/agentHealth",
        {"top":5}),
    ("Endpoint Tasks",               "GET",  "/v3.0/endpointSecurity/tasks",
        {"top":5}),
    ("Connected Products",           "GET",  "/v3.0/productInstances",
        {"top":5}),

    # CREM / ASRM (rutas correctas v3.0 — confirmadas por soporte Trend Micro)
    ("CREM Vulnerable Devices",      "GET",  "/v3.0/asrm/vulnerableDevices",
        {"top":5,"cveDetectionStatus":"any"}),
    ("CREM Attack Surface Devices",  "GET",  "/v3.0/asrm/attackSurfaceDevices",
        {"top":5}),
    ("CREM Security Posture",        "GET",  "/v3.0/asrm/securityPosture",
        {"top":5}),
    ("CREM High Risk Devices",       "GET",  "/v3.0/asrm/highRiskDevices",
        {"top":5}),
    ("CREM Public IP Addresses",     "GET",  "/v3.0/asrm/attackSurfacePublicIpAddresses",
        {"top":5}),
    ("CREM Asset Groups",            "GET",  "/v3.0/asrm/assetGroups",
        {"top":5}),
    ("ASM Risk Score",               "GET",  "/v3.0/asm/riskScore",
        None),
    ("ASM Attack Paths",             "GET",  "/v3.0/asm/attackPaths",
        {"top":5}),
    ("Risk Insights Score",          "GET",  "/v3.0/riskInsights/riskScore",
        None),
    ("Risk Insights Indices",        "GET",  "/v3.0/riskInsights/riskIndices",
        {"top":5}),
    ("Operations Dashboard",         "GET",  "/v3.0/riskInsights/opsRiskEvents",
        {"top":5}),

    # Cloud & Email
    ("Cloud Access Risk Events",     "GET",  "/v3.0/cloudAccess/riskAccessEvents",
        {"startDateTime":start,"endDateTime":end,"top":5}),
    ("Email Security Alerts",        "GET",  "/v3.0/emailSecurity/alerts",
        {"startDateTime":start,"endDateTime":end,"top":5}),
    ("Cloud File Security",          "GET",  "/v3.0/cloudFileSecurity/events",
        {"top":5}),

    # Threat Intel
    ("Sandbox Submissions",          "GET",  "/v3.0/sandbox/submissionList",
        {"top":5}),
    ("Suspicious Objects",           "GET",  "/v3.0/threatintel/suspiciousObjects",
        {"top":5}),
    ("Intel Reports",                "GET",  "/v3.0/threatintel/intelligenceReports",
        {"top":5}),

    # Identity
    ("IAM API Keys",                 "GET",  "/v3.0/iam/apiKeys",
        None),
    ("IAM Accounts Risk",            "GET",  "/v3.0/iam/accountsRiskInsight",
        {"top":5}),

    # Audit & Response
    ("Audit Logs",                   "GET",  "/v3.0/auditLogs",
        {"startDateTime":start,"endDateTime":end,"top":5}),
    ("Response Tasks",               "GET",  "/v3.0/response/tasks",
        {"startDateTime":start,"endDateTime":end,"top":5}),

    # Network
    ("Network Sensors",              "GET",  "/v3.0/networkSecurity/sensors",
        {"top":5}),

    # SIEM
    ("SIEM Events",                  "GET",  "/v3.0/siem/events",
        {"startDateTime":start,"endDateTime":end,"top":5}),
]

OK, PARTIAL, EMPTY, FAIL = [], [], [], []

for label, method, path, params_or_body in TESTS:
    if method == "POST":
        code, resp = req(BASE, KEY, "POST", path, body=params_or_body)
    else:
        code, resp = req(BASE, KEY, "GET", path, params=params_or_body)

    items = resp.get("items", resp.get("data", resp.get("value", [])))
    error = resp.get("_error","") or resp.get("error",{})

    if code == 200:
        if items:
            n = len(items)
            # Show first item keys
            first = items[0] if items else {}
            keys = list(first.keys())[:8] if isinstance(first, dict) else []
            print(f"  ✅  [{code}] {label}")
            print(f"        → {n} item(s) | keys: {', '.join(keys)}")
            # Show sample values for key fields
            for k in ["model","alertProvider","severity","id","filterName","type","objectType"]:
                if k in first:
                    print(f"           {k}: {str(first[k])[:60]}")
            OK.append(label)
        else:
            # 200 but empty — endpoint exists
            print(f"  🟡  [{code}] {label} — vacío (sin datos en el período)")
            EMPTY.append(label)
    elif code in (400, 405):
        # Bad request — endpoint exists but wrong params
        err_msg = str(error)[:100] if error else ""
        print(f"  🟠  [{code}] {label} — parámetros inválidos: {err_msg[:80]}")
        PARTIAL.append(label)
    elif code == 404:
        print(f"  ❌  [{code}] {label} — módulo no disponible")
        FAIL.append(label)
    elif code == 403:
        print(f"  🔒  [{code}] {label} — sin permisos (rol insuficiente)")
        FAIL.append(label)
    elif code == 401:
        print(f"  🔑  [{code}] {label} — API key inválida")
        FAIL.append(label)
    else:
        err_msg = str(error)[:100] if error else ""
        print(f"  ❓  [{code}] {label} — {err_msg[:80]}")
        FAIL.append(label)

    time.sleep(0.3)  # rate limit gentil

print(f"\n{'─'*70}")
print(f"  RESUMEN:")
print(f"  ✅ Funciona con datos:  {len(OK):2d}  — {', '.join(OK[:5])}{'...' if len(OK)>5 else ''}")
print(f"  🟡 Funciona vacío:      {len(EMPTY):2d}  — {', '.join(EMPTY[:5])}{'...' if len(EMPTY)>5 else ''}")
print(f"  🟠 Existe/params mal:   {len(PARTIAL):2d}  — {', '.join(PARTIAL[:5])}")
print(f"  ❌ No disponible/error: {len(FAIL):2d}")
print(f"{'─'*70}\n")
