#!/usr/bin/env python3
"""Encuentra los params correctos para los 5 endpoints con 400"""
import json, sys, time
from pathlib import Path

def load_env(empresa):
    p = Path(f"{empresa}/.env")
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
    if params: url += "?" + urllib.parse.urlencode(params)
    headers = {"Authorization":f"Bearer {key}","Content-Type":"application/json;charset=utf-8","Accept":"application/json"}
    data = json.dumps(body).encode("utf-8") if body else None
    r = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as e:
        try: body_e = e.read().decode("utf-8")
        except: body_e = ""
        return e.code, {"_error": body_e}

empresa = sys.argv[1] if len(sys.argv) > 1 else "ACME"
cfg  = load_env(empresa)
KEY  = cfg["TRENDAI_API_KEY"]
BASE = "https://api.eu.xdr.trendmicro.com"

def show(label, code, resp):
    items = resp.get("items", resp.get("data", resp.get("value", [])))
    err   = resp.get("_error","")
    if code == 200:
        n = len(items)
        first = items[0] if items else {}
        keys = list(first.keys())[:10] if isinstance(first, dict) else []
        print(f"  ✅ {label}: {n} items | keys: {keys}")
        if first and isinstance(first, dict):
            for k,v in list(first.items())[:5]:
                print(f"      {k}: {str(v)[:80]}")
    else:
        print(f"  ❌ [{code}] {label}: {err[:120]}")
    print()

print(f"\n{'─'*60}")
print("  Buscando params correctos para endpoints 400")
print(f"{'─'*60}\n")

# ── 1. Endpoint Inventory — probar variantes ──────────────────────────
print("=== ENDPOINT INVENTORY ===")
variants = [
    ("sin params",           {}),
    ("pageSize=10",          {"pageSize":10}),
    ("limit=10",             {"limit":10}),
    ("top=10",               {"top":10}),
    ("top=10&skip=0",        {"top":10,"skip":0}),
    ("size=10",              {"size":10}),
    ("count=10",             {"count":10}),
]
for label, params in variants:
    code, resp = req(BASE, KEY, "GET", "/v3.0/endpointSecurity/endpoints", params)
    show(f"endpoints ({label})", code, resp)
    if code == 200: break
    time.sleep(0.3)

# ── 2. EIQS — probar variantes ────────────────────────────────────────
print("=== EIQS ENDPOINTS ===")
for label, params in variants:
    code, resp = req(BASE, KEY, "GET", "/v3.0/eiqs/endpoints", params)
    show(f"eiqs ({label})", code, resp)
    if code == 200: break
    time.sleep(0.3)

# ── 3. Response Tasks ─────────────────────────────────────────────────
print("=== RESPONSE TASKS ===")
task_variants = [
    ("sin params",   {}),
    ("top=10",       {"top":10}),
    ("limit=10",     {"limit":10}),
    ("pageSize=10",  {"pageSize":10}),
]
for label, params in task_variants:
    code, resp = req(BASE, KEY, "GET", "/v3.0/response/tasks", params)
    show(f"response/tasks ({label})", code, resp)
    if code == 200: break
    time.sleep(0.3)

# ── 4. Intel Reports ─────────────────────────────────────────────────
print("=== INTEL REPORTS ===")
intel_variants = [
    ("sin params",    {}),
    ("top=5",         {"top":5}),
    ("limit=5",       {"limit":5}),
    ("pageSize=5",    {"pageSize":5}),
]
for label, params in intel_variants:
    code, resp = req(BASE, KEY, "GET", "/v3.0/threatintel/intelligenceReports", params)
    show(f"intel reports ({label})", code, resp)
    if code == 200: break
    time.sleep(0.3)

# ── 5. Endpoint tasks ─────────────────────────────────────────────────
print("=== ENDPOINT TASKS ===")
for label, params in task_variants:
    code, resp = req(BASE, KEY, "GET", "/v3.0/endpointSecurity/tasks", params)
    show(f"endpoint tasks ({label})", code, resp)
    if code == 200: break
    time.sleep(0.3)

# ── 6. Workbench sin fecha — cuántas alertas hay realmente? ────────────
print("=== WORKBENCH — todos los datos disponibles ===")
code, resp = req(BASE, KEY, "GET", "/v3.0/workbench/alerts", {"top":200})
items = resp.get("items",[])
print(f"  Total alertas disponibles: {len(items)}")
if items:
    # Mostrar distribución por tipo
    from collections import Counter
    providers = Counter(a.get("alertProvider","?") for a in items)
    severities = Counter(a.get("severity","?") for a in items)
    models = Counter(a.get("model","?") for a in items)
    print(f"  Por provider: {dict(providers)}")
    print(f"  Por severidad: {dict(severities)}")
    print(f"  Top modelos:")
    for model, n in models.most_common(10):
        print(f"    {n:3d}x  {model}")
    print(f"\n  Primera alerta completa:")
    print(json.dumps(items[0], indent=2, ensure_ascii=False)[:1000])

# ── 7. Suspicious Objects — qué tipos hay? ────────────────────────────
print("\n=== SUSPICIOUS OBJECTS — todos ===")
code, resp = req(BASE, KEY, "GET", "/v3.0/threatintel/suspiciousObjects", {"top":200})
items = resp.get("items",[])
print(f"  Total: {len(items)}")
if items:
    types = {}
    for o in items:
        t = o.get("type","?")
        types[t] = types.get(t,0) + 1
    print(f"  Por tipo: {types}")
    print(f"\n  Primer objeto completo:")
    print(json.dumps(items[0], indent=2, ensure_ascii=False)[:500])
