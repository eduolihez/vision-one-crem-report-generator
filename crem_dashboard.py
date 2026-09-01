#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CREM Dashboard v3 — Aplicación de escritorio
Ejecutar: python crem_dashboard.py
"""
import subprocess, sys, importlib, importlib.util, os, secrets, threading, time

# ── Auto-install deps ─────────────────────────────────────────────────────────
_DEPS = {"flask": "flask>=2.0"}
def _ensure():
    miss = [p for m, p in _DEPS.items() if not importlib.util.find_spec(m)]
    if miss:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet"] + miss)
_ensure()

import csv, json, queue, traceback, webbrowser
from datetime import date, timedelta, datetime
from pathlib import Path
from flask import Flask, Response, jsonify, render_template_string, request

_DIR = Path(__file__).parent
_INFORME_PY = _DIR / "informe_crem.py"
try:
    from informe_crem import normalizar_csvs
except ImportError:
    def normalizar_csvs(d): pass

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
_q: queue.Queue = queue.Queue()
_job = {"running": False}
_job_lock = threading.Lock()
_SKIP_DIRS = {"plantilla","datos","__pycache__",".git","default","debug","info_doc","CLIENTES","herramientas","cve_cache"}

MESES_ES = {"January":"Enero","February":"Febrero","March":"Marzo","April":"Abril",
            "May":"Mayo","June":"Junio","July":"Julio","August":"Agosto",
            "September":"Septiembre","October":"Octubre","November":"Noviembre","December":"Diciembre"}

CSV_REQ = ["cve-events.csv","cve-assets.csv","threat-detections.csv",
           "anomaly-detections.csv","security-conf.csv","sys-conf.csv",
           "cloud-app.csv","account-compromise.csv"]

CRITICIDADES = ["MUY CRITICO","CRITICO","NORMAL","NO CRITICO",""]

DEFAULT_CFG = {
    "empresa":"","sla_critico_dias":1,"sla_alto_dias":3,"sla_medio_dias":7,
    "meses_reincidente":2,"modulos_ignorar":[],"notas_adicionales":"",
    "contacto_tecnico":"","abrir_html_al_terminar":False,"inventario_activos":{}
}

MODULOS_ALL = ["cve-events","cve-assets","threat-detections","anomaly-detections",
               "security-conf","sys-conf","cloud-app","account-compromise"]

# ── Helpers ───────────────────────────────────────────────────────────────────
def _get_meses():
    hoy = date.today()
    out = []
    for i in range(18):
        yr = hoy.year + (hoy.month - 1 - i) // 12
        mo = ((hoy.month - 1 - i) % 12) + 1
        d  = date(yr, mo, 1)
        out.append(MESES_ES.get(d.strftime("%B"), d.strftime("%B")) + " " + str(d.year))
    return out

_CLIENTES_DIR = _DIR / "CLIENTES"
def _emp(nombre):
    slug = nombre.replace("/","_").replace("\\","_").replace(":","_").strip()
    p_cli = _CLIENTES_DIR / slug
    return p_cli if _CLIENTES_DIR.is_dir() else (_DIR / slug)
def _cfg_path(n):  return _emp(n) / "config.json"

def _read_cfg(p):
    cp = (p / "config.json") if isinstance(p, Path) else _cfg_path(p)
    if not cp.exists(): return dict(DEFAULT_CFG)
    try:    return json.loads(cp.read_text(encoding="utf-8"))
    except Exception as ex:
        print(f"[WARN] config.json inválido en {cp} ({ex}) — usando valores por defecto", file=sys.stderr)
        return dict(DEFAULT_CFG)

def _write_cfg(n, cfg):
    ed = _emp(n); ed.mkdir(parents=True, exist_ok=True)
    _cfg_path(n).write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")

def _last_inf(p):
    d = p / "INFORMES"
    if not d.exists(): return ""
    subs = sorted([x for x in d.iterdir() if x.is_dir() and x.name != "CSV"], reverse=True)
    return subs[0].name.replace("_"," ") if subs else ""

def _detectar_empresas():
    out = []
    _base = _CLIENTES_DIR if _CLIENTES_DIR.is_dir() else _DIR
    for p in sorted(_base.iterdir()):
        if not p.is_dir() or p.name in _SKIP_DIRS or p.name.startswith("."): continue
        if not ((p/"CSV").is_dir() or (p/"INFORMES").is_dir()): continue
        cfg = _read_cfg(p)
        hist = p/"INFORMES"/"CSV"
        csv_dir = p/"CSV"
        if csv_dir.is_dir():
            normalizar_csvs(csv_dir)
        inv = {k:v for k,v in cfg.get("inventario_activos",{}).items() if not k.startswith("_")}
        out.append({
            "nombre":    p.name,
            "csv_ok":    csv_dir.is_dir(),
            "hist_ok":   hist.exists(),
            "csv_count": len(list(csv_dir.glob("*.csv"))) if csv_dir.is_dir() else 0,
            "hist_count":len(list(hist.glob("csv-*"))) if hist.exists() else 0,
            "inv_count": len(inv),
            "contacto":  cfg.get("contacto_tecnico",""),
            "last_info": _last_inf(p),
            "api_ok":    _has_api_key(p.name),
            "api_meta":  _api_meta(p.name),
        })
    return out

def _csv_info(nombre):
    csv_dir = _emp(nombre) / "CSV"
    if not csv_dir.exists(): return []
    normalizar_csvs(csv_dir)
    out = []
    for f in sorted(csv_dir.glob("*.csv")):
        try:
            size = f.stat().st_size
            with open(f, encoding="utf-8-sig", errors="replace", newline="") as fh:
                rows = max(0, sum(1 for _ in csv.reader(fh)) - 1)
        except Exception: size=0; rows=0
        out.append({"name":f.name,"rows":rows,"size":round(size/1024,1),"req":f.name in CSV_REQ})
    return out

def _get_historico():
    items = []
    _base2 = _CLIENTES_DIR if _CLIENTES_DIR.is_dir() else _DIR
    for emp in sorted(_base2.iterdir()):
        if not emp.is_dir() or emp.name in _SKIP_DIRS or emp.name.startswith("."): continue
        inf = emp / "INFORMES"
        if not inf.exists(): continue
        for mes in sorted(inf.iterdir(), reverse=True):
            if mes.name == "CSV" or not mes.is_dir(): continue
            html_f = next(mes.glob("*.html"), None)
            pdf_f  = next(mes.glob("*.pdf"), None)
            word_f = next(mes.glob("*.docx"), None)
            items.append({
                "empresa": emp.name, "mes": mes.name.replace("_"," "),
                "path": str(mes),
                "html": str(html_f) if html_f else "",
                "pdf":  str(pdf_f)  if pdf_f  else "",
                "word": str(word_f) if word_f else "",
            })
    return items[:60]

def _get_resumen_global():
    empresas = _detectar_empresas()
    historico = _get_historico()
    
    total_empresas = len(empresas)
    empresas_ok = sum(1 for e in empresas if e.get("csv_count", 0) >= 8 or e.get("api_ok"))
    total_csvs = sum(e.get("csv_count", 0) for e in empresas)
    total_informes = len(historico)
    api_configuradas = sum(1 for e in empresas if e.get("api_ok"))
    
    desactualizados = 0
    try:
        from informe_crem import validar_vigencia_csv
        for e in empresas:
            csv_dir = _emp(e["nombre"]) / "CSV"
            if csv_dir.exists():
                for f in csv_dir.glob("*.csv"):
                    vig = validar_vigencia_csv(f)
                    if vig.get("status") == "stale":
                        desactualizados += 1
                        break
    except Exception:
        pass
        
    return {
        "total_empresas": total_empresas,
        "empresas_ok": empresas_ok,
        "total_csvs": total_csvs,
        "total_informes": total_informes,
        "api_configuradas": api_configuradas,
        "desactualizados": desactualizados,
        "empresas": empresas,
        "ultimos_informes": historico[:5]
    }

# ── TrendAI API helpers ───────────────────────────────────────────────────────
_TRENDAI_API = Path(__file__).parent / "trendai_api.py"
_ENV_TEMPLATE = """# CREM — Configuración API TrendAI Vision One
# Obtén tu API Key en: Vision One > Administration > API Keys

TRENDAI_API_KEY=
TRENDAI_REGION=EU

# Regiones disponibles: EU, US, AU, IN, SG, JP
# EU  = https://api.eu.xdr.trendmicro.com  (España/Europa)
# US  = https://api.xdr.trendmicro.com
"""

def _env_path(nombre):
    return _emp(nombre) / ".env"

def _read_env(nombre) -> dict:
    p = _env_path(nombre)
    if not p.exists(): return {"TRENDAI_API_KEY": "", "TRENDAI_REGION": "EU"}
    cfg = {}
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line: continue
        k, _, v = line.partition("=")
        cfg[k.strip()] = v.strip().strip('"').strip("'")
    return cfg

def _write_env(nombre, api_key, region="EU"):
    ed = _emp(nombre); ed.mkdir(parents=True, exist_ok=True)
    content = f"""# CREM — Configuración API TrendAI Vision One
# Generado: {datetime.now().strftime("%Y-%m-%d %H:%M")}

TRENDAI_API_KEY={api_key}
TRENDAI_REGION={region}
"""
    _env_path(nombre).write_text(content, encoding="utf-8")

def _has_api_key(nombre) -> bool:
    env = _read_env(nombre)
    return bool(env.get("TRENDAI_API_KEY","").strip())

def _api_meta(nombre) -> dict:
    meta_path = _emp(nombre) / "CSV" / ".api_meta.json"
    if not meta_path.exists(): return {}
    try: return json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception as ex:
        print(f"[WARN] .api_meta.json inválido en {meta_path} ({ex})", file=sys.stderr)
        return {}


# ── Main HTML ─────────────────────────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="es" data-theme="light">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CREM Command Center — EMPRESA / Trend Micro</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;700&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --brand-navy:#0f172a;
  --brand-crimson:#D52B1E;
  --brand-crimson-h:#b71c1c;
  --bg:#f8fafc;
  --s1:#ffffff;--s2:#f1f5f9;--s3:#e2e8f0;--s4:#cbd5e1;
  --bd:#e2e8f0;--bd2:#cbd5e1;--bd3:#94a3b8;
  --t1:#0f172a;--t2:#475569;--t3:#94a3b8;
  --green:#10B981;--amber:#F59E0B;--red:#EF4444;--purple:#8B5CF6;--blue:#2563EB;
  --font:'Plus Jakarta Sans','Inter',system-ui,-apple-system,sans-serif;
  --mono:'JetBrains Mono','Consolas',monospace;
  --r:10px;--r2:14px;--r3:18px;
  --sh:0 4px 6px -1px rgba(0,0,0,0.04),0 2px 4px -2px rgba(0,0,0,0.03);
  --sh2:0 10px 25px -5px rgba(15,23,42,0.08);
}
[data-theme="dark"]{
  --bg:#090d16;
  --s1:#111827;--s2:#1f2937;--s3:#374151;--s4:#4b5563;
  --bd:#1f2937;--bd2:#374151;--bd3:#6b7280;
  --t1:#f9fafb;--t2:#d1d5db;--t3:#9ca3af;
  --sh:0 4px 12px rgba(0,0,0,0.3);
  --sh2:0 12px 30px rgba(0,0,0,0.5);
}
html,body{background:var(--bg);color:var(--t1);font-family:var(--font);font-size:13.5px;height:100%;overflow:hidden;line-height:1.5;transition:background .2s,color .2s}
a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}

/* ── BRAND TOP ACCENT LINE ── */
.top-brand-bar{height:4px;background:var(--brand-crimson);width:100%;position:fixed;top:0;left:0;z-index:999}

/* ── ICONOS SVG ── */
.ico{display:inline-flex;align-items:center;justify-content:center;flex:none;width:1em;height:1em;line-height:0;vertical-align:-.125em}
.ico svg{width:1em;height:1em;display:block}

/* ── APP SHELL ── */
.app{display:flex;height:100vh;padding-top:4px;overflow:hidden}

/* ── SIDEBAR (NAVY CORPORATE) ── */
.sb{
  width:230px;flex-shrink:0;background:var(--brand-navy);color:#fff;
  display:flex;flex-direction:column;overflow:hidden;box-shadow:4px 0 15px rgba(0,0,0,.1);
}
.sb-logo{padding:20px 18px;border-bottom:1px solid rgba(255,255,255,.08);display:flex;align-items:center;gap:12px}
.sb-logo-mark{width:32px;height:32px;background:var(--brand-crimson);border-radius:8px;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:14px;color:#fff;box-shadow:0 2px 8px rgba(213,43,30,.4)}
.sb-logo-text{font-size:14.5px;font-weight:700;letter-spacing:-.3px;color:#fff}
.sb-logo-sub{font-size:10px;color:rgba(255,255,255,.5);font-weight:500}
.sb-scroll{flex:1;overflow-y:auto;padding:12px 0;scrollbar-width:none}
.sb-scroll::-webkit-scrollbar{display:none}
.sb-g{padding:0 10px}
.sb-lbl{font-size:10px;font-weight:700;color:rgba(255,255,255,.4);text-transform:uppercase;letter-spacing:.8px;padding:12px 10px 6px}
.ni{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:var(--r);cursor:pointer;font-size:13px;color:rgba(255,255,255,.7);transition:all .15s;margin-bottom:2px;border:1px solid transparent}
.ni:hover{background:rgba(255,255,255,.08);color:#fff}
.ni.on{background:rgba(213,43,30,.2);color:#fff;border-left:3px solid var(--brand-crimson);font-weight:600}
.ni-ico{font-size:16px;width:18px;height:18px;flex-shrink:0;color:rgba(255,255,255,.5)}
.ni.on .ni-ico{color:var(--brand-crimson)}
.ni-ct{margin-left:auto;font-size:11px;font-weight:700;background:rgba(255,255,255,.1);border-radius:10px;padding:1px 8px;color:#fff}
.sb-foot{padding:14px 18px;border-top:1px solid rgba(255,255,255,.08);font-size:11px;color:rgba(255,255,255,.5)}

/* ── MAIN CONTENT ── */
.main{flex:1;display:flex;flex-direction:column;overflow:hidden;min-width:0}
.topbar{height:54px;background:var(--s1);border-bottom:1px solid var(--bd);padding:0 24px;display:flex;align-items:center;justify-content:space-between;flex-shrink:0;box-shadow:var(--sh)}
.topbar-title{font-size:15px;font-weight:700;display:flex;align-items:center;gap:8px}

/* ── TICKER BAR ── */
.ticker-wrap{display:flex;align-items:center;gap:16px;font-size:12px;color:var(--t2);background:var(--s2);padding:4px 14px;border-radius:20px;border:1px solid var(--bd)}
.ticker-item{display:flex;align-items:center;gap:6px}
.ticker-item strong{color:var(--t1)}
.dot{width:7px;height:7px;border-radius:50%;display:inline-block}
.dot.g{background:var(--green);box-shadow:0 0 6px var(--green)}.dot.a{background:var(--amber)}.dot.r{background:var(--red)}

.topbar-right{display:flex;align-items:center;gap:12px}
.theme-btn{background:var(--s2);border:1px solid var(--bd);border-radius:50%;width:34px;height:34px;cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:16px;transition:all .15s}
.theme-btn:hover{background:var(--s3);transform:scale(1.05)}

.content{flex:1;overflow-y:auto;padding:24px;scrollbar-width:thin}
.page{display:none}.page.on{display:block;animation:fadeIn .2s ease-out}

@keyframes fadeIn{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}

/* ── CARDS & METRICS ── */
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px;margin-bottom:20px}
.kpi-card{background:var(--s1);border:1px solid var(--bd);border-radius:var(--r2);padding:16px 20px;box-shadow:var(--sh);position:relative;overflow:hidden;transition:all .15s}
.kpi-card:hover{transform:translateY(-2px);box-shadow:var(--sh2)}
.kpi-card::before{content:'';position:absolute;top:0;left:0;width:4px;height:100%;background:var(--blue)}
.kpi-card.kpi-ok::before{background:var(--green)}
.kpi-card.kpi-warn::before{background:var(--amber)}
.kpi-card.kpi-crit::before{background:var(--brand-crimson)}
.kpi-lbl{font-size:11.5px;font-weight:600;color:var(--t3);text-transform:uppercase;letter-spacing:.5px}
.kpi-val{font-size:26px;font-weight:800;font-family:var(--mono);color:var(--t1);margin:4px 0 2px}
.kpi-sub{font-size:11.5px;color:var(--t2)}

/* ── SPEEDOMETER GAUGE CARD ── */
.gauge-card{background:var(--s1);border:1px solid var(--bd);border-radius:var(--r3);padding:20px;box-shadow:var(--sh2);margin-bottom:20px;display:flex;align-items:center;gap:24px;position:relative;overflow:hidden}
.gauge-left{flex:1}
.gauge-title{font-size:16px;font-weight:700;color:var(--t1);margin-bottom:4px}
.gauge-desc{font-size:12.5px;color:var(--t2);line-height:1.5}
.gauge-wrap{position:relative;width:140px;height:90px;flex-shrink:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.gauge-ring{width:140px;height:70px}
.gauge-score{position:absolute;top:32px;font-size:26px;font-weight:800;font-family:var(--mono);color:var(--t1)}
.gauge-badge{position:absolute;bottom:0;font-size:11px;font-weight:700;padding:2px 10px;border-radius:12px}

/* ── CARDS ── */
.card{background:var(--s1);border:1px solid var(--bd);border-radius:var(--r2);overflow:hidden;margin-bottom:18px;box-shadow:var(--sh)}
.card-hdr{padding:14px 20px;border-bottom:1px solid var(--bd);background:var(--s2);display:flex;align-items:center;justify-content:space-between;gap:12px}
.card-title{font-size:12px;font-weight:700;color:var(--t2);text-transform:uppercase;letter-spacing:.5px;display:flex;align-items:center;gap:8px}
.card-title .ico{font-size:16px;color:var(--brand-crimson)}
.card-body{padding:20px}

/* ── EMPRESA GRID ── */
.emp-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px;margin-bottom:18px}
.emp-card{background:var(--s1);border:1px solid var(--bd);border-left:4px solid var(--bd2);border-radius:var(--r2);padding:16px;cursor:pointer;transition:all .15s;box-shadow:var(--sh)}
.emp-card:hover{border-color:var(--brand-crimson);transform:translateY(-2px);box-shadow:var(--sh2)}
.emp-card.sel{border-left-color:var(--brand-crimson);background:var(--s2);box-shadow:0 0 0 2px var(--brand-crimson)}
/* ── FORM CONTROLS & INPUTS ── */
.fgrid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.fgrid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px}
.fg{display:flex;flex-direction:column;gap:6px}
.lbl{font-size:12px;font-weight:600;color:var(--t2);letter-spacing:.2px}
input,select,textarea{
  background:var(--s1);
  border:1px solid var(--bd2);
  border-radius:var(--r);
  padding:9px 13px;
  color:var(--t1);
  outline:none;
  transition:all .15s ease;
  width:100%;
  font-family:var(--font);
  font-size:13px;
  box-shadow:var(--sh);
}
select{
  appearance:none;-webkit-appearance:none;
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%2394a3b8' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpolyline points='6 9 12 15 18 9'%3E%3C/polyline%3E%3C/svg%3E");
  background-repeat:no-repeat;
  background-position:right 12px center;
  padding-right:38px;
  cursor:pointer;
}
input:focus,select:focus,textarea:focus{
  border-color:var(--brand-crimson);
  box-shadow:0 0 0 3px rgba(213,43,30,.15);
  background:var(--s1);
  outline:none;
}
input::placeholder,textarea::placeholder{color:var(--t3)}
select option{background:var(--s1);color:var(--t1);padding:6px}

/* ── CUSTOM CHECKBOXES & RADIOS ── */
input[type="checkbox"]{
  appearance:none;-webkit-appearance:none;
  width:18px;height:18px;
  border:1.5px solid var(--bd3);
  border-radius:5px;
  background:var(--s1);
  cursor:pointer;
  display:inline-flex;align-items:center;justify-content:center;
  transition:all .15s ease;
  position:relative;
  flex-shrink:0;
  box-shadow:none;
  margin:0;
  vertical-align:middle;
}
input[type="checkbox"]:hover{
  border-color:var(--brand-crimson);
  background:var(--s2);
}
input[type="checkbox"]:checked{
  background:var(--brand-crimson);
  border-color:var(--brand-crimson);
  box-shadow:0 2px 6px rgba(213,43,30,.3);
}
input[type="checkbox"]:checked::after{
  content:'';
  width:4px;height:8px;
  border:solid #fff;
  border-width:0 2px 2px 0;
  transform:rotate(45deg);
  margin-bottom:2px;
}

input[type="radio"]{
  appearance:none;-webkit-appearance:none;
  width:18px;height:18px;
  border:1.5px solid var(--bd3);
  border-radius:50%;
  background:var(--s1);
  cursor:pointer;
  display:inline-flex;align-items:center;justify-content:center;
  transition:all .15s ease;
  position:relative;
  flex-shrink:0;
  box-shadow:none;
}
input[type="radio"]:checked{
  border-color:var(--brand-crimson);
  background:var(--s1);
}
input[type="radio"]:checked::after{
  content:'';
  width:8px;height:8px;
  border-radius:50%;
  background:var(--brand-crimson);
}

/* ── NUMBER CONTROL STEPPERS (+ / -) ── */
.nc-wrap{display:inline-flex;align-items:center;background:var(--s1);border:1px solid var(--bd2);border-radius:var(--r);box-shadow:var(--sh);overflow:hidden;transition:border-color .15s}
.nc-wrap:focus-within,.nc-wrap:hover{border-color:var(--brand-crimson)}
.nc-btn{
  background:var(--s2);
  border:none;
  color:var(--t1);
  width:32px;height:34px;
  cursor:pointer;
  font-size:15px;font-weight:700;
  display:flex;align-items:center;justify-content:center;
  transition:all .15s;
  user-select:none;
  flex-shrink:0;
}
.nc-btn:hover{background:var(--brand-crimson);color:#fff}
.nc-input{
  border:none!important;
  box-shadow:none!important;
  text-align:center;
  font-family:var(--mono);
  font-weight:700;
  width:50px!important;
  height:34px;
  padding:0!important;
  border-left:1px solid var(--bd)!important;
  border-right:1px solid var(--bd)!important;
  border-radius:0!important;
}

/* ── RESPONSIVE DESIGN ── */
@media(max-width:960px){
  .sb{width:70px}
  .sb-logo-text,.sb-logo-sub,.sb-lbl,.ni span:not(.ni-ico),.sb-foot,.ni-ct{display:none}
  .sb-logo{padding:14px;justify-content:center}
  .ni{justify-content:center;padding:12px 0}
  .fgrid,.fgrid3{grid-template-columns:1fr}
  .gauge-card{flex-direction:column;align-items:flex-start}
  .ticker-wrap{display:none}
}
@media(max-width:640px){
  .topbar{padding:0 14px}
  .content{padding:14px}
  .kpi-grid{grid-template-columns:1fr 1fr}
  .emp-grid{grid-template-columns:1fr}
}

/* ── DRAG & DROP OVERLAY ── */
.drop-overlay{position:fixed;inset:0;background:rgba(15,23,42,.85);backdrop-filter:blur(8px);z-index:9999;display:none;align-items:center;justify-content:center;padding:40px}
.drop-overlay.on{display:flex;animation:fadeIn .15s ease-out}
.drop-box{border:3px dashed var(--brand-crimson);border-radius:var(--r3);background:rgba(213,43,30,.08);padding:50px 40px;text-align:center;color:#fff;max-width:500px;width:100%;box-shadow:0 0 40px rgba(213,43,30,.3)}
.drop-ico{font-size:48px;color:var(--brand-crimson);margin-bottom:12px}
.drop-title{font-size:18px;font-weight:700;margin-bottom:6px}
.drop-sub{font-size:12.5px;color:rgba(255,255,255,.7)}

/* ── BUTTONS ── */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:9px 18px;border-radius:var(--r);font-size:13px;font-weight:600;cursor:pointer;border:1px solid transparent;transition:all .15s;white-space:nowrap;font-family:var(--font)}
.btn-primary{background:var(--brand-crimson);color:#fff;border-color:var(--brand-crimson);box-shadow:0 2px 8px rgba(213,43,30,.3)}
.btn-primary:hover{background:var(--brand-crimson-h);transform:translateY(-1px)}
.btn-secondary{background:var(--s1);color:var(--t1);border-color:var(--bd);box-shadow:var(--sh)}
.btn-secondary:hover{background:var(--s2);border-color:var(--bd2)}
.btn-ghost{background:none;color:var(--t2);border-color:transparent}
.btn-ghost:hover{color:var(--t1);background:var(--s2)}
.btn-sm{padding:6px 12px;font-size:12px}
.btn:disabled{opacity:.4;cursor:not-allowed}

/* ── BADGES ── */
.inv-tbl th{background:var(--s3);padding:7px 12px;font-size:10.5px;font-weight:700;color:var(--t2);text-transform:uppercase;letter-spacing:.4px;text-align:left;border-bottom:1px solid var(--bd)}
.inv-tbl td{padding:7px 12px;border-bottom:1px solid var(--bd);vertical-align:middle}
.inv-tbl tr:last-child td{border-bottom:none}
.inv-tbl tr:hover td{background:var(--s2)}
.inp-inv{background:transparent;border:1px solid transparent;border-radius:5px;padding:3px 7px;color:var(--t1);width:100%;transition:all .12s;font-family:var(--font);font-size:12.5px}
.inp-inv:hover{border-color:var(--bd2);background:var(--s3)}
.inp-inv:focus{border-color:var(--red);background:#fff;outline:none;box-shadow:0 0 0 2px rgba(214,48,49,.1)}
.sel-crit{background:#fff;border:1px solid var(--bd2);border-radius:5px;padding:3px 8px;color:var(--t1);cursor:pointer;font-size:12px;font-family:var(--font)}

/* ── TEMPLATE SELECTOR ── */
.tpl-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:16px}
.tpl-card{background:#fff;border:1px solid var(--bd2);border-radius:var(--r2);padding:16px;cursor:pointer;transition:all .15s;text-align:center;position:relative;box-shadow:var(--sh)}
.tpl-card:hover{border-color:var(--red-b);background:var(--red-s);transform:translateY(-1px);box-shadow:var(--sh2)}
.tpl-card.sel{border-color:var(--red);background:var(--red-s)}
.tpl-card.sel::after{content:'✓';position:absolute;top:10px;right:12px;color:var(--red);font-weight:700}
.tpl-ico{font-size:26px;margin-bottom:10px;color:var(--red);display:flex;justify-content:center}
.tpl-card .tpl-ico .ico{font-size:26px}
.tpl-name{font-size:13px;font-weight:700;margin-bottom:4px}
.tpl-desc{font-size:11.5px;color:var(--t3);line-height:1.5}
.tpl-files{display:flex;gap:5px;justify-content:center;flex-wrap:wrap;margin-top:8px}
.tpl-file{font-size:10px;background:var(--s4);border:1px solid var(--bd2);border-radius:20px;padding:2px 8px;color:var(--t2)}

/* ── PROGRESS ── */
.prog-bar-wrap{background:var(--s4);border-radius:6px;height:6px;overflow:hidden;margin:12px 0}
.prog-bar{height:100%;background:linear-gradient(90deg,var(--red),#ff7b7b);border-radius:6px;transition:width .4s cubic-bezier(.4,0,.2,1)}
.steps{display:flex;gap:5px;flex-wrap:wrap;margin:10px 0}
.step{font-size:11.5px;padding:4px 11px;border-radius:20px;background:var(--s3);color:var(--t2);border:1px solid var(--bd2);transition:all .2s;display:inline-flex;align-items:center;gap:4px}
.step.active{background:var(--red-s);color:var(--red);border-color:var(--red-b);font-weight:600;animation:pulse 1.4s infinite}
.step.done{background:rgba(21,128,61,.08);color:var(--green);border-color:rgba(21,128,61,.2)}
.step.done::before{content:'✓ '}
@keyframes pulse{0%,100%{opacity:1;box-shadow:0 0 0 0 rgba(214,48,49,.3)}60%{opacity:.75;box-shadow:0 0 0 5px rgba(214,48,49,0)}}

/* ── LOG ── */
.log{background:#13161f;border:1px solid rgba(255,255,255,.06);border-radius:var(--r);padding:14px;font-family:var(--mono);font-size:12px;line-height:1.9;max-height:300px;overflow-y:auto;scrollbar-width:thin;scrollbar-color:#2a3045 transparent}
.log::-webkit-scrollbar{width:4px}.log::-webkit-scrollbar-thumb{background:#2a3045;border-radius:2px}
.ll{display:flex;gap:8px;animation:fdin .16s ease}
@keyframes fdin{from{opacity:0;transform:translateY(3px)}to{opacity:1;transform:none}}
.lt{color:#3d4f6e;flex-shrink:0;font-size:10.5px;padding-top:1px}
.lok{color:#4ade80}.lwarn{color:#fbbf24}.lerr{color:#f87171}.linfo{color:#60a5fa}.lplain{color:#8894aa}

/* ── RESULT ── */
.result{background:rgba(21,128,61,.03);border:1px solid rgba(21,128,61,.18);border-radius:var(--r2);padding:18px;margin-top:14px}
.result-hdr{display:flex;align-items:center;gap:10px;margin-bottom:4px}
.res-files{display:flex;flex-direction:column;gap:7px;margin-top:12px}
.res-file{display:flex;align-items:center;justify-content:space-between;background:#fff;border:1px solid var(--bd2);box-shadow:var(--sh);border-radius:var(--r);padding:10px 16px;transition:border-color .12s}
.res-file:hover{border-color:var(--bd3)}
.res-file-name{font-family:var(--mono);font-size:12px;color:var(--t1);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:350px}

/* ── CSV TABLE ── */
.csv-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:8px}
.csv-row{display:flex;align-items:center;justify-content:space-between;background:#fff;border:1px solid var(--bd2);box-shadow:var(--sh);border-radius:var(--r);padding:10px 14px}
.csv-name{font-family:var(--mono);font-size:12px}
.csv-meta{font-size:11px;color:var(--t3);margin-top:2px}

/* ── HIST ── */
.hist-row{display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--bd);transition:background .12s}
.hist-row:last-child{border-bottom:none}
.hist-row:hover{background:var(--s2)}
.hist-emp{font-weight:700;font-size:13.5px}
.hist-mes{font-size:13px;color:var(--t1);font-weight:600}
.hist-path{font-size:10.5px;color:var(--t3);font-family:var(--mono);margin-top:3px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:420px}

/* ── GEN FOOTER ── */
.gen-foot{background:var(--s1);border-top:1px solid var(--bd2);box-shadow:0 -2px 8px rgba(0,0,0,.05);padding:14px 22px;display:flex;align-items:center;justify-content:space-between;flex-shrink:0;gap:16px}
.gen-sum{font-size:13px;color:var(--t2)}
.gen-sum strong{color:var(--t1);font-weight:600}

/* ── UTILS ── */
.divider{height:1px;background:var(--bd);margin:16px 0}
.sec-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}
.sec-ttl{font-size:13px;font-weight:600}
.empty{text-align:center;padding:32px;color:var(--t3);font-size:13px}
.empty-ico{font-size:30px;margin-bottom:10px;color:var(--t3);display:flex;justify-content:center}
.empty-ico .ico{font-size:30px}
.date-mode-btn{flex:1;padding:6px 12px;border-radius:var(--r);font-size:12px;font-weight:500;cursor:pointer;border:1px solid var(--bd2);background:#fff;color:var(--t2);transition:all .15s;font-family:var(--font)}
.date-mode-btn:hover{background:var(--s3);color:var(--t1)}
.date-mode-btn.on{background:var(--red);color:#fff;border-color:var(--red);box-shadow:0 2px 6px rgba(214,48,49,.25)}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.one-col{display:grid;grid-template-columns:1fr;gap:16px}
.three-col{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}
.warn-box{background:rgba(180,83,9,.06);border:1px solid rgba(180,83,9,.2);border-radius:var(--r);padding:10px 14px;font-size:12.5px;color:var(--amber);margin-bottom:12px}
.info-box{background:rgba(29,78,216,.06);border:1px solid rgba(29,78,216,.18);border-radius:var(--r);padding:10px 14px;font-size:12.5px;color:var(--blue);margin-bottom:12px}
.toast{position:fixed;bottom:18px;right:18px;z-index:9999;background:#fff;border:1px solid var(--bd2);border-radius:var(--r);padding:10px 16px;font-size:13px;box-shadow:0 8px 24px rgba(0,0,0,.12);display:none;animation:fdin .2s ease}

.api-status{display:flex;align-items:center;gap:8px;padding:10px 14px;border-radius:var(--r);border:1px solid;margin-bottom:12px;font-size:13px;font-weight:500}
.api-status.ok{background:rgba(21,128,61,.05);border-color:rgba(21,128,61,.2);color:var(--green)}
.api-status.err{background:rgba(214,48,49,.05);border-color:rgba(214,48,49,.2);color:var(--red)}
.api-status.warn{background:rgba(180,83,9,.05);border-color:rgba(180,83,9,.2);color:var(--amber)}
.api-key-input{font-family:var(--mono);letter-spacing:.5px}
.region-btn{padding:6px 14px;border-radius:var(--r);font-size:12px;font-weight:600;cursor:pointer;border:1px solid var(--bd2);background:#fff;color:var(--t2);transition:all .13s;font-family:var(--font)}
.region-btn:hover{border-color:var(--red-b);color:var(--red)}
.region-btn.on{background:var(--red);color:#fff;border-color:var(--red)}
.tpl-badge{display:inline-block;font-size:10px;font-weight:700;padding:1px 7px;border-radius:9px;vertical-align:middle}
.tpl-badge-green{background:rgba(21,128,61,.1);color:var(--green);border:1px solid rgba(21,128,61,.2)}
.tpl-badge-warn{background:rgba(180,83,9,.09);color:var(--amber);border:1px solid rgba(180,83,9,.2)}
@media(max-width:900px){.two-col,.three-col,.tpl-grid,.fgrid,.fgrid3{grid-template-columns:1fr}.sb{width:180px}}
</style>
</head>
<body>
<div class="app">

<!-- ── SIDEBAR ── -->
<nav class="sb">
  <div class="sb-logo">
    <div class="sb-logo-mark">D</div>
    <div><div class="sb-logo-text">CREM</div><div class="sb-logo-ver">by EMPRESA</div></div>
  </div>
  <div class="sb-scroll">
    <div class="sb-g">
      <div class="sb-lbl">Generación</div>
      <div class="ni on" id="n-gen" onclick="go('pg-gen','n-gen')"><span class="ni-ico" data-i="zap"></span>Generar informe</div>
      <div class="ni" id="n-hist" onclick="go('pg-hist','n-hist')"><span class="ni-ico" data-i="list"></span>Histórico</div>
      <div class="sb-div"></div>
      <div class="sb-lbl">Configuración</div>
      <div class="ni" id="n-cfg" onclick="go('pg-cfg','n-cfg')"><span class="ni-ico" data-i="gear"></span>Empresa</div>
      <div class="ni" id="n-inv" onclick="go('pg-inv','n-inv')"><span class="ni-ico" data-i="box"></span>Inventario activos</div>
      <div class="ni" id="n-sla" onclick="go('pg-sla','n-sla')"><span class="ni-ico" data-i="sliders"></span>SLAs y módulos</div>
      <div class="sb-div"></div>
      <div class="sb-lbl">Diagnóstico</div>
      <div class="ni" id="n-csv" onclick="go('pg-csv','n-csv')"><span class="ni-ico" data-i="database"></span>Estado CSVs</div>
      <div class="ni" id="n-api" onclick="go('pg-api','n-api')"><span class="ni-ico" data-i="server"></span>Conexión API</div>
      <div class="ni" id="n-about" onclick="go('pg-about','n-about')"><span class="ni-ico" data-i="info"></span>Acerca de</div>
    </div>
  </div>
  <div class="sb-foot">
    <strong>v4.1 — CREM Dashboard</strong>
    localhost:5001
  </div>
</nav>

<!-- ── MAIN ── -->
<div class="main">
  <div class="topbar">
    <span class="topbar-title" id="pg-title">Generar Informe</span>
    <div class="topbar-right">
      <span id="emp-tag" class="tbtag">Sin empresa seleccionada</span>
      <span class="tbtag ok">● Activo</span>
    </div>
  </div>

  <div class="content">

    <!-- ══ GENERAR ══ -->
    <div class="page on" id="pg-gen">

      <!-- Empresa -->
      <div class="card">
        <div class="card-hdr">
          <div class="card-title"><span data-i="building"></span> Empresa cliente</div>
          <button class="btn btn-ghost btn-sm" onclick="loadEmpresas()"><span data-i="refresh"></span></button>
        </div>
        <div class="card-body">
          <div class="emp-grid" id="emp-grid"><div class="empty"><div class="empty-ico" data-i="loader"></div>Cargando…</div></div>
          <div style="display:flex;gap:8px;align-items:center">
            <input type="text" id="new-emp" placeholder="Escribe el nombre de una nueva empresa y pulsa Crear" style="flex:1">
            <button class="btn btn-secondary btn-sm" onclick="crearEmpresa()"><span data-i="plus"></span> Crear</button>
          </div>
        </div>
      </div>

      <!-- Plantilla + Período -->
      <div class="card">
        <div class="card-hdr"><div class="card-title"><span data-i="file"></span> Plantilla de informe</div></div>
        <div class="card-body">
          <div class="tpl-grid" id="tpl-grid">
            <div class="tpl-card" onclick="selectTpl(this,'tecnico')">
              <div class="tpl-ico" data-i="file"></div>
              <div class="tpl-name">Técnica</div>
              <div class="tpl-desc">Detalle completo — tablas, CVEs, Detail info, filtros avanzados</div>
              <div class="tpl-files">
                <span class="tpl-file">Word</span>
                <span class="tpl-file">HTML dark</span>
              </div>
            </div>
            <div class="tpl-card" onclick="selectTpl(this,'ejecutivo')">
              <div class="tpl-ico" data-i="chart"></div>
              <div class="tpl-name">Ejecutiva</div>
              <div class="tpl-desc">Lenguaje de negocio — KPIs, gráficos, tendencias, sin tecnicismos</div>
              <div class="tpl-files">
                <span class="tpl-file">HTML light</span>
              </div>
            </div>
            <div class="tpl-card sel" onclick="selectTpl(this,'ambos')">
              <div class="tpl-ico" data-i="layers"></div>
              <div class="tpl-name">Ambas</div>
              <div class="tpl-desc">Genera técnica + ejecutiva en un solo paso</div>
              <div class="tpl-files">
                <span class="tpl-file">Word</span>
                <span class="tpl-file">PDF</span>
                <span class="tpl-file">×2 HTML</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Fuente de datos -->
      <div class="card">
        <div class="card-hdr"><div class="card-title"><span data-i="cloud"></span> Fuente de datos</div></div>
        <div class="card-body">
          <div class="tpl-grid" id="src-grid">
            <div class="tpl-card" id="src-api-card" onclick="selectSrc(this,'api')">
              <div class="tpl-ico" data-i="cloud"></div>
              <div class="tpl-name" style="display:flex;align-items:center;gap:7px;justify-content:center">API Vision One <span class="tpl-badge tpl-badge-green" id="src-api-badge" style="display:none">Activa</span><span class="tpl-badge tpl-badge-warn" id="src-api-badge-warn" style="display:none">Sin key</span></div>
              <div class="tpl-desc">Descarga los datos del mes automáticamente desde Vision One antes de generar</div>
              <div id="src-api-hint" style="font-size:11px;margin-top:7px;color:var(--t3)">Selecciona una empresa para ver el estado</div>
            </div>
            <div class="tpl-card sel" id="src-csv-card" onclick="selectSrc(this,'csv')">
              <div class="tpl-ico" data-i="folder"></div>
              <div class="tpl-name">CSVs descargados</div>
              <div class="tpl-desc">Usa los archivos CSV descargados del portal (obtiene Cyber Risk Index de API si existe key)</div>
              <div id="src-csv-hint" style="font-size:11px;margin-top:7px;color:var(--t3)">Selecciona una empresa para ver el estado</div>
            </div>
          </div>
        </div>
      </div>


      <!-- Período + opciones -->
      <div class="one-col">
        <div class="card">
          <div class="card-hdr"><div class="card-title"><span data-i="calendar"></span> Período del informe</div></div>
          <div class="card-body">
            <!-- Modo de selección -->
            <div style="display:flex;gap:6px;margin-bottom:12px">
              <button class="date-mode-btn on" id="dmode-preset" onclick="setDateMode('preset')">Recientes</button>
              <button class="date-mode-btn" id="dmode-custom" onclick="setDateMode('custom')">Personalizar</button>
            </div>
            <!-- Selector desplegable (últimos 18 meses) -->
            <div id="date-preset-wrap" class="fg" style="margin-bottom:14px">
              <label class="lbl">Mes del informe</label>
              <select id="mes-sel" onchange="updateSummary()"></select>
            </div>
            <!-- Selector personalizado -->
            <div id="date-custom-wrap" style="display:none;margin-bottom:14px">
              <label class="lbl" style="margin-bottom:6px;display:block">Mes y año del informe</label>
              <div style="display:grid;grid-template-columns:1fr 1fr auto;gap:8px;align-items:end">
                <div class="fg">
                  <label class="lbl" style="font-size:10.5px">Mes</label>
                  <select id="mes-custom-m" onchange="buildCustomDate()">
                    <option value="Enero">Enero</option><option value="Febrero">Febrero</option>
                    <option value="Marzo">Marzo</option><option value="Abril">Abril</option>
                    <option value="Mayo">Mayo</option><option value="Junio">Junio</option>
                    <option value="Julio">Julio</option><option value="Agosto">Agosto</option>
                    <option value="Septiembre">Septiembre</option><option value="Octubre">Octubre</option>
                    <option value="Noviembre">Noviembre</option><option value="Diciembre">Diciembre</option>
                  </select>
                </div>
                <div class="fg">
                  <label class="lbl" style="font-size:10.5px">Año</label>
                  <input type="number" id="mes-custom-y" min="2020" max="2035" placeholder="2026" onchange="buildCustomDate()" oninput="buildCustomDate()">
                </div>
                <div class="fg">
                  <label class="lbl" style="font-size:10.5px;opacity:0">OK</label>
                  <div id="custom-date-badge" style="padding:8px 12px;background:var(--s3);border:1px solid var(--bd2);border-radius:var(--r);font-size:12.5px;font-weight:600;color:var(--t1);white-space:nowrap">—</div>
                </div>
              </div>
            </div>
            <div class="trow">
              <div class="tinfo"><div class="tname">Solo regenerar</div><div class="tdesc">Usa caché .pkl — no relee los CSVs</div></div>
              <label class="sw"><input type="checkbox" id="sw-solo"><span class="sw-track"></span></label>
            </div>
            <div class="trow">
              <div class="tinfo"><div class="tname">Generar Excel de revisión</div><div class="tdesc">Exporta cada módulo como .xlsx</div></div>
              <label class="sw"><input type="checkbox" id="sw-excel"><span class="sw-track"></span></label>
            </div>
            <div class="trow">
              <div class="tinfo"><div class="tname">Abrir al terminar</div><div class="tdesc">Abre automáticamente los informes generados</div></div>
              <label class="sw"><input type="checkbox" id="sw-abrir" checked><span class="sw-track"></span></label>
            </div>
            <div class="info-box" style="margin:4px 0 0;display:flex;align-items:center;gap:7px"><span data-i="checkc"></span> Los CVEs se enriquecen siempre con su solución (NVD · CISA KEV · EPSS)</div>
            <div class="trow">
              <div class="tinfo"><div class="tname">Riesgo CREM manual</div><div class="tdesc">Sobreescribe el score automático si difiere del portal Vision One (0-100)</div></div>
              <div style="display:flex;gap:6px;align-items:center">
                <input type="number" id="riesgo-crem-manual" min="0" max="100" step="0.1" placeholder="Auto" style="width:80px;padding:6px 8px;background:var(--s3);border:1px solid var(--bd2);border-radius:var(--r);color:var(--t1);font-size:13px">
                <button class="btn btn-secondary btn-sm" id="btn-fetch-risk-index" onclick="fetchRiskIndexFromApi()" title="Obtener Cyber Risk Index actual desde Vision One API"><span data-i="zap"></span> Obtener de API</button>
              </div>
            </div>

          </div>
        </div>
      </div>

      <!-- Progress -->
      <div class="card" id="prog-card" style="display:none">
        <div class="card-hdr">
          <div class="card-title" id="prog-title"><span data-i="loader"></span> Generando…</div>
          <span id="prog-pct" style="font-size:12px;color:var(--t3)">0%</span>
        </div>
        <div class="card-body">
          <div class="steps" id="steps"></div>
          <div class="prog-bar-wrap"><div class="prog-bar" id="prog-bar" style="width:0%"></div></div>
          <div class="log" id="log"></div>
        </div>
      </div>

      <!-- Result -->
      <div class="result" id="result" style="display:none">
        <div style="font-weight:700;font-size:14px;color:var(--green);margin-bottom:4px;display:flex;align-items:center;gap:7px"><span data-i="checkc"></span> Informe generado</div>
        <div id="res-sum" style="font-size:13px;color:var(--t2);margin-bottom:8px"></div>
        <div id="res-files" class="res-files"></div>
      </div>
    </div>

    <!-- ══ HISTÓRICO ══ -->
    <div class="page" id="pg-hist">
      <div class="card">
        <div class="card-hdr"><div class="card-title"><span data-i="list"></span> Informes generados</div><button class="btn btn-ghost btn-sm" onclick="loadHist()"><span data-i="refresh"></span></button></div>
        <div class="card-body" style="padding:0 18px"><div id="hist-list"><div class="empty"><div class="empty-ico" data-i="loader"></div>Cargando…</div></div></div>
      </div>
    </div>

    <!-- ══ CONFIGURACIÓN EMPRESA ══ -->
    <div class="page" id="pg-cfg">
      <div class="card">
        <div class="card-hdr">
          <div class="card-title"><span data-i="gear"></span> Configuración de empresa</div>
          <div style="display:flex;gap:8px">
            <select id="cfg-sel" style="width:160px" onchange="loadCfg()"><option value="">Selecciona…</option></select>
            <button class="btn btn-primary btn-sm" onclick="saveCfg()"><span data-i="save"></span> Guardar</button>
          </div>
        </div>
        <div class="card-body" id="cfg-body"><div class="empty"><div class="empty-ico" data-i="gear"></div>Selecciona una empresa</div></div>
      </div>
    </div>

    <!-- ══ INVENTARIO ══ -->
    <div class="page" id="pg-inv">
      <div class="card">
        <div class="card-hdr">
          <div class="card-title"><span data-i="box"></span> Inventario de activos</div>
          <div style="display:flex;gap:8px">
            <select id="inv-sel" style="width:160px" onchange="loadInv()"><option value="">Selecciona…</option></select>
            <button class="btn btn-secondary btn-sm" onclick="addInvRow()"><span data-i="plus"></span> Activo</button>
            <button class="btn btn-primary btn-sm" onclick="saveInv()"><span data-i="save"></span> Guardar</button>
          </div>
        </div>
        <div class="card-body" style="padding:0">
          <div class="info-box" style="margin:14px 18px 0;font-size:12px">
            Etiqueta cada equipo para que aparezca destacado en los informes con su nivel de criticidad.
          </div>
          <div id="inv-body" style="overflow-x:auto"><div class="empty"><div class="empty-ico" data-i="box"></div>Selecciona una empresa</div></div>
        </div>
      </div>
    </div>

    <!-- ══ SLAs ══ -->
    <div class="page" id="pg-sla">
      <div class="card">
        <div class="card-hdr">
          <div class="card-title"><span data-i="sliders"></span> SLAs y módulos</div>
          <div style="display:flex;gap:8px">
            <select id="sla-sel" style="width:160px" onchange="loadSla()"><option value="">Selecciona…</option></select>
            <button class="btn btn-primary btn-sm" onclick="saveSla()"><span data-i="save"></span> Guardar</button>
          </div>
        </div>
        <div class="card-body" id="sla-body"><div class="empty"><div class="empty-ico" data-i="sliders"></div>Selecciona una empresa</div></div>
      </div>
    </div>


    <!-- ══ API TRENDAI ══ -->
    <div class="page" id="pg-api">
      <div class="card">
        <div class="card-hdr">
          <div class="card-title"><span data-i="server"></span> Conexión API TrendAI Vision One</div>
          <div style="display:flex;gap:8px">
            <select id="api-emp-sel" style="width:160px" onchange="loadApiPage()"><option value="">Selecciona…</option></select>
          </div>
        </div>
        <div class="card-body" id="api-body">
          <div class="empty"><div class="empty-ico" data-i="server"></div>Selecciona una empresa para configurar la API</div>
        </div>
      </div>

      <!-- Fetch card (hidden until empresa selected) -->
      <div class="card" id="api-fetch-card" style="display:none">
        <div class="card-hdr">
          <div class="card-title"><span data-i="download"></span> Obtener datos de la API</div>
          <span id="api-fetch-status" class="badge b-gray">Listo</span>
        </div>
        <div class="card-body">
          <div class="info-box" style="margin-bottom:14px">
            Esto reemplaza la descarga manual de CSVs desde TrendAI — obtiene los datos directamente de la API
            y los guarda en <code style="font-size:11px;background:rgba(0,0,0,.06);padding:1px 6px;border-radius:4px">[EMPRESA]/CSV/</code>
          </div>
          <div class="fgrid" style="gap:12px;margin-bottom:14px">
            <div class="fg">
              <label class="lbl">Período a descargar</label>
              <select id="api-mes-sel"></select>
            </div>
            <div class="fg" style="justify-content:flex-end;align-items:flex-end">
              <button class="btn btn-primary" id="btn-api-fetch" onclick="apiFetch()" style="width:100%">
                <span data-i="download"></span> Obtener datos de la API
              </button>
            </div>
          </div>

          <!-- Fetch progress -->
          <div id="api-prog-wrap" style="display:none">
            <div class="steps" id="api-steps"></div>
            <div class="prog-bar-wrap"><div class="prog-bar" id="api-prog-bar" style="width:0%"></div></div>
            <div class="log" id="api-log" style="max-height:200px;margin-top:8px"></div>
          </div>

          <!-- Last fetch info -->
          <div id="api-last-fetch" style="display:none;margin-top:12px;padding:10px 14px;background:rgba(21,128,61,.05);border:1px solid rgba(21,128,61,.15);border-radius:var(--r)">
            <div style="font-size:12px;font-weight:600;color:var(--green);margin-bottom:6px;display:flex;align-items:center;gap:6px"><span data-i="checkc"></span> Última extracción</div>
            <div id="api-last-fetch-detail" style="font-size:12px;color:var(--t2)"></div>
          </div>
        </div>
      </div>
    </div>

    <!-- ══ CSV STATUS ══ -->
    <div class="page" id="pg-csv">
      <div class="card">
        <div class="card-hdr">
          <div class="card-title"><span data-i="database"></span> Estado de CSVs</div>
          <div style="display:flex;gap:8px">
            <select id="csv-sel" style="width:160px" onchange="loadCsvStatus()"><option value="">Selecciona…</option></select>
            <button class="btn btn-ghost btn-sm" onclick="loadCsvStatus()"><span data-i="refresh"></span></button>
          </div>
        </div>
        <div class="card-body" id="csv-body"><div class="empty"><div class="empty-ico" data-i="database"></div>Selecciona una empresa</div></div>
      </div>
    </div>

    <!-- ══ ABOUT ══ -->
    <div class="page" id="pg-about">
      <div class="card">
        <div class="card-hdr"><div class="card-title"><span data-i="info"></span> Acerca de CREM Dashboard</div></div>
        <div class="card-body">
          <div style="font-size:13px;color:var(--t2);display:flex;flex-direction:column;gap:10px">
            <div>Script: <code id="ab-script" style="background:var(--s2);padding:2px 8px;border-radius:5px;font-family:var(--mono);font-size:11.5px"></code></div>
            <div>Directorio: <code id="ab-dir" style="background:var(--s2);padding:2px 8px;border-radius:5px;font-family:var(--mono);font-size:11.5px"></code></div>
            <div>Servidor: <span style="color:var(--green)">● Activo en http://localhost:5001</span></div>
          </div>
          <div class="divider"></div>
          <div style="font-size:12px;font-weight:600;color:var(--t2);margin-bottom:10px;display:flex;align-items:center;gap:6px"><span data-i="folder"></span> Estructura de carpetas</div>
          <pre style="background:var(--bg);border:1px solid var(--bd);border-radius:var(--r);padding:14px;font-family:var(--mono);font-size:12px;color:var(--t2);line-height:1.9">[EMPRESA]/
├── config.json
├── CSV/                ← CSVs del mes actual (8 archivos TrendAI)
└── INFORMES/
    ├── CSV/csv-mes-año/← Histórico + caché .pkl
    └── Mes_Año/        ← Word + PDF + HTML</pre>
        </div>
      </div>
    </div>

  </div><!-- /content -->

  <!-- GEN FOOTER -->
  <div class="gen-foot" id="gen-foot">
    <div class="gen-sum">
      Empresa: <strong id="sum-emp">—</strong> &nbsp;·&nbsp;
      Período: <strong id="sum-mes">—</strong> &nbsp;·&nbsp;
      Plantilla: <strong id="sum-tpl">—</strong> &nbsp;·&nbsp;
      Fuente: <strong id="sum-src">API</strong>
    </div>
    <div style="display:flex;gap:8px">
      <button class="btn btn-secondary" id="btn-reset" onclick="resetGen()" style="display:none"><span data-i="rotate"></span> Nueva</button>
      <button class="btn btn-secondary btn-lg" id="btn-gen-test" onclick="generate(true)" title="Genera en PRUEBAS/ sin tocar el histórico"><span data-i="flask"></span> Generar prueba</button>
      <button class="btn btn-primary btn-lg" id="btn-gen" onclick="generate()"><span data-i="zap"></span> Generar informe</button>
    </div>
  </div>
</div><!-- /main -->
</div><!-- /app -->

<div id="toast" class="toast"></div>

<script>
'use strict';
// ── Iconos SVG (estilo lineal, currentColor) — sustituyen a todos los emojis ──
const ICO_P = {
  zap:'<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
  list:'<line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/>',
  clock:'<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
  gear:'<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
  sliders:'<line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/>',
  target:'<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>',
  cloud:'<path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/>',
  server:'<rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/>',
  info:'<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>',
  building:'<path d="M3 21h18"/><path d="M5 21V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2v16"/><line x1="9" y1="7" x2="9" y2="7"/><line x1="9" y1="11" x2="9" y2="11"/><line x1="15" y1="7" x2="15" y2="7"/><line x1="15" y1="11" x2="15" y2="11"/><path d="M9 21v-4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v4"/>',
  briefcase:'<rect x="2" y="7" width="20" height="14" rx="2" ry="2"/><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/>',
  file:'<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><line x1="10" y1="9" x2="8" y2="9"/>',
  chart:'<line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/>',
  layers:'<polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/>',
  calendar:'<rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/>',
  folder:'<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>',
  box:'<path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/>',
  database:'<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>',
  plus:'<line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>',
  save:'<path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/>',
  refresh:'<polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>',
  rotate:'<polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/>',
  play:'<polygon points="5 3 19 12 5 21 5 3"/>',
  download:'<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>',
  edit:'<path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.12 2.12 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>',
  search:'<circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
  check:'<polyline points="20 6 9 17 4 12"/>',
  checkc:'<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>',
  xc:'<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>',
  x:'<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
  loader:'<line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"/><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"/><line x1="2" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="22" y2="12"/><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"/><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"/>',
  inbox:'<polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/>',
  shield:'<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
  alert:'<path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
  chevron:'<polyline points="9 18 15 12 9 6"/>',
  ext:'<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>',
  key:'<path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>',
  eye:'<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>',
  flask:'<path d="M9 3v6.34a2 2 0 0 1-.34 1.12L4.2 17.5A2 2 0 0 0 5.86 21h12.28a2 2 0 0 0 1.66-3.5l-4.46-6.04A2 2 0 0 1 15 9.34V3"/><line x1="8" y1="3" x2="16" y2="3"/><line x1="7" y1="14" x2="17" y2="14"/>',
  folderopen:'<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>',
};
function svg(n){ return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'+(ICO_P[n]||'')+'</svg>'; }
function icon(n){ return '<span class="ico">'+svg(n)+'</span>'; }
function dot(c){ return '<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:'+c+';margin-right:7px;vertical-align:middle;flex:none"></span>'; }
function hydrateIcons(root){ (root||document).querySelectorAll('[data-i]').forEach(e=>{ if(e.dataset.done)return; e.classList.add('ico'); e.innerHTML=svg(e.dataset.i); e.dataset.done='1'; }); }

// ── State ─────────────────────────────────────────────────────────────────
let selEmp = null, selTpl = 'ambos', selSrc = 'csv';
let invRows = [], cfgCache = {};
let es = null;
const STEPS_API = ['Descargando API','Cargando CSVs','Comparando CVEs','Generando docs','Archivando'];
const STEPS_CSV = ['Cargando CSVs','Comparando CVEs','Generando docs','Generando HTML','Archivando'];
let STEPS = STEPS_CSV;

const MODULOS = ['cve-events','cve-assets','threat-detections','anomaly-detections',
                 'security-conf','sys-conf','cloud-app','account-compromise'];
const CRIT_OPTS = [
  {val:'MUY CRITICO',label:'Muy crítico'},{val:'CRITICO',label:'Crítico'},
  {val:'NORMAL',label:'Normal'},{val:'NO CRITICO',label:'No crítico'},{val:'',label:'Sin catalogar'}
];
const TITLES = {
  'pg-gen':'Generar Informe','pg-hist':'Histórico',
  'pg-cfg':'Configuración de Empresa','pg-inv':'Inventario de Activos',
  'pg-sla':'SLAs y Módulos','pg-csv':'Estado de CSVs',
  'pg-api':'Conexión API TrendAI','pg-about':'Acerca de'
};

// ── Init ──────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  hydrateIcons();
  loadEmpresas(); loadMeses(); loadAbout();
  document.getElementById('gen-foot').style.display = 'flex';
});

// ── Nav ───────────────────────────────────────────────────────────────────
function go(page, navId) {
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('on'));
  document.querySelectorAll('.ni').forEach(n=>n.classList.remove('on'));
  document.getElementById(page).classList.add('on');
  document.getElementById(navId).classList.add('on');
  document.getElementById('pg-title').textContent = TITLES[page] || '';
  document.getElementById('gen-foot').style.display = page === 'pg-gen' ? 'flex' : 'none';
  if (page === 'pg-hist') loadHist();
  if (page === 'pg-cfg')  { populateSels(); if(selEmp){document.getElementById('cfg-sel').value=selEmp;loadCfg();} }
  if (page === 'pg-inv')  { populateSels(); if(selEmp){document.getElementById('inv-sel').value=selEmp;loadInv();} }
  if (page === 'pg-sla')  { populateSels(); if(selEmp){document.getElementById('sla-sel').value=selEmp;loadSla();} }
  if (page === 'pg-csv')  { populateSels(); if(selEmp){document.getElementById('csv-sel').value=selEmp;loadCsvStatus();} }
  if (page === 'pg-api')  { populateSels(); if(selEmp){document.getElementById('api-emp-sel').value=selEmp;loadApiPage();} }
}

// ── Template selector ──────────────────────────────────────────────────────
function selectTpl(el, tpl) {
  document.querySelectorAll('#tpl-grid .tpl-card').forEach(c=>c.classList.remove('sel'));
  el.classList.add('sel');
  selTpl = tpl;
  updateSummary();
}

// ── Source selector ────────────────────────────────────────────────────────
function selectSrc(el, src) {
  document.querySelectorAll('#src-grid .tpl-card').forEach(c=>c.classList.remove('sel'));
  el.classList.add('sel');
  selSrc = src;
  STEPS = src === 'api' ? STEPS_API : STEPS_CSV;
  updateSummary();
}

function updateSrcCards(empresa) {
  if (!empresa) return;
  fetch(`/api/empresa/${encodeURIComponent(empresa)}/csvs`)
    .then(r=>r.json()).then(d=>{
      const count = (d.files||[]).filter(f=>f.req).length;
      const total = 8;
      const hint = `${count}/${total} CSVs requeridos presentes`;
      const hintEl = document.getElementById('src-csv-hint');
      if (hintEl) hintEl.textContent = hint;
    }).catch(()=>{});
  fetch(`/api/empresa/${encodeURIComponent(empresa)}/env`)
    .then(r=>r.json()).then(d=>{
      const badge    = document.getElementById('src-api-badge');
      const badgeWrn = document.getElementById('src-api-badge-warn');
      const hint     = document.getElementById('src-api-hint');
      if (d.has_key) {
        if (badge)    { badge.style.display='inline-block'; }
        if (badgeWrn) { badgeWrn.style.display='none'; }
        const region = d.region || 'EU';
        if (hint) hint.textContent = `Key configurada · Región ${region}`;
      } else {
        if (badge)    { badge.style.display='none'; }
        if (badgeWrn) { badgeWrn.style.display='inline-block'; }
        if (hint) hint.innerHTML = 'Sin API key · <a href="#" onclick="go(\'pg-api\',\'n-api\')">Configurar →</a>';
      }
    }).catch(()=>{});
}

// ── Empresas ──────────────────────────────────────────────────────────────
async function loadEmpresas() {
  const {empresas} = await fetch('/api/empresas').then(r=>r.json());
  const grid = document.getElementById('emp-grid');
  if (!empresas.length) {
    grid.innerHTML='<div class="empty"><div class="empty-ico">'+icon('building')+'</div>Crea una carpeta [EMPRESA]/CSV/ con los CSVs de TrendAI</div>';
    return;
  }
  grid.innerHTML = empresas.map(e=>{
    const apiMeta = e.api_meta || {};
    const lastFetch = apiMeta.extracted_at ? apiMeta.extracted_at.slice(0,10) : '';
    const totalRows = apiMeta.rows ? Object.values(apiMeta.rows).reduce((a,b)=>a+b,0) : 0;
    return `
    <div class="emp-card ${selEmp===e.nombre?'sel':''}" onclick="selectEmp('${esc(e.nombre)}')">
      <div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:7px">
        <div class="emp-name" style="margin:0">${esc(e.nombre)}</div>
        ${e.api_ok ? `<span class="badge b-ok" style="font-size:10px">API ✓</span>` : `<span class="badge b-warn" style="font-size:10px">Sin API</span>`}
      </div>
      <div class="emp-meta">
        <div style="display:flex;align-items:center;gap:4px"><span class="dot ${e.csv_ok && e.csv_count>=8?'g':e.csv_ok?'a':'r'}"></span>
          CSVs: ${e.csv_count} ${e.csv_count>=8?'✓':'/ 8 req.'}
        </div>
        <div style="display:flex;align-items:center;gap:4px"><span class="dot ${e.hist_ok?'g':''}"></span>
          Histórico: ${e.hist_count} mes${e.hist_count!==1?'es':''}
        </div>
        ${e.inv_count?`<div style="display:flex;align-items:center;gap:4px"><span class="dot g"></span>${e.inv_count} activos catalogados</div>`:''}
        ${lastFetch?`<div style="color:var(--t3);font-size:11px">API: ${lastFetch} · ${totalRows.toLocaleString()} filas</div>`:''}
        ${e.last_info?`<div style="color:var(--t3);font-size:11px">Informe: ${esc(e.last_info)}</div>`:''}
      </div>
    </div>`;
  }).join('');
  populateSels(empresas.map(e=>e.nombre));
  updateSummary();
}

async function crearEmpresa() {
  const v = document.getElementById('new-emp').value.trim();
  if (!v) return toast('Escribe el nombre','warn');
  await fetch('/api/empresa/crear',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({nombre:v})});
  document.getElementById('new-emp').value='';
  selectEmp(v); await loadEmpresas();
  toast(`Empresa "${v}" creada`,'ok');
}

function selectEmp(n) {
  selEmp = n;
  document.getElementById('emp-tag').textContent = n;
  loadEmpresas(); updateSummary();
  updateSrcCards(n);
  toast(`Empresa: ${n}`,'ok');
}

function populateSels(nombres) {
  if (!nombres) { fetch('/api/empresas').then(r=>r.json()).then(d=>populateSels(d.empresas.map(e=>e.nombre))); return; }
  const opts = '<option value="">Selecciona…</option>' + nombres.map(n=>`<option value="${esc(n)}">${esc(n)}</option>`).join('');
  ['cfg-sel','inv-sel','sla-sel','csv-sel','api-emp-sel'].forEach(id=>{const el=document.getElementById(id);if(el)el.innerHTML=opts;});
}

// ── Meses ─────────────────────────────────────────────────────────────────
let dateMode = 'preset';

async function loadMeses() {
  const {meses} = await fetch('/api/meses').then(r=>r.json());
  const sel = document.getElementById('mes-sel');
  sel.innerHTML = meses.map((m,i)=>`<option value="${m}" ${i===0?'selected':''}>${m}</option>`).join('');
  sel.addEventListener('change', updateSummary);
  // Pre-fill custom with current month/year
  const now = new Date();
  const MESES = ['Enero','Febrero','Marzo','Abril','Mayo','Junio',
                 'Julio','Agosto','Septiembre','Octubre','Noviembre','Diciembre'];
  const prevMonth = now.getMonth() === 0 ? 11 : now.getMonth() - 1;
  const prevYear  = now.getMonth() === 0 ? now.getFullYear()-1 : now.getFullYear();
  document.getElementById('mes-custom-m').value = MESES[prevMonth];
  document.getElementById('mes-custom-y').value = prevYear;
  buildCustomDate();
  updateSummary();
}

function setDateMode(mode) {
  dateMode = mode;
  document.querySelectorAll('.date-mode-btn').forEach(b=>b.classList.remove('on'));
  document.getElementById('dmode-'+mode).classList.add('on');
  document.getElementById('date-preset-wrap').style.display = mode==='preset' ? '' : 'none';
  document.getElementById('date-custom-wrap').style.display = mode==='custom' ? '' : 'none';
  updateSummary();
}

function buildCustomDate() {
  const m = document.getElementById('mes-custom-m').value;
  const y = document.getElementById('mes-custom-y').value;
  const badge = document.getElementById('custom-date-badge');
  if (m && y && y >= 2020 && y <= 2035) {
    badge.textContent = m + ' ' + y;
    badge.style.color = 'var(--red)';
    badge.style.background = 'var(--red-s)';
    badge.style.borderColor = 'var(--red-b)';
  } else {
    badge.textContent = '—';
    badge.style.color = 'var(--t2)';
    badge.style.background = 'var(--s3)';
    badge.style.borderColor = 'var(--bd2)';
  }
  updateSummary();
}

function getSelectedMes() {
  if (dateMode === 'custom') {
    const m = document.getElementById('mes-custom-m').value;
    const y = document.getElementById('mes-custom-y').value;
    return (m && y) ? m + ' ' + y : null;
  }
  const sel = document.getElementById('mes-sel');
  return sel ? sel.value : null;
}

function updateSummary() {
  document.getElementById('sum-emp').textContent = selEmp || '—';
  document.getElementById('sum-mes').textContent = getSelectedMes() || '—';
  const tplNames = {tecnico:'Técnica',ejecutivo:'Ejecutiva',ambos:'Ambas'};
  document.getElementById('sum-tpl').textContent = tplNames[selTpl] || selTpl;
  const srcNames = {api:'API Vision One', csv:'CSVs descargados'};
  const srcEl = document.getElementById('sum-src');
  if (srcEl) srcEl.textContent = srcNames[selSrc] || selSrc;
}

// ── Config ────────────────────────────────────────────────────────────────
async function loadCfg() {
  const emp = document.getElementById('cfg-sel').value; if (!emp) return;
  const d = await fetch(`/api/empresa/${encodeURIComponent(emp)}/config`).then(r=>r.json());
  const cfg = d.ok ? d.config : {...DEFAULT_CONFIG, empresa: emp};
  cfgCache[emp] = cfg;
  document.getElementById('cfg-body').innerHTML = `
    <div class="fgrid" style="margin-bottom:14px">
      <div class="fg"><label class="lbl">Nombre empresa</label><input type="text" id="cfg-empresa" value="${esc(cfg.empresa||emp)}"></div>
      <div class="fg"><label class="lbl">Contacto técnico</label><input type="text" id="cfg-contacto" value="${esc(cfg.contacto_tecnico||'')}" placeholder="nombre@empresa.com"></div>
    </div>
    <div class="fg" style="margin-bottom:14px">
      <label class="lbl">Notas adicionales <span class="lbl-h">Aparecen al final del informe</span></label>
      <textarea id="cfg-notas" rows="3" placeholder="Observaciones, acuerdos, contexto del cliente…">${esc(cfg.notas_adicionales||'')}</textarea>
    </div>
    <div class="divider"></div>
    <div style="font-size:12px;font-weight:600;color:var(--t2);margin-bottom:10px;display:flex;align-items:center;gap:6px">${icon('gear')} Opciones</div>
    <div class="trow">
      <div class="tinfo"><div class="tname">Abrir HTML al terminar</div><div class="tdesc">Abre automáticamente el informe en el navegador</div></div>
      <label class="sw"><input type="checkbox" id="cfg-abrir" ${cfg.abrir_html_al_terminar?'checked':''}><span class="sw-track"></span></label>
    </div>`;
}

async function saveCfg() {
  const emp = document.getElementById('cfg-sel').value; if (!emp) return toast('Selecciona empresa','warn');
  const cfg = cfgCache[emp] || {...DEFAULT_CONFIG};
  cfg.empresa           = document.getElementById('cfg-empresa')?.value.trim() || emp;
  cfg.contacto_tecnico  = document.getElementById('cfg-contacto')?.value.trim() || '';
  cfg.notas_adicionales = document.getElementById('cfg-notas')?.value.trim() || '';
  cfg.abrir_html_al_terminar = document.getElementById('cfg-abrir')?.checked || false;
  const r = await fetch(`/api/empresa/${encodeURIComponent(emp)}/config`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(cfg)});
  const d = await r.json();
  d.ok ? (cfgCache[emp]=cfg, toast('Configuración guardada','ok')) : toast('Error: '+d.error,'err');
}

// ── Inventory ─────────────────────────────────────────────────────────────
async function loadInv() {
  const emp = document.getElementById('inv-sel').value; if (!emp) return;
  const d = await fetch(`/api/empresa/${encodeURIComponent(emp)}/config`).then(r=>r.json());
  const cfg = d.ok ? d.config : {...DEFAULT_CONFIG};
  cfgCache[emp] = cfg;
  const raw = cfg.inventario_activos || {};
  invRows = Object.entries(raw).filter(([k])=>!k.startsWith('_')).map(([k,v])=>({name:k,desc:v.descripcion||'',crit:v.criticidad||''}));
  renderInv(emp);
}

function renderInv(emp) {
  emp = emp || document.getElementById('inv-sel').value;
  const el = document.getElementById('inv-body');
  if (!emp) { el.innerHTML='<div class="empty"><div class="empty-ico">'+icon('box')+'</div>Selecciona una empresa</div>'; return; }
  if (!invRows.length) {
    el.innerHTML=`<div class="empty"><div class="empty-ico">${icon('box')}</div>Sin activos.<br><button class="btn btn-secondary btn-sm" style="margin-top:10px" onclick="addInvRow()">${icon('plus')} Añadir primer activo</button></div>`;
    return;
  }
  el.innerHTML = `<table class="inv-tbl">
    <thead><tr><th style="width:150px">Nombre / Hostname</th><th>Descripción / Función</th><th style="width:170px">Criticidad</th><th style="width:40px"></th></tr></thead>
    <tbody>${invRows.map((r,i)=>`
      <tr>
        <td><input class="inp-inv" value="${esc(r.name)}" placeholder="hostname" onchange="invRows[${i}].name=this.value"></td>
        <td><input class="inp-inv" value="${esc(r.desc)}" placeholder="Descripción del activo" onchange="invRows[${i}].desc=this.value" style="width:100%"></td>
        <td><select class="sel-crit" onchange="invRows[${i}].crit=this.value">${CRIT_OPTS.map(o=>`<option value="${o.val}" ${r.crit===o.val?'selected':''}>${o.label}</option>`).join('')}</select></td>
        <td><button class="btn btn-ghost btn-sm" onclick="removeInvRow(${i})" style="padding:4px 8px">✕</button></td>
      </tr>`).join('')}
    </tbody>
  </table>
  <div style="padding:12px 18px;border-top:1px solid var(--bd);display:flex;align-items:center;gap:12px">
    <button class="btn btn-secondary btn-sm" onclick="addInvRow()">+ Añadir activo</button>
    <span style="font-size:12px;color:var(--t3)">${invRows.length} activo${invRows.length!==1?'s':''}</span>
  </div>`;
}

function addInvRow() { invRows.push({name:'',desc:'',crit:''}); renderInv(); setTimeout(()=>{const is=document.querySelectorAll('.inp-inv');if(is.length)is[is.length-2].focus();},50); }
function removeInvRow(i) { invRows.splice(i,1); renderInv(); }

async function saveInv() {
  const emp = document.getElementById('inv-sel').value; if (!emp) return toast('Selecciona empresa','warn');
  if (invRows.some(r=>!r.name.trim())) return toast('Hay activos sin nombre — revisa la tabla','warn');
  const cfg = cfgCache[emp] || {...DEFAULT_CONFIG};
  cfg.inventario_activos = {"_comentario":"MUY CRITICO | CRITICO | NORMAL | NO CRITICO | (vacío)"};
  invRows.forEach(r=>{ if(r.name.trim()) cfg.inventario_activos[r.name.trim()]={descripcion:r.desc,criticidad:r.crit}; });
  const res = await fetch(`/api/empresa/${encodeURIComponent(emp)}/config`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(cfg)});
  const d = await res.json();
  if(d.ok){cfgCache[emp]=cfg;toast(`Inventario guardado: ${invRows.length} activos`,'ok');loadEmpresas();}
  else toast('Error: '+d.error,'err');
}

// ── SLAs ──────────────────────────────────────────────────────────────────
async function loadSla() {
  const emp = document.getElementById('sla-sel').value; if (!emp) return;
  const d = await fetch(`/api/empresa/${encodeURIComponent(emp)}/config`).then(r=>r.json());
  const cfg = d.ok ? d.config : {...DEFAULT_CONFIG};
  cfgCache[emp] = cfg;
  const mods = cfg.modulos_ignorar || [];
  document.getElementById('sla-body').innerHTML = `
    <div style="margin-bottom:20px">
      <div style="font-size:12px;font-weight:600;color:var(--t2);margin-bottom:14px;display:flex;align-items:center;gap:6px">${icon('clock')} SLA por criticidad <span class="lbl-h">Días máximos para resolver</span></div>
      <div class="three-col">
        ${[['sla-crit',dot('#c62828')+'Crítico',cfg.sla_critico_dias??1,30],['sla-alto',dot('#e65100')+'Alto',cfg.sla_alto_dias??3,30],['sla-med',dot('#f57f17')+'Medio',cfg.sla_medio_dias??7,90]].map(([id,lbl,val,max])=>`
          <div class="card" style="margin:0;padding:14px;text-align:center">
            <div style="font-size:11px;font-weight:600;color:var(--t3);text-transform:uppercase;margin-bottom:10px">${lbl}</div>
            <div class="nc" style="justify-content:center;margin:0 auto">
              <button class="nc-btn" onclick="numAdj('${id}',-1)">−</button>
              <input class="nc-val" id="${id}" type="number" min="0" max="${max}" value="${val}">
              <button class="nc-btn" onclick="numAdj('${id}',1)">+</button>
            </div>
            <div style="font-size:11px;color:var(--t3);margin-top:8px">días máximos</div>
          </div>`).join('')}
      </div>
    </div>
    <div class="divider"></div>
    <div style="margin-bottom:20px">
      <div style="font-size:12px;font-weight:600;color:var(--t2);margin-bottom:4px;display:flex;align-items:center;gap:6px">${icon('rotate')} Activos reincidentes</div>
      <div style="font-size:11.5px;color:var(--t3);margin-bottom:14px">CVEs presentes durante N meses consecutivos sin resolver</div>
      <div style="display:flex;align-items:center;gap:14px">
        <div class="nc"><button class="nc-btn" onclick="numAdj('sla-rein',-1)">−</button><input class="nc-val" id="sla-rein" type="number" min="1" max="12" value="${cfg.meses_reincidente??2}"><button class="nc-btn" onclick="numAdj('sla-rein',1)">+</button></div>
        <span style="font-size:13px;color:var(--t2)">meses consecutivos sin resolver</span>
      </div>
    </div>
    <div class="divider"></div>
    <div>
      <div style="font-size:12px;font-weight:600;color:var(--t2);margin-bottom:4px;display:flex;align-items:center;gap:6px">${icon('x')} Módulos a ignorar</div>
      <div style="font-size:11.5px;color:var(--t3);margin-bottom:14px">Los módulos seleccionados no se procesarán al generar el informe</div>
      <div style="display:flex;flex-wrap:wrap;gap:7px" id="mod-chips">
        ${MODULOS.map(m=>`<span style="display:inline-flex;align-items:center;gap:4px;background:var(--s2);border:1px solid ${mods.includes(m)?'var(--red)':'var(--bd2)'};border-radius:20px;padding:4px 12px;font-size:12px;cursor:pointer;color:${mods.includes(m)?'var(--red)':'var(--t2)'}" onclick="this.style.borderColor=this.style.borderColor.includes('red')?'var(--bd2)':'var(--red)';this.style.color=this.style.color.includes('red')?'var(--t2)':'var(--red)'" data-mod="${m}">${m}</span>`).join('')}
      </div>
    </div>`;
}

function numAdj(id,d) { const el=document.getElementById(id); if(!el)return; el.value=Math.max(parseInt(el.min)||0,Math.min(parseInt(el.max)||99,(parseInt(el.value)||0)+d)); }

async function saveSla() {
  const emp = document.getElementById('sla-sel').value; if (!emp) return toast('Selecciona empresa','warn');
  const cfg = cfgCache[emp] || {...DEFAULT_CONFIG};
  cfg.sla_critico_dias  = parseInt(document.getElementById('sla-crit')?.value)||1;
  cfg.sla_alto_dias     = parseInt(document.getElementById('sla-alto')?.value)||3;
  cfg.sla_medio_dias    = parseInt(document.getElementById('sla-med')?.value)||7;
  cfg.meses_reincidente = parseInt(document.getElementById('sla-rein')?.value)||2;
  cfg.modulos_ignorar   = Array.from(document.querySelectorAll('#mod-chips span[data-mod]')).filter(s=>s.style.color.includes('red')).map(s=>s.dataset.mod);
  const res = await fetch(`/api/empresa/${encodeURIComponent(emp)}/config`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(cfg)});
  const d = await res.json();
  d.ok ? (cfgCache[emp]=cfg, toast('SLAs guardados','ok')) : toast('Error: '+d.error,'err');
}

// ── CSV Status ────────────────────────────────────────────────────────────
async function uploadFiles(files) {
  const emp = document.getElementById('csv-sel').value; if (!emp) return;
  const formData = new FormData();
  for (let i = 0; i < files.length; i++) formData.append('files', files[i]);
  toast('Subiendo y normalizando ' + files.length + ' CSVs…', 'info');
  try {
    const res = await fetch(`/api/empresa/${encodeURIComponent(emp)}/upload-csv`, { method: 'POST', body: formData }).then(r => r.json());
    if (res.ok) {
      toast('✓ Archivos subidos y normalizados automáticamente', 'ok');
      loadCsvStatus();
      loadEmpresas();
    } else {
      toast('Error: ' + (res.error || 'No se pudo subir'), 'err');
    }
  } catch(e) {
    toast('Error al subir archivos: ' + String(e), 'err');
  }
}

async function loadCsvStatus() {
  const emp = document.getElementById('csv-sel').value; if (!emp) return;
  document.getElementById('csv-body').innerHTML='<div class="empty"><div class="empty-ico">'+icon('loader')+'</div>Cargando…</div>';
  const d = await fetch(`/api/empresa/${encodeURIComponent(emp)}/csvs`).then(r=>r.json());
  
  const req = new Set(['cve-events.csv','cve-assets.csv','threat-detections.csv','anomaly-detections.csv','security-conf.csv','sys-conf.csv','cloud-app.csv','account-compromise.csv']);
  const found = new Set((d.csvs||[]).map(c=>c.name));
  const miss = [...req].filter(r=>!found.has(r));
  let html = '';
  
  // Zona Drag & Drop masivo
  html += `
  <div id="drop-zone" class="drop-zone" style="margin:14px 18px 0;padding:20px;border:2px dashed var(--bd3);border-radius:var(--r2);text-align:center;background:var(--s2);cursor:pointer;transition:all .2s">
    <div style="font-size:24px;color:var(--blue);margin-bottom:4px">${icon('download')}</div>
    <div style="font-weight:600;color:var(--t1);font-size:13.5px">Arrastra aquí tus archivos CSV en bruto de Vision One</div>
    <div style="font-size:11.5px;color:var(--t3);margin-top:2px">o haz clic para seleccionar archivos. Se renombrarán y normalizarán automáticamente.</div>
    <input type="file" id="drop-file-input" multiple accept=".csv" style="display:none">
  </div>`;

  if (!d.ok || !d.csvs || !d.csvs.length) {
    html += `<div class="empty" style="padding:24px"><div class="empty-ico">${icon('inbox')}</div>No hay CSVs requeridos aún en ${esc(emp)}/CSV/</div>`;
    document.getElementById('csv-body').innerHTML = html;
    initDropZone();
    return;
  }
  
  if (miss.length) html+=`<div class="warn-box" style="margin:14px 18px 0;display:flex;align-items:center;gap:7px">${icon('alert')} Faltan ${miss.length} CSV(s): ${miss.join(', ')}</div>`;
  else html+=`<div class="info-box" style="margin:14px 18px 0;color:var(--green);border-color:rgba(35,209,96,.2);background:rgba(35,209,96,.04);display:flex;align-items:center;gap:7px">${icon('check')} Los 8 CSVs requeridos están presentes y normalizados</div>`;
  html+=`<div class="csv-grid" style="padding:14px 18px">`;
  html+=d.csvs.map(c=>`
    <div class="csv-row">
      <div>
        <div class="csv-name" style="color:${req.has(c.name)?'var(--t1)':'var(--t2)'};display:flex;align-items:center;gap:6px">${req.has(c.name)?icon('check'):icon('file')} ${esc(c.name)}</div>
        <div class="csv-meta">${c.rows.toLocaleString()} filas · ${c.size} KB</div>
      </div>
      <span class="badge ${req.has(c.name)?'b-ok':'b-gray'}">${req.has(c.name)?'OK':'Extra'}</span>
    </div>`).join('');
  html+='</div>';
  document.getElementById('csv-body').innerHTML=html;
  initDropZone();
}

function initDropZone() {
  setTimeout(() => {
    const dz = document.getElementById('drop-zone');
    const fi = document.getElementById('drop-file-input');
    if (!dz || !fi) return;
    dz.onclick = () => fi.click();
    fi.onchange = () => uploadFiles(fi.files);
    dz.ondragover = (e) => { e.preventDefault(); dz.style.borderColor = 'var(--blue)'; dz.style.background = 'rgba(30,64,175,.06)'; };
    dz.ondragleave = () => { dz.style.borderColor = 'var(--bd3)'; dz.style.background = 'var(--s2)'; };
    dz.ondrop = (e) => {
      e.preventDefault();
      dz.style.borderColor = 'var(--bd3)'; dz.style.background = 'var(--s2)';
      if (e.dataTransfer.files && e.dataTransfer.files.length) {
        uploadFiles(e.dataTransfer.files);
      }
    };
  }, 50);
}

// ── Historico ─────────────────────────────────────────────────────────────
async function loadHist() {
  const d = await fetch('/api/historico').then(r=>r.json());
  const el = document.getElementById('hist-list');
  if (!d.items.length) { el.innerHTML='<div class="empty"><div class="empty-ico">'+icon('list')+'</div>No hay informes generados aún</div>'; return; }
  // Agrupar por empresa
  const byEmp = {};
  d.items.forEach(i => { (byEmp[i.empresa]=byEmp[i.empresa]||[]).push(i); });
  let html = '';
  for (const [emp, items] of Object.entries(byEmp)) {
    html += `<div style="padding:10px 18px 4px;font-size:11px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:.5px;background:var(--s2);border-bottom:1px solid var(--bd)">${esc(emp)}</div>`;
    items.forEach(i => {
      const files = [
        i.html  ? {lbl:icon('ext')+' HTML técnico', path:i.html}   : null,
        i.pdf   ? {lbl:icon('file')+' PDF ejecutivo', path:i.pdf}   : null,
        i.word  ? {lbl:icon('file')+' Word',          path:i.word} : null,
      ].filter(Boolean);
      html += `
      <div class="hist-row" style="padding:10px 18px">
        <div style="min-width:0;flex:1">
          <div style="display:flex;align-items:center;gap:8px">
            <div class="hist-mes" style="font-weight:700;font-size:13px">${esc(i.mes)}</div>
            <span class="badge b-gray" style="font-size:10px">${files.length} archivo${files.length!==1?'s':''}</span>
          </div>
          <div class="hist-path" style="max-width:500px">${esc(i.path)}</div>
        </div>
        <div style="display:flex;gap:5px;flex-shrink:0;flex-wrap:wrap">
          ${files.map(f=>`<button class="btn btn-secondary btn-sm" onclick="openFile('${esc(f.path)}')">${f.lbl}</button>`).join('')}
          <button class="btn btn-ghost btn-sm" onclick="openFolder('${esc(i.path)}')" title="Abrir carpeta">${icon('folder')}</button>
        </div>
      </div>`;
    });
  }
  el.innerHTML = html;
}

// ── About ─────────────────────────────────────────────────────────────────
async function loadAbout() {
  const d = await fetch('/api/config').then(r=>r.json());
  const s=document.getElementById('ab-script'); if(s)s.textContent=d.script_path;
  const dr=document.getElementById('ab-dir'); if(dr)dr.textContent=d.work_dir;
}

// ── Generate ──────────────────────────────────────────────────────────────
let genPrueba = false;
async function generate(prueba) {
  if (!selEmp) return toast('Selecciona una empresa primero','warn');
  const mes = getSelectedMes();
  if (!mes) return toast('Selecciona un período válido','warn');
  genPrueba = !!prueba;
  document.getElementById('prog-card').style.display='block';
  document.getElementById('result').style.display='none';
  document.getElementById('btn-gen').disabled=true;
  document.getElementById('btn-gen-test').disabled=true;
  document.getElementById('btn-reset').style.display='none';
  document.getElementById('log').innerHTML='';
  document.getElementById('prog-bar').style.width='0%';
  document.getElementById('prog-pct').textContent='0%';
  STEPS = selSrc === 'api' ? STEPS_API : STEPS_CSV;
  const pruebaTag = genPrueba ? '<span class="badge b-warn" style="margin-left:8px">Prueba</span>' : '';
  const srcLabel = selSrc === 'api' ? icon('download')+' Descargando y generando…' : icon('loader')+' Generando informe…';
  document.getElementById('prog-title').innerHTML = srcLabel + pruebaTag;
  document.getElementById('steps').innerHTML = STEPS.map((s,i)=>`<span class="step" id="st-${i}">${s}</span>`).join('');
  document.getElementById('prog-card').scrollIntoView({behavior:'smooth',block:'start'});

  const riesgoCremVal = document.getElementById('riesgo-crem-manual').value;
  const res = await fetch('/api/generate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
    empresa:selEmp, mes, template:selTpl, source:selSrc,
    solo_word:document.getElementById('sw-solo').checked,
    excels:document.getElementById('sw-excel').checked,
    abrir:document.getElementById('sw-abrir').checked,
    prueba:genPrueba,
    riesgo_crem: riesgoCremVal === '' ? null : parseFloat(riesgoCremVal),
  })});
  const d = await res.json();
  if (!d.ok) { document.getElementById('btn-gen').disabled=false; document.getElementById('btn-gen-test').disabled=false; return toast(d.error||'Error al iniciar','err'); }
  if (es) es.close();
  es = new EventSource('/api/stream');
  es.onmessage = onSSE;
  es.onerror = ()=>es.close();
}

function onSSE(ev) {
  const d = JSON.parse(ev.data);
  if (d.type==='done')  { es.close(); onDone(d); return; }
  if (d.type==='error') { es.close(); onErr(d.msg); return; }
  if (d.type==='progress') {
    document.getElementById('prog-bar').style.width=d.pct+'%';
    document.getElementById('prog-pct').textContent=d.pct+'%';
    if (d.step!==undefined) {
      document.querySelectorAll('.step').forEach((el,i)=>{el.classList.remove('active');if(i<d.step)el.classList.add('done');});
      const cur=document.getElementById(`st-${d.step}`);if(cur)cur.classList.add('active');
    }
    return;
  }
  if (d.type==='log') addLog(d.text, d.level);
}

function addLog(text,level) {
  const p=document.getElementById('log');
  const ts=new Date().toLocaleTimeString('es',{hour:'2-digit',minute:'2-digit',second:'2-digit'});
  const cls={ok:'lok',warn:'lwarn',err:'lerr',info:'linfo'}[level]||'lplain';
  const div=document.createElement('div');
  div.className='ll';
  div.innerHTML=`<span class="lt">${ts}</span><span class="${cls}">${text.replace(/</g,'&lt;')}</span>`;
  p.appendChild(div); p.scrollTop=p.scrollHeight;
}

function onDone(d) {
  STEPS.forEach((_,i)=>{const el=document.getElementById(`st-${i}`);if(el){el.classList.remove('active');el.classList.add('done');}});
  document.getElementById('prog-bar').style.width='100%';
  document.getElementById('prog-pct').textContent='100%';
  document.getElementById('prog-title').innerHTML=icon('checkc')+` Completado en ${d.elapsed}s`+(genPrueba?'<span class="badge b-warn" style="margin-left:8px">Prueba</span>':'');
  document.getElementById('btn-gen').disabled=false;
  document.getElementById('btn-gen-test').disabled=false;
  document.getElementById('btn-reset').style.display='inline-flex';
  const res=document.getElementById('result');
  res.style.display='block';
  document.getElementById('res-sum').innerHTML=`${esc(d.empresa)} · ${esc(d.mes)}`+(genPrueba?' · <b style="color:var(--amber)">modo prueba (carpeta PRUEBAS/, no afecta al histórico)</b>':'');
  const rf=document.getElementById('res-files');
  rf.innerHTML='';
  const files=[
    [icon('file')+' Word',d.word],[icon('file')+' PDF ejecutivo',d.pdf],
    [icon('ext')+' HTML técnico',d.html],[icon('ext')+' HTML ejecutivo',d.html_eje]
  ];
  files.forEach(([lbl,path])=>{ if(!path)return;
    rf.innerHTML+=`<div class="res-file"><span class="res-file-name">${lbl} — ${path.split(/[\/\\]/).pop()}</span><button class="btn btn-secondary btn-sm" onclick="openFile('${esc(path)}')">Abrir</button></div>`;
  });
  res.scrollIntoView({behavior:'smooth',block:'nearest'});
  if(!genPrueba) loadHist();
  toast(genPrueba?'Informe de prueba generado':'¡Informe generado!','ok');
}

function onErr(msg) {
  document.getElementById('prog-title').innerHTML=icon('xc')+' Error';
  document.getElementById('btn-gen').disabled=false;
  document.getElementById('btn-gen-test').disabled=false;
  document.getElementById('btn-reset').style.display='inline-flex';
  addLog(msg,'err'); toast('Error en la generación','err');
}

function resetGen() {
  document.getElementById('prog-card').style.display='none';
  document.getElementById('result').style.display='none';
  document.getElementById('btn-reset').style.display='none';
  document.getElementById('btn-gen').disabled=false;
  document.getElementById('btn-gen-test').disabled=false;
}

async function fetchRiskIndexFromApi() {

  if (!selEmp) return toast('Selecciona una empresa primero', 'warn');
  const btn = document.getElementById('btn-fetch-risk-index');
  if (btn) btn.disabled = true;
  toast('Consultando Cyber Risk Index en Vision One API...', 'info');
  try {
    const res = await fetch('/api/fetch_risk_index', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({empresa: selEmp})
    });
    const d = await res.json();
    if (d.ok) {
      document.getElementById('riesgo-crem-manual').value = d.score;
      toast(`Cyber Risk Index obtenido: ${d.score} (${d.level})`, 'ok');
    } else {
      toast('Error: ' + (d.error || 'No se pudo obtener el score'), 'err');
    }
  } catch (e) {
    toast('Error consultando la API: ' + e, 'err');
  } finally {
    if (btn) btn.disabled = false;
  }
}

// ── Utils ─────────────────────────────────────────────────────────────────

async function openFile(path) {
  await fetch('/api/open',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path})});
  toast('Abriendo…','info');
}
async function openFolder(path) {
  await fetch('/api/open-folder',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path})});
  toast('Abriendo carpeta…','info');
}

function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}

let _tt;
function toast(msg,type='ok'){
  const el=document.getElementById('toast');
  const c={ok:'var(--green)',warn:'var(--amber)',err:'var(--red)',info:'var(--blue)'}[type]||'var(--t1)';
  el.style.color=c;el.textContent=msg;el.style.display='block';
  clearTimeout(_tt);_tt=setTimeout(()=>el.style.display='none',3200);
}


// ── API TrendAI ───────────────────────────────────────────────────────────
let selApiEmp = null, selApiRegion = 'EU', selHasApiKey = false;
const API_REGIONS = ['EU','US','AU','IN','SG','JP'];
let apiEventSource = null;

const MODULE_GROUPS_UI = {
  'Core XDR':           ['workbench','oat','search'],
  'Endpoint Security':  ['endpoint_inventory','endpoint_health','endpoint_eiqs','endpoint_tasks'],
  'ASM / Cyber Risk':   ['asm_vuln','asm_assessments','asm_attack_paths','asm_endpoints','asm_risk'],
  'Cloud & Email':      ['cloud_access','cloud_email','cloud_file_security'],
  'Threat Intel':       ['sandbox','suspicious_objects','intel_reports','intel_tasks'],
  'Identity & Audit':   ['identity_risk','identity_accounts','audit_logs','response_tasks','network_sensor'],
};
const MODULE_LABELS = {
  workbench:'Workbench Alerts', oat:'Observed Attack Techniques', search:'Search API',
  endpoint_inventory:'Inventario Endpoints', endpoint_health:'Agent Health',
  endpoint_eiqs:'Endpoint EIQS', endpoint_tasks:'Endpoint Tasks',
  asm_vuln:'CVE Vulnerabilidades', asm_assessments:'Evaluaciones postura',
  asm_attack_paths:'Rutas de ataque', asm_endpoints:'Endpoints ASM', asm_risk:'Risk Score',
  cloud_access:'Cloud App Access', cloud_email:'Email Security', cloud_file_security:'File Security',
  sandbox:'Sandbox Analysis', suspicious_objects:'Suspicious Objects',
  intel_reports:'Intel Reports', intel_tasks:'STIX Sweeping',
  identity_risk:'Identity Risk', identity_accounts:'Cuentas IAM',
  audit_logs:'Audit Logs', response_tasks:'Response Tasks', network_sensor:'Network Sensors',
  risk_insights:'Risk Insights', network_policy:'Network Policy',
};

async function loadApiPage() {
  const emp = document.getElementById('api-emp-sel').value;
  if (!emp) return;
  selApiEmp = emp;
  document.getElementById('api-fetch-card').style.display = 'block';

  // Cargar meses para el selector de fetch
  const {meses} = await fetch('/api/meses').then(r=>r.json());
  const sel = document.getElementById('api-mes-sel');
  if (sel) sel.innerHTML = meses.map((m,i)=>`<option value="${m}" ${i===0?'selected':''}>${m}</option>`).join('');

  // Cargar estado del .env (sin exponer clave real)
  const d = await fetch(`/api/empresa/${encodeURIComponent(emp)}/env`).then(r=>r.json());
  const region     = d.region || 'EU';
  const hasKey     = d.has_key || false;
  const keyMasked  = d.key_masked || '';
  selApiRegion     = region;
  selHasApiKey     = hasKey;
  const meta       = d.meta || {};

  document.getElementById('api-body').innerHTML = `
    <div class="api-status ${hasKey ? 'ok' : 'warn'}">
      ${hasKey ? `${icon('checkc')} API key configurada — <code style="font-family:var(--mono);font-size:11px">${esc(keyMasked)}</code>`
               : icon('alert')+' API key no configurada — introduce tu clave para habilitar la descarga automática'}
    </div>
    <div class="fgrid" style="margin-bottom:16px">
      <div class="fg" style="grid-column:1/-1">
        <label class="lbl">API Key TrendAI Vision One
          <span class="lbl-h">Administration → API Keys → Add API Key (permisos: Viewer + Response Management)</span>
        </label>
        <div style="display:flex;gap:8px">
          <input type="password" id="api-key-in" class="api-key-input"
            placeholder="${hasKey ? '● Clave guardada — escribe aquí para cambiarla' : 'Pega aquí tu API Key de Vision One…'}"
            style="flex:1" autocomplete="new-password">
          <button class="btn btn-ghost btn-sm" onclick="toggleApiKeyVisible()" id="btn-eye" title="Mostrar/ocultar">${icon('eye')}</button>
        </div>
        ${hasKey ? '<div style="font-size:11px;color:var(--t3);margin-top:4px">Deja en blanco para mantener la clave actual; escribe una nueva para actualizarla.</div>' : ''}
      </div>
    </div>
    <div class="fg" style="margin-bottom:16px">
      <label class="lbl">Región del servidor</label>
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:4px">
        ${API_REGIONS.map(r=>`<button class="region-btn ${r===region?'on':''}" onclick="selectRegion(this,'${r}')">${r}</button>`).join('')}
      </div>
      <div style="font-size:11.5px;color:var(--t3);margin-top:5px" id="region-url">${getRegionUrl(region)}</div>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px">
      <button class="btn btn-secondary" onclick="testApiConnection()">${icon('search')} Probar conexión</button>
      <button class="btn btn-secondary" onclick="discoverModules()" ${!hasKey?'disabled':''}>${icon('layers')} Ver módulos disponibles</button>
      <button class="btn btn-primary" onclick="saveApiKey()">${icon('save')} Guardar configuración</button>
    </div>
    <div id="api-test-result"></div>
    <div id="api-modules-result"></div>
    ${meta.extracted_at ? `
      <div style="margin-top:12px;padding:12px 16px;background:rgba(21,128,61,.04);border:1px solid rgba(21,128,61,.15);border-radius:var(--r)">
        <div style="font-size:11.5px;font-weight:700;color:var(--green);margin-bottom:6px;display:flex;align-items:center;gap:6px">${icon('checkc')} Última extracción via API</div>
        <div style="font-size:12px;color:var(--t2);display:flex;flex-wrap:wrap;gap:14px">
          <span style="display:inline-flex;align-items:center;gap:5px">${icon('calendar')} ${esc(meta.extracted_at?.slice(0,16).replace('T',' ') || '')}</span>
          <span style="display:inline-flex;align-items:center;gap:5px">${icon('clock')} ${esc(meta.mes || '')}</span>
          <span style="display:inline-flex;align-items:center;gap:5px">${icon('chart')} ${Object.values(meta.rows||{}).reduce((a,b)=>a+b,0).toLocaleString()} filas totales</span>
        </div>
        <div style="font-size:11px;color:var(--t3);margin-top:6px;display:flex;flex-wrap:wrap;gap:8px">
          ${Object.entries(meta.rows||{}).map(([k,v])=>`<span>${k.replace('.csv','')}: <strong style="color:${v>0?'var(--green)':'var(--t3)'}">${v}</strong></span>`).join('')}
        </div>
      </div>` : ''}
  `;
}

function getRegionUrl(region) {
  const urls = {EU:'api.eu.xdr.trendmicro.com',US:'api.xdr.trendmicro.com',
    AU:'api.au.xdr.trendmicro.com',IN:'api.in.xdr.trendmicro.com',
    SG:'api.sg.xdr.trendmicro.com',JP:'api.jp.xdr.trendmicro.com'};
  return `Servidor: ${urls[region] || urls.EU}`;
}

function selectRegion(btn, region) {
  selApiRegion = region;
  document.querySelectorAll('.region-btn').forEach(b=>b.classList.remove('on'));
  btn.classList.add('on');
  const urlEl = document.getElementById('region-url');
  if (urlEl) urlEl.textContent = getRegionUrl(region);
}

function toggleApiKeyVisible() {
  const inp = document.getElementById('api-key-in');
  if (!inp) return;
  inp.type = inp.type === 'password' ? 'text' : 'password';
}

async function saveApiKey() {
  const emp = selApiEmp; if (!emp) return toast('Selecciona empresa','warn');
  const key = document.getElementById('api-key-in')?.value.trim();
  // Si el campo está vacío y ya hay clave guardada, solo actualizar región
  if (!key && !selHasApiKey) return toast('Introduce la API key','warn');
  const r = await fetch(`/api/empresa/${encodeURIComponent(emp)}/env`, {
    method:  'POST',
    headers: {'Content-Type':'application/json'},
    body:    JSON.stringify({api_key: key || null, region: selApiRegion}),
  });
  const d = await r.json();
  if (d.ok) { toast(key ? 'API key guardada ✓' : 'Región actualizada ✓', 'ok'); loadApiPage(); loadEmpresas(); }
  else toast('Error: ' + d.error, 'err');
}

async function testApiConnection() {
  const emp = selApiEmp; if (!emp) return toast('Selecciona empresa','warn');
  const key = document.getElementById('api-key-in')?.value.trim();
  // Test sin guardar: enviar la clave en el POST body para probarla en memoria
  if (!key && !selHasApiKey) return toast('Introduce la API key primero','warn');
  const res_el = document.getElementById('api-test-result');
  if (res_el) res_el.innerHTML = '<div class="api-status warn">'+icon('loader')+' Probando conexión con Vision One…</div>';
  const r = await fetch(`/api/empresa/${encodeURIComponent(emp)}/api-test`, {
    method:  'POST',
    headers: {'Content-Type':'application/json'},
    body:    JSON.stringify({api_key: key || null, region: selApiRegion}),
  });
  const d = await r.json();
  if (res_el) {
    const extras = d.endpoint ? ` <span style="font-size:11px;opacity:.7">(${esc(d.endpoint)})</span>` : '';
    res_el.innerHTML = `<div class="api-status ${d.ok?'ok':'err'}">${d.ok?icon('checkc'):icon('xc')} ${esc(d.message)}${extras}</div>`;
  }
}

async function discoverModules() {
  const emp = selApiEmp; if (!emp) return toast('Selecciona empresa','warn');
  const mod_el = document.getElementById('api-modules-result');
  if (mod_el) mod_el.innerHTML = '<div class="api-status warn">'+icon('loader')+' Descubriendo módulos disponibles… (puede tardar unos segundos)</div>';
  try {
    const d = await fetch(`/api/empresa/${encodeURIComponent(emp)}/api-discover`).then(r=>r.json());
    if (!d.ok) { if(mod_el) mod_el.innerHTML=`<div class="api-status err">${icon('xc')} ${esc(d.message)}</div>`; return; }
    const mods = d.modules || {};
    let html = `<div style="margin-top:4px;padding:14px 16px;background:var(--s2);border:1px solid var(--bd2);border-radius:var(--r2)">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
        <div style="font-size:12px;font-weight:700;color:var(--t2);display:flex;align-items:center;gap:6px">${icon('layers')} Módulos disponibles</div>
        <span class="badge b-ok">${d.active_count}/${d.total} activos</span>
      </div>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:6px">`;
    for (const [grp, keys] of Object.entries(MODULE_GROUPS_UI)) {
      const grpActive = keys.filter(k => mods[k]).length;
      const grpTotal  = keys.filter(k => k in mods).length;
      if (!grpTotal) continue;
      html += `<div style="background:#fff;border:1px solid var(--bd);border-radius:var(--r);padding:10px 12px">
        <div style="font-size:10.5px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px">
          ${esc(grp)} <span style="color:${grpActive?'var(--green)':'var(--t3)'}">${grpActive}/${grpTotal}</span>
        </div>
        ${keys.filter(k => k in mods).map(k => `
          <div style="display:flex;align-items:center;gap:6px;padding:2px 0;font-size:12px;color:${mods[k]?'var(--t1)':'var(--t3)'}">
            <span style="width:8px;height:8px;border-radius:50%;background:${mods[k]?'var(--green)':'var(--s5)'};flex-shrink:0"></span>
            ${esc(MODULE_LABELS[k] || k)}
          </div>`).join('')}
      </div>`;
    }
    html += '</div></div>';
    if (mod_el) mod_el.innerHTML = html;
  } catch(e) {
    if (mod_el) mod_el.innerHTML = `<div class="api-status err">${icon('xc')} Error: ${esc(String(e))}</div>`;
  }
}

async function apiFetch() {
  const emp = selApiEmp; if (!emp) return toast('Selecciona empresa','warn');
  const mes = document.getElementById('api-mes-sel')?.value;
  if (!mes) return toast('Selecciona período','warn');

  document.getElementById('api-prog-wrap').style.display = 'block';
  document.getElementById('btn-api-fetch').disabled = true;
  document.getElementById('api-fetch-status').textContent = 'Descargando…';
  document.getElementById('api-fetch-status').className = 'badge b-warn';
  document.getElementById('api-log').innerHTML = '';

  const API_STEPS = ['Alertas Workbench','CVE Vulnerabilidades','Inventario endpoints',
                     'Postura seguridad','Cloud Apps','Guardando CSVs','Metadatos'];
  document.getElementById('api-steps').innerHTML =
    API_STEPS.map((s,i)=>`<span class="step" id="api-st-${i}">${s}</span>`).join('');

  const r = await fetch(`/api/empresa/${encodeURIComponent(emp)}/api-fetch`, {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({mes, empresa: emp})
  });
  const d = await r.json();
  if (!d.ok) { toast(d.error||'Error','err'); document.getElementById('btn-api-fetch').disabled=false; return; }

  if (apiEventSource) apiEventSource.close();
  apiEventSource = new EventSource('/api/api-stream');
  apiEventSource.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.type === 'done') {
      apiEventSource.close();
      document.getElementById('btn-api-fetch').disabled = false;
      document.getElementById('api-fetch-status').textContent = 'Completado';
      document.getElementById('api-fetch-status').className = 'badge b-ok';
      API_STEPS.forEach((_,i) => {
        const el = document.getElementById(`api-st-${i}`);
        if (el) { el.classList.remove('active'); el.classList.add('done'); }
      });
      // Show results
      if (msg.rows) {
        const rows = Object.entries(msg.rows).map(([k,v])=>`${k.replace('.csv','')}: <strong>${v}</strong>`).join(' · ');
        addApiLog(`✓ Completado en ${msg.elapsed}s — ${rows}`, 'ok');
      }
      document.getElementById('api-last-fetch').style.display = 'block';
      document.getElementById('api-last-fetch-detail').innerHTML =
        `${esc(mes)} · Extraídos: ${Object.values(msg.rows||{}).reduce((a,b)=>a+b,0)} filas`;
      toast('Datos descargados de la API','ok');
      loadApiPage();
    } else if (msg.type === 'error') {
      apiEventSource.close();
      addApiLog('✗ ' + msg.msg, 'err');
      document.getElementById('btn-api-fetch').disabled = false;
      document.getElementById('api-fetch-status').textContent = 'Error';
      document.getElementById('api-fetch-status').className = 'badge b-err';
      toast('Error en descarga API','err');
    } else if (msg.type === 'step') {
      const el = document.getElementById(`api-st-${msg.idx}`);
      if (el) {
        document.querySelectorAll('[id^="api-st-"]').forEach(s=>s.classList.remove('active'));
        if (msg.idx > 0) {
          const prev = document.getElementById(`api-st-${msg.idx-1}`);
          if (prev) { prev.classList.remove('active'); prev.classList.add('done'); }
        }
        el.classList.add('active');
        document.getElementById('api-prog-bar').style.width = Math.round((msg.idx/API_STEPS.length)*100)+'%';
      }
    } else if (msg.type === 'log') {
      addApiLog(msg.text, msg.level);
    }
  };
}

function addApiLog(text, level) {
  const p = document.getElementById('api-log');
  const cls = {ok:'lok',warn:'lwarn',err:'lerr',info:'linfo'}[level]||'lplain';
  const div = document.createElement('div');
  div.className = 'll';
  div.innerHTML = `<span class="lt">${new Date().toLocaleTimeString('es',{hour:'2-digit',minute:'2-digit',second:'2-digit'})}</span><span class="${cls}">${text.replace(/</g,'&lt;')}</span>`;
  p.appendChild(div); p.scrollTop = p.scrollHeight;
}

const DEFAULT_CONFIG={empresa:'',sla_critico_dias:1,sla_alto_dias:3,sla_medio_dias:7,meses_reincidente:2,modulos_ignorar:[],notas_adicionales:'',contacto_tecnico:'',abrir_html_al_terminar:false,inventario_activos:{}};
</script>
</body>
</html>"""

# ── API routes ────────────────────────────────────────────────────────────────
@app.route("/")
def index(): return render_template_string(HTML)

@app.route("/api/resumen-global")
def api_resumen_global(): return jsonify(_get_resumen_global())

@app.route("/api/empresas")
def api_empresas(): return jsonify({"empresas": _detectar_empresas()})

@app.route("/api/meses")
def api_meses(): return jsonify({"meses": _get_meses()})

@app.route("/api/config")
def api_config(): return jsonify({"script_path": str(_INFORME_PY), "work_dir": str(_DIR)})

@app.route("/api/empresa/crear", methods=["POST"])
def api_crear():
    nombre = request.json.get("nombre","").strip()
    if not nombre: return jsonify({"ok":False,"error":"Nombre vacío"})
    ed = _emp(nombre); (ed/"CSV").mkdir(parents=True, exist_ok=True)
    _write_cfg(nombre, {**DEFAULT_CFG, "empresa": nombre})
    return jsonify({"ok": True})

@app.route("/api/empresa/<nombre>/config")
def api_cfg_get(nombre):
    cp = _cfg_path(nombre)
    if not cp.exists(): return jsonify({"ok":False,"error":"No existe"})
    try: return jsonify({"ok":True,"config":json.loads(cp.read_text(encoding="utf-8"))})
    except Exception as e: return jsonify({"ok":False,"error":str(e)})

@app.route("/api/empresa/<nombre>/config", methods=["POST"])
def api_cfg_save(nombre):
    ed = _emp(nombre); ed.mkdir(parents=True, exist_ok=True)
    try: _cfg_path(nombre).write_text(json.dumps(request.json,indent=2,ensure_ascii=False),encoding="utf-8"); return jsonify({"ok":True})
    except Exception as e: return jsonify({"ok":False,"error":str(e)})

@app.route("/api/empresa/<nombre>/csvs")
def api_csvs(nombre): return jsonify({"ok":True,"csvs":_csv_info(nombre)})

@app.route("/api/empresa/<nombre>/upload-csv", methods=["POST"])
def api_upload_csv(nombre):
    csv_dir = _emp(nombre) / "CSV"
    csv_dir.mkdir(parents=True, exist_ok=True)
    
    files = request.files.getlist("files")
    if not files:
        return jsonify({"ok": False, "error": "No se recibieron archivos CSV"})
        
    uploaded = []
    for f in files:
        if f.filename:
            dest = csv_dir / f.filename
            f.save(str(dest))
            uploaded.append(f.filename)
            
    try:
        from informe_crem import normalizar_csvs
        normalizar_csvs(csv_dir)
    except Exception:
        pass
        
    return jsonify({"ok": True, "uploaded": uploaded, "csvs": _csv_info(nombre)})

@app.route("/api/empresa/<nombre>/pdf", methods=["POST"])
def api_export_pdf(nombre):
    rel_html = request.json.get("html_path", "")
    sp = _safe_path(rel_html)
    if not sp or not sp.exists():
        return jsonify({"ok": False, "error": "Archivo HTML no encontrado"})
        
    pdf_path = sp.with_suffix(".pdf")
    try:
        from informe_crem import convertir_html_a_pdf
        ok = convertir_html_a_pdf(sp, pdf_path)
        if ok and pdf_path.exists():
            return jsonify({"ok": True, "pdf_path": str(pdf_path)})
        else:
            return jsonify({"ok": False, "error": "No se pudo convertir a PDF"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/historico")
def api_hist(): return jsonify({"items": _get_historico()})

def _is_within(p: "Path", a: "Path") -> bool:
    try:
        p.relative_to(a)
        return True
    except ValueError:
        return False

def _safe_path(raw: str) -> "Path | None":
    """Return resolved Path only if it falls within _DIR or _CLIENTES_DIR."""
    if not raw: return None
    try:
        p = Path(raw).resolve()
    except Exception:
        return None
    allowed = [_DIR.resolve()]
    if _CLIENTES_DIR.is_dir():
        allowed.append(_CLIENTES_DIR.resolve())
    if any(p == a or _is_within(p, a) for a in allowed):
        return p
    return None

@app.route("/api/open", methods=["POST"])
def api_open():
    p = _safe_path(request.json.get("path",""))
    if p and p.exists():
        try:
            if sys.platform=="win32": os.startfile(str(p))
            elif sys.platform=="darwin": subprocess.run(["open", str(p)])
            else: webbrowser.open(f"file://{p}")
        except Exception as e: return jsonify({"ok":False,"error":str(e)})
    return jsonify({"ok":True})

@app.route("/api/open-folder", methods=["POST"])
def api_open_folder():
    p = _safe_path(request.json.get("path",""))
    if p:
        target = p if p.is_dir() else p.parent
        if target.exists():
            try:
                if sys.platform=="win32": subprocess.run(["explorer", str(target)])
                elif sys.platform=="darwin": subprocess.run(["open", str(target)])
                else: webbrowser.open(f"file://{target}")
            except Exception as e: return jsonify({"ok":False,"error":str(e)})
    return jsonify({"ok":True})

@app.route("/api/empresa/<nombre>/env")
def api_env_get(nombre):
    env = _read_env(nombre)
    key = env.get("TRENDAI_API_KEY", "")
    region = env.get("TRENDAI_REGION", "EU")
    has_key = bool(key.strip())
    # Solo devolver clave enmascarada, nunca la real
    if has_key:
        masked = key[:4] + "•" * max(0, len(key) - 8) + key[-4:]
    else:
        masked = ""
    meta = _api_meta(nombre)
    return jsonify({
        "ok":       True,
        "has_key":  has_key,
        "key_masked": masked,
        "region":   region,
        "meta":     meta,
    })

@app.route("/api/empresa/<nombre>/env", methods=["POST"])
def api_env_save(nombre):
    data = request.json or {}
    new_key = data.get("api_key")
    region  = data.get("region", "EU")
    try:
        if new_key is None or new_key.strip() == "":
            # Sin nueva clave: preservar la existente, solo actualizar región
            existing = _read_env(nombre)
            key = existing.get("TRENDAI_API_KEY", "")
        else:
            key = new_key.strip()
        if not key:
            return jsonify({"ok": False, "error": "API key vacía — introduce una clave válida"})
        _write_env(nombre, key, region)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/empresa/<nombre>/api-test", methods=["GET", "POST"])
def api_test_connection(nombre):
    if not _TRENDAI_API.exists():
        return jsonify({"ok": False, "message": "trendai_api.py no encontrado junto a crem_dashboard.py"})

    # Acepta key+region desde POST (test sin guardar) o usa el .env guardado
    if request.method == "POST":
        data = request.json or {}
        key    = (data.get("api_key") or "").strip()
        region = (data.get("region") or "EU").strip()
    else:
        env    = _read_env(nombre)
        key    = env.get("TRENDAI_API_KEY", "")
        region = env.get("TRENDAI_REGION", "EU")

    if not key:
        return jsonify({"ok": False, "message": "API key no configurada"})

    try:
        import importlib.util
        spec    = importlib.util.spec_from_file_location("trendai_api", str(_TRENDAI_API))
        trendai = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(trendai)
        client  = trendai.TrendAIClient(key, region)
        result  = client.test_connection()
        return jsonify(result)
    except Exception as e:
        return jsonify({"ok": False, "message": f"Error interno: {str(e)[:200]}"})

@app.route("/api/empresa/<nombre>/api-discover")
def api_discover_modules(nombre):
    """Descubre módulos disponibles sin hacer fetch completo."""
    if not _TRENDAI_API.exists():
        return jsonify({"ok": False, "message": "trendai_api.py no encontrado"})
    env = _read_env(nombre)
    key = env.get("TRENDAI_API_KEY", "")
    if not key:
        return jsonify({"ok": False, "message": "API key no configurada"})
    try:
        import importlib.util
        spec    = importlib.util.spec_from_file_location("trendai_api", str(_TRENDAI_API))
        trendai = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(trendai)
        client  = trendai.TrendAIClient(key, env.get("TRENDAI_REGION", "EU"))
        modules = client.discover_modules()
        active   = [k for k, v in modules.items() if v]
        inactive = [k for k, v in modules.items() if not v]
        return jsonify({"ok": True, "modules": modules, "active": active, "inactive": inactive,
                        "active_count": len(active), "total": len(modules)})
    except Exception as e:
        return jsonify({"ok": False, "message": str(e)[:300]})

# ── API Fetch job ─────────────────────────────────────────────────────────────
_api_q: queue.Queue = queue.Queue()
_api_job = {"running": False}

def _run_api_fetch(opts):
    empresa = opts["empresa"]
    mes     = opts["mes"]
    def emit(**kw): _api_q.put(kw)

    t0 = time.monotonic()
    try:
        if not _TRENDAI_API.exists():
            emit(type="error", msg="trendai_api.py no encontrado junto a crem_dashboard.py"); return

        # Add trendai_api.py dir to path and import
        import importlib.util
        spec = importlib.util.spec_from_file_location("trendai_api", str(_TRENDAI_API))
        trendai = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(trendai)

        # Load client
        env_file = str(_env_path(empresa))
        try:
            client = trendai.TrendAIClient.from_env(env_file)
        except Exception as e:
            emit(type="error", msg=str(e)); return

        csv_dir = str(_emp(empresa) / "CSV")

        step_names = ["Alertas Workbench","CVE Vulnerabilidades","Inventario endpoints",
                      "Postura seguridad","Cloud Apps","Guardando CSVs","Metadatos"]

        def progress_cb(step, total, message):
            emit(type="step", idx=step-1, total=total, text=message)
            emit(type="log",  text=message, level="info")

        results = client.fetch_all(mes, csv_dir, progress_cb=progress_cb)

        elapsed = round(time.monotonic() - t0, 1)
        emit(type="log", text=f"✓ Descarga completada en {elapsed}s", level="ok")
        emit(type="done", rows=results, elapsed=elapsed, empresa=empresa, mes=mes)

    except Exception as e:
        emit(type="error", msg=traceback.format_exc())
    finally:
        _api_job["running"] = False

@app.route("/api/empresa/<nombre>/api-fetch", methods=["POST"])
def api_fetch_start(nombre):
    if _api_job["running"]:
        return jsonify({"ok": False, "error": "Ya hay una descarga en curso"})
    data = request.json or {}
    _api_job["running"] = True
    while not _api_q.empty():
        try: _api_q.get_nowait()
        except Exception: break
    threading.Thread(
        target=_run_api_fetch,
        args=({"empresa": nombre, "mes": data.get("mes","")},),
        daemon=True
    ).start()
    return jsonify({"ok": True})

@app.route("/api/api-stream")
def api_stream_api():
    def gen():
        while True:
            try:
                item = _api_q.get(timeout=30)
                yield f"data: {json.dumps(item, ensure_ascii=False)}\n\n"
                if item["type"] in ("done","error"): break
            except queue.Empty:
                yield 'data: {"type":"ping"}\n\n'
    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

# ── Inline API fetch (usado dentro de _run_job para el modo API) ──────────────
def _run_api_fetch_inline(empresa: str, mes: str, emit) -> dict:
    """Descarga datos de Vision One en el hilo del job principal.
    Emite progress (pct 3-30) y log al mismo queue que el informe.
    Retorna dict {modulo: n_rows}.
    """
    if not _TRENDAI_API.exists():
        raise RuntimeError(
            "trendai_api.py no encontrado junto a crem_dashboard.py — "
            "descarga el archivo del repositorio."
        )
    import importlib.util as _ilu
    spec    = _ilu.spec_from_file_location("trendai_api", str(_TRENDAI_API))
    trendai = _ilu.module_from_spec(spec)
    spec.loader.exec_module(trendai)

    env_file = str(_env_path(empresa))
    try:
        client = trendai.TrendAIClient.from_env(env_file)
    except Exception as e:
        raise RuntimeError(f"Error cargando API key de {empresa}: {e}")

    csv_dir = str(_emp(empresa) / "CSV")
    Path(csv_dir).mkdir(parents=True, exist_ok=True)

    def _cb(step, total, message):
        pct = 3 + int((step / max(total, 1)) * 27)   # 3 % → 30 %
        emit(type="progress", pct=pct, step=0)
        emit(type="log", text=message, level="info")

    results = client.fetch_all(mes, csv_dir, progress_cb=_cb)
    rows_total = sum(v for v in results.values() if isinstance(v, int))
    emit(type="log",
         text=f"✓ Descarga Vision One completada — {rows_total:,} registros en {len(results)} módulos",
         level="ok")
    emit(type="progress", pct=30, step=1)
    return results

# ── Job runner ────────────────────────────────────────────────────────────────
def _run_job(opts):
    def emit(**kw): _q.put(kw)
    t0 = time.monotonic()
    empresa  = opts["empresa"]; mes = opts["mes"]
    template = opts.get("template", "tecnico")
    source   = opts.get("source",   "api")      # 'api' | 'csv'

    cmd = [sys.executable, str(_INFORME_PY), "--mes", mes, "--no-input",
           "--empresa", empresa, "--template", template]
    if opts.get("solo_word"): cmd.append("--solo-word")
    if opts.get("excels"):    cmd.append("--excels")
    if opts.get("riesgo_crem") not in (None, ""):
        cmd += ["--riesgo-crem", str(opts["riesgo_crem"])]
    else:
        cmd.append("--api-riesgo")


    # Con API los pasos del subprocess empiezan en step=1 y pct=30
    if source == "api":
        STEP_MAP = [
            ("Cargando y procesando", 1, 44),
            ("Comparando CVE",        2, 58),
            ("Generando informe Word",3, 72),
            ("Generando HTML",        3, 86),
            ("Actualización de hist", 4, 95),
        ]
    else:
        STEP_MAP = [
            ("Cargando y procesando", 0, 15),
            ("Comparando CVE",        1, 30),
            ("Generando informe Word",2, 45),
            ("Generando HTML",        3, 80),
            ("Actualización de hist", 4, 94),
        ]

    try:
        # ── Fase 1: descarga API (solo modo API) ───────────────────────────
        if source == "api":
            emit(type="progress", pct=2, step=0)
            emit(type="log", text="→ Conectando con Vision One API…", level="info")
            if not _has_api_key(empresa):
                emit(type="error",
                     msg="API key no configurada para esta empresa. "
                         "Ve a Configuración API → introduce tu clave y guarda.")
                return
            _run_api_fetch_inline(empresa, mes, emit)

        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, encoding="utf-8", errors="replace", cwd=str(_DIR)) as proc:
            for line in proc.stdout:
                line = line.rstrip()
                if not line: continue
                level = "plain"
                if "✓" in line: level="ok"
                elif "⚠" in line or "Warning" in line: level="warn"
                elif "✗" in line or "Error" in line:   level="err"
                elif "→" in line or "─" in line or "[" in line: level="info"
                emit(type="log", text=line, level=level)
                for key, step_n, pct in STEP_MAP:
                    if key in line: emit(type="progress", pct=pct, step=step_n); break
            proc.wait()
        elapsed = round(time.monotonic() - t0, 1)
        if proc.returncode != 0:
            emit(type="error", msg=f"Script terminó con código {proc.returncode}"); return

        # Find output files (en modo prueba la salida va a PRUEBAS/, no a INFORMES/)
        ed      = _emp(empresa)
        mes_safe = mes.replace("/","-").replace(" ","_")
        _base_out = "PRUEBAS" if opts.get("prueba") else "INFORMES"
        inf_dir  = ed / _base_out / mes_safe
        def _find(pat): return next(inf_dir.glob(pat), None) if inf_dir.exists() else None

        html_f     = _find("Revisión_CREM_*.html") if template in ("tecnico","ambos") else None
        html_eje_f = _find("*_ejecutivo.html")
        pdf_f      = _find("*.pdf")
        word_f     = _find("*.docx") if template in ("tecnico","ambos") else None

        if opts.get("abrir"):
            for f in [html_f, html_eje_f, pdf_f]:
                if f and f.exists():
                    try:
                        if sys.platform=="win32": os.startfile(str(f))
                        elif sys.platform=="darwin": subprocess.run(["open",str(f)])
                        else: webbrowser.open(f"file://{f}")
                    except Exception: pass
                    break

        emit(type="progress", pct=100, step=4)
        emit(type="done", empresa=empresa, mes=mes, elapsed=elapsed,
             html=str(html_f) if html_f else "",
             html_eje=str(html_eje_f) if html_eje_f else "",
             pdf=str(pdf_f) if pdf_f else "",
             word=str(word_f) if word_f else "")
    except Exception as _e:
        import logging as _lg
        _lg.getLogger(__name__).exception("_run_job falló")
        emit(type="error", msg=f"Error interno al generar el informe: {type(_e).__name__}")
    finally:
        with _job_lock:
            _job["running"] = False

@app.route("/api/fetch_risk_index", methods=["POST"])
def api_fetch_risk_index():
    data = request.json or {}
    empresa = data.get("empresa", "").strip()
    if not empresa:
        return jsonify({"ok": False, "error": "Falta especificar la empresa"})
    env_file = _env_path(empresa)
    if not env_file.exists():
        return jsonify({"ok": False, "error": f"No existe archivo .env para {empresa}"})
    try:
        from trendai_api import TrendAIClient
        client = TrendAIClient.from_env(str(env_file))
        res = client.get_cyber_risk_index()
        if res.get("ok"):
            return jsonify({"ok": True, "score": res["score"], "level": res["level"], "endpoint": res.get("endpoint", "")})
        else:
            return jsonify({"ok": False, "error": res.get("message", "Error consultando la API")})
    except Exception as ex:
        return jsonify({"ok": False, "error": f"Error consultando Vision One API: {ex}"})

@app.route("/api/generate", methods=["POST"])

def api_generate():
    with _job_lock:
        if _job["running"]: return jsonify({"ok":False,"error":"Ya hay un trabajo en curso"})
        _job["running"] = True
    while not _q.empty():
        try: _q.get_nowait()
        except Exception: break
    threading.Thread(target=_run_job, args=(request.json,), daemon=True).start()
    return jsonify({"ok":True})

@app.route("/api/stream")
def api_stream():
    def gen():
        while True:
            try:
                item = _q.get(timeout=25)
                yield f"data: {json.dumps(item, ensure_ascii=False)}\n\n"
                if item["type"] in ("done","error"): break
            except queue.Empty:
                yield 'data: {"type":"ping"}\n\n'
    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

# ── Desktop App ───────────────────────────────────────────────────────────────

def _find_free_port():
    """Encuentra un puerto libre para Flask."""
    import socket
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def _start_flask(port):
    """Arranca Flask en un hilo demonio."""
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    flask_thread = threading.Thread(
        target=lambda: app.run(
            host="127.0.0.1", port=port,
            debug=False, threaded=True, use_reloader=False
        ),
        daemon=True
    )
    flask_thread.start()
    # Esperar a que Flask esté listo
    import urllib.request
    for _ in range(40):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=0.3)
            return True
        except Exception:
            time.sleep(0.1)
    return False

def _launch_pyqt(port):
    """Ventana nativa con PyQt6 + QWebEngineView."""
    from PyQt6.QtWidgets import QApplication, QMainWindow, QStatusBar
    from PyQt6.QtWebEngineWidgets import QWebEngineView
    from PyQt6.QtWebEngineCore import QWebEngineSettings, QWebEnginePage
    from PyQt6.QtCore import QUrl, Qt, QTimer
    from PyQt6.QtGui import QIcon, QPixmap, QColor

    qt_app = QApplication(sys.argv)
    qt_app.setApplicationName("CREM Dashboard")
    qt_app.setOrganizationName("EMPRESA")
    qt_app.setStyle("Fusion")

    # Dark palette para la barra de título y bordes
    from PyQt6.QtGui import QPalette
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window,           QColor("#f4f6fb"))
    palette.setColor(QPalette.ColorRole.WindowText,       QColor("#111827"))
    palette.setColor(QPalette.ColorRole.Base,             QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.AlternateBase,    QColor("#f8f9fc"))
    palette.setColor(QPalette.ColorRole.Button,           QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.ButtonText,       QColor("#111827"))
    palette.setColor(QPalette.ColorRole.Highlight,        QColor("#f04747"))
    palette.setColor(QPalette.ColorRole.HighlightedText,  QColor("#ffffff"))
    qt_app.setPalette(palette)

    class CREMMainWindow(QMainWindow):
        def closeEvent(self, event):
            event.accept()
            QApplication.quit()

    # Ventana principal
    win = CREMMainWindow()
    win.setWindowTitle("CREM Dashboard  ·  EMPRESA")
    win.resize(1360, 860)
    win.setMinimumSize(960, 640)

    # Centrar en pantalla
    screen = qt_app.primaryScreen()
    if screen:
        sg = screen.availableGeometry()
        win.move(
            (sg.width()  - win.width())  // 2 + sg.x(),
            (sg.height() - win.height()) // 2 + sg.y()
        )

    # WebView
    browser = QWebEngineView()
    browser.settings().setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessRemoteUrls, True)
    browser.settings().setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, True)
    browser.settings().setAttribute(QWebEngineSettings.WebAttribute.LocalStorageEnabled, True)

    # Barra de estado minimal
    status = QStatusBar()
    status.setFixedHeight(22)
    status.setStyleSheet("""
        QStatusBar {
            background: #f4f6fb;
            color: #9ca3af;
            font-size: 11px;
            border-top: 1px solid rgba(0,0,0,0.08);
        }
    """)
    status.showMessage(f"  CREM Dashboard v3  ·  EMPRESA  ·  localhost:{port}")
    win.setStatusBar(status)

    # Estilos de la barra de título (Windows)
    win.setStyleSheet("""
        QMainWindow {
            background: #060810;
        }
        QMenuBar {
            background: #0c0f1a;
            color: #8892ab;
        }
    """)

    win.setCentralWidget(browser)

    # Splash: pantalla de carga mientras Flask arranca
    splash_html = f"""
    <html>
    <head>
    <style>
        body {{ margin:0; background:#f4f6fb; display:flex; align-items:center;
               justify-content:center; height:100vh; flex-direction:column;
               font-family:'Segoe UI',system-ui,sans-serif; gap:20px; }}
        .logo {{ font-size:28px; font-weight:700; color:#111827; letter-spacing:-0.5px }}
        .logo span {{ color:#f04747 }}
        .bar {{ width:240px; height:3px; background:rgba(0,0,0,0.1); border-radius:2px; overflow:hidden }}
        .fill {{ height:100%; background:linear-gradient(90deg,#f04747,#ff6b6b);
                 border-radius:2px; animation:load 1.2s ease infinite }}
        @keyframes load {{ 0%{{width:0%}} 100%{{width:100%}} }}
        .msg {{ color:#9ca3af; font-size:12px }}
    </style>
    </head>
    <body>
        <div class="logo">d<span>a</span>gram</div>
        <div class="bar"><div class="fill"></div></div>
        <div class="msg">Iniciando CREM Dashboard…</div>
    </body>
    </html>
    """
    browser.setHtml(splash_html)
    win.show()

    # Cargar la app cuando Flask esté listo
    def load_app():
        url = f"http://127.0.0.1:{port}/"
        import urllib.request
        for _ in range(60):
            try:
                urllib.request.urlopen(url, timeout=0.5)
                browser.setUrl(QUrl(url))
                status.showMessage(f"  ● CREM Dashboard  ·  EMPRESA  ·  localhost:{port}")
                return
            except Exception:
                time.sleep(0.15)
        status.showMessage("  Error: No se pudo conectar con el servidor Flask")

    QTimer.singleShot(300, load_app)

    return qt_app.exec()

def _launch_pywebview(port):
    """Fallback: pywebview si PyQt no está disponible."""
    import webview
    webview.create_window(
        "CREM Dashboard  ·  EMPRESA",
        f"http://127.0.0.1:{port}/",
        width=1360, height=860,
        min_size=(960, 640),
        background_color="#060810",
        frameless=False,
    )
    webview.start()

def _launch_browser_fallback(port):
    """Último fallback: abrir en el navegador del sistema."""
    import webbrowser
    time.sleep(0.5)
    webbrowser.open(f"http://127.0.0.1:{port}/")
    print(f"\n  Abre http://localhost:{port} en tu navegador")
    print("  Ctrl+C para salir\n")
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        pass

# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    PORT = _find_free_port()

    print(f"\n  CREM Dashboard v3  ·  EMPRESA")
    print(f"  Iniciando servidor en puerto {PORT}…")

    # Arrancar Flask en hilo demonio ANTES de lanzar la UI
    _start_flask(PORT)

    # Intentar GUI en orden de preferencia
    launched = False

    # 1. PyQt6 (mejor opción — ventana nativa real)
    if not launched:
        try:
            from PyQt6.QtWidgets import QApplication
            from PyQt6.QtWebEngineWidgets import QWebEngineView
            print("  Modo: ventana nativa (PyQt6)\n")
            sys.exit(_launch_pyqt(PORT))
        except ImportError:
            pass

    # 2. pywebview
    if not launched:
        try:
            import webview
            print("  Modo: ventana nativa (pywebview)\n")
            _launch_pywebview(PORT)
            launched = True
        except (ImportError, Exception):
            pass

    # 3. Navegador del sistema (fallback)
    if not launched:
        print("  Modo: navegador del sistema\n")
        print("  Para instalar modo nativo: pip install PyQt6 PyQt6-WebEngine\n")
        _launch_browser_fallback(PORT)
