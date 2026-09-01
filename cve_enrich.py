# -*- coding: utf-8 -*-
"""
Enriquecimiento gratuito de CVEs para el generador de informes CREM.

Fuentes (todas gratuitas, sin coste):
  · NVD 2.0  (NIST)      → versión que corrige (fix), CVSS, CWE, enlaces al parche.
  · CISA KEV             → ¿se explota activamente? + fecha límite de remediación.
  · EPSS  (FIRST.org)    → probabilidad de explotación en 30 días (0-1).

Diseño:
  · Solo librería estándar (urllib) — sin dependencias nuevas.
  · Caché a disco (JSON): los CVE no cambian, así que solo se descargan los que
    faltan. La regeneración del informe funciona OFFLINE con lo ya cacheado.
  · NVD tiene rate-limit (5 req/30s sin clave, 50 req/30s con clave gratuita).
    Se respeta con una pausa entre peticiones. EPSS y KEV van en lote/1 descarga.

Uso típico:
    from cve_enrich import enrich
    datos = enrich(["CVE-2024-9680", ...], cache_dir=Path("cve_cache"),
                   nvd_api_key="xxxx", log=print)
    datos["CVE-2024-9680"]["solucion"]  →  "Actualizar Mozilla Firefox a la versión 131.0.2 o superior"
"""
from __future__ import annotations

import json
import time
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Iterable, Optional, Callable

# ── Endpoints ────────────────────────────────────────────────────────────────
NVD_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"

CACHE_SCHEMA = 2          # sube este número si cambia el formato del registro cacheado
KEV_TTL_HORAS = 24        # refrescar catálogo KEV cada 24 h
UA = "CREM-Report-Generator/1.0 (+cve-enrichment)"

# ── CWE → español (nombre + impacto típico) ─────────────────────────────────
# Mapa de los CWE más frecuentes en entornos Windows/enterprise. Permite generar
# una descripción en español fiable a partir de datos estructurados (sin depender
# de un traductor externo). Los no mapeados usan la descripción original de NVD.
CWE_ES: Dict[str, tuple] = {
    "CWE-79":  ("Cross-site scripting (XSS)", "inyectar scripts en el navegador de la víctima"),
    "CWE-89":  ("Inyección SQL", "manipular la base de datos o extraer información"),
    "CWE-20":  ("Validación de entrada incorrecta", "provocar comportamientos no previstos"),
    "CWE-22":  ("Salto de directorio (path traversal)", "acceder a ficheros fuera de la ruta permitida"),
    "CWE-78":  ("Inyección de comandos del SO", "ejecutar comandos arbitrarios en el sistema"),
    "CWE-119": ("Error de límites de memoria", "corromper memoria y ejecutar código"),
    "CWE-120": ("Desbordamiento de búfer", "ejecutar código o provocar caída del servicio"),
    "CWE-125": ("Lectura fuera de límites", "leer memoria no autorizada o provocar caída"),
    "CWE-787": ("Escritura fuera de límites", "corromper memoria y ejecutar código remoto"),
    "CWE-416": ("Uso de memoria tras liberarla (use-after-free)", "ejecutar código o provocar caída"),
    "CWE-476": ("Desreferencia de puntero nulo", "provocar denegación de servicio"),
    "CWE-190": ("Desbordamiento de entero", "corromper memoria o eludir controles"),
    "CWE-200": ("Exposición de información sensible", "acceder a datos confidenciales"),
    "CWE-269": ("Gestión de privilegios incorrecta", "elevar privilegios en el sistema"),
    "CWE-287": ("Autenticación incorrecta", "suplantar identidad o eludir el login"),
    "CWE-306": ("Falta de autenticación", "acceder a funciones sin credenciales"),
    "CWE-352": ("Cross-site request forgery (CSRF)", "ejecutar acciones en nombre del usuario"),
    "CWE-362": ("Condición de carrera", "provocar estados inconsistentes o escalar privilegios"),
    "CWE-400": ("Consumo incontrolado de recursos", "agotar recursos y tumbar el servicio"),
    "CWE-434": ("Subida de ficheros peligrosa", "ejecutar código subiendo un fichero malicioso"),
    "CWE-502": ("Deserialización insegura", "ejecutar código remoto"),
    "CWE-611": ("Procesamiento inseguro de XML (XXE)", "leer ficheros o realizar SSRF"),
    "CWE-798": ("Credenciales embebidas en el código", "acceder con credenciales conocidas"),
    "CWE-863": ("Autorización incorrecta", "acceder a recursos sin permiso"),
    "CWE-918": ("Server-side request forgery (SSRF)", "forzar peticiones internas del servidor"),
    "CWE-94":  ("Inyección de código", "ejecutar código arbitrario"),
    "CWE-284": ("Control de acceso incorrecto", "acceder a recursos restringidos"),
    "CWE-77":  ("Inyección de comandos", "ejecutar comandos arbitrarios"),
    "CWE-522": ("Credenciales protegidas de forma insuficiente", "capturar credenciales"),
    "CWE-295": ("Validación de certificados incorrecta", "interceptar comunicaciones (MITM)"),
    "CWE-noinfo": ("Vulnerabilidad sin clasificar", "comprometer la seguridad del sistema"),
}

_SEV_ES = {"CRITICAL": "Crítica", "HIGH": "Alta", "MEDIUM": "Media", "LOW": "Baja", "NONE": "Informativa"}


# ── HTTP helper ──────────────────────────────────────────────────────────────
def _http_json(url: str, headers: Optional[dict] = None, timeout: int = 30) -> tuple:
    """Devuelve (status, json|None). No lanza en errores HTTP: los codifica en status."""
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception:
        return -1, None


def _fmt_producto(criteria: str) -> str:
    """cpe:2.3:a:mozilla:firefox:* → 'Mozilla Firefox'."""
    try:
        parts = criteria.split(":")
        vendor, product = parts[3], parts[4]
    except Exception:
        return ""
    def _cap(s): return " ".join(w.capitalize() for w in s.replace("_", " ").split())
    v, p = _cap(vendor), _cap(product)
    if not v or v.lower() in p.lower():
        return p
    return f"{v} {p}"


# ── NVD ──────────────────────────────────────────────────────────────────────
def _parse_nvd(cve_obj: dict) -> dict:
    """Extrae de un objeto CVE de NVD lo relevante para el informe."""
    rec: dict = {"found": True}

    # Descripción (inglés) — se usa como respaldo
    desc_en = ""
    for d in cve_obj.get("descriptions", []):
        if d.get("lang") == "en":
            desc_en = d.get("value", ""); break
    rec["desc_en"] = desc_en

    # CVSS (prioridad v3.1 → v3.0 → v2)
    metrics = cve_obj.get("metrics", {})
    score = sev = vector = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            m = metrics[key][0]
            cd = m.get("cvssData", {})
            score = cd.get("baseScore")
            sev = cd.get("baseSeverity") or m.get("baseSeverity")
            vector = cd.get("vectorString")
            break
    rec["cvss"] = score
    rec["severidad"] = (sev or "").upper()
    rec["vector"] = vector

    # CWE (primero disponible)
    cwe = ""
    for w in cve_obj.get("weaknesses", []):
        for d in w.get("description", []):
            if d.get("value", "").startswith("CWE-"):
                cwe = d["value"]; break
        if cwe: break
    rec["cwe"] = cwe

    # Versiones que corrigen (fix) desde las configuraciones CPE
    fixes: List[tuple] = []
    for node in cve_obj.get("configurations", []):
        for nd in node.get("nodes", []):
            for m in nd.get("cpeMatch", []):
                if not m.get("vulnerable", True):
                    continue
                ver = m.get("versionEndExcluding") or m.get("versionEndIncluding")
                if not ver:
                    continue
                prod = _fmt_producto(m.get("criteria", ""))
                incl = bool(m.get("versionEndIncluding"))  # 'hasta X incluido' → fix es posterior
                if prod:
                    fixes.append((prod, ver, incl))
    # Dedup por producto quedándose con la versión de fix más alta
    best: Dict[str, tuple] = {}
    for prod, ver, incl in fixes:
        if prod not in best or _ver_key(ver) > _ver_key(best[prod][0]):
            best[prod] = (ver, incl)
    rec["fixes"] = [(p, v, i) for p, (v, i) in best.items()]

    # Referencias (prioriza avisos/parches del fabricante)
    refs = []
    for r in cve_obj.get("references", []):
        url = r.get("url", "")
        tags = r.get("tags", [])
        if url:
            refs.append({"url": url, "tags": tags})
    def _ref_rank(r):
        t = set(r["tags"])
        if {"Vendor Advisory", "Patch"} & t: return 0
        if "Release Notes" in t: return 1
        if "Mitigation" in t: return 2
        return 3
    refs.sort(key=_ref_rank)
    rec["refs"] = refs[:4]
    return rec


def _ver_key(v: str):
    """Clave de orden numérica-tolerante para versiones tipo '131.0.2'."""
    out = []
    for part in str(v).replace("-", ".").split("."):
        out.append((int(part), "") if part.isdigit() else (0, part))
    return tuple(out)


def _validar_nvd_key(api_key: str, timeout: int = 15) -> bool:
    """
    Comprueba que la API key es aceptada por NVD contra un CVE conocido.
    NVD responde 404 a la petición completa cuando la key es inválida (no 401/403),
    lo que se confundiría con «CVE inexistente». Validar evita envenenar la caché.
    """
    url = f"{NVD_URL}?cveId=CVE-2021-44228"      # Log4Shell — existe siempre
    status, data = _http_json(url, headers={"apiKey": api_key}, timeout=timeout)
    return status == 200 and bool((data or {}).get("vulnerabilities"))


def _fetch_nvd(cve_id: str, api_key: Optional[str], timeout: int = 30) -> dict:
    url = f"{NVD_URL}?cveId={urllib.parse.quote(cve_id)}"
    headers = {"apiKey": api_key} if api_key else {}
    for intento in range(4):
        status, data = _http_json(url, headers=headers, timeout=timeout)
        if status == 200 and data:
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return {"found": False}
            return _parse_nvd(vulns[0]["cve"])
        if status == 404:
            # 404 con key puede ser una key inválida (no un CVE inexistente):
            # reintentar sin key para no cachear un falso negativo.
            if api_key:
                s2, d2 = _http_json(url, headers={}, timeout=timeout)
                if s2 == 200 and d2 and d2.get("vulnerabilities"):
                    return _parse_nvd(d2["vulnerabilities"][0]["cve"])
                if s2 == 404:
                    return {"found": False}          # 404 también sin key → no existe
                return {"found": False, "error": s2 or "err"}   # transitorio → no cachear como definitivo
            return {"found": False}
        if status in (403, 429, -1):        # rate-limit / red → esperar y reintentar
            time.sleep(6 * (intento + 1))
            continue
        return {"found": False, "error": status}
    return {"found": False, "error": "rate-limit"}


# ── CISA KEV ─────────────────────────────────────────────────────────────────
def _load_kev(cache_dir: Path, log: Callable) -> Dict[str, dict]:
    cache_dir.mkdir(parents=True, exist_ok=True)
    kev_cache = cache_dir / "kev_catalog.json"
    fresh = False
    if kev_cache.exists():
        edad_h = (time.time() - kev_cache.stat().st_mtime) / 3600
        fresh = edad_h < KEV_TTL_HORAS
    if not fresh:
        status, data = _http_json(KEV_URL, timeout=30)
        if status == 200 and data:
            kev_cache.write_text(json.dumps(data), encoding="utf-8")
            log(f"KEV: catálogo actualizado ({len(data.get('vulnerabilities', []))} entradas)")
        else:
            log(f"KEV: no se pudo descargar (status {status}); uso caché si existe")
    if not kev_cache.exists():
        return {}
    try:
        data = json.loads(kev_cache.read_text(encoding="utf-8"))
    except Exception:
        return {}
    out = {}
    for v in data.get("vulnerabilities", []):
        out[v.get("cveID", "")] = {
            "dueDate": v.get("dueDate", ""),
            "ransomware": v.get("knownRansomwareCampaignUse", "") == "Known",
            "action": v.get("requiredAction", ""),
        }
    return out


# ── EPSS ─────────────────────────────────────────────────────────────────────
def _fetch_epss(cve_ids: List[str], log: Callable) -> Dict[str, dict]:
    out: Dict[str, dict] = {}
    lote = 100
    for i in range(0, len(cve_ids), lote):
        chunk = cve_ids[i:i + lote]
        url = f"{EPSS_URL}?cve={','.join(chunk)}"
        status, data = _http_json(url, timeout=30)
        if status == 200 and data:
            for row in data.get("data", []):
                try:
                    out[row["cve"]] = {"epss": float(row["epss"]),
                                       "percentil": float(row["percentile"])}
                except Exception:
                    pass
        else:
            log(f"EPSS: lote {i//lote+1} sin respuesta (status {status})")
        time.sleep(0.3)
    return out


# ── Construcción de la "solución recomendada" ────────────────────────────────
def construir_solucion(rec: dict) -> str:
    """Frase de remediación en español a partir del registro NVD."""
    fixes = rec.get("fixes") or []
    if fixes:
        # Ordena por producto y toma hasta 3 para no saturar
        partes = []
        for prod, ver, incl in fixes[:3]:
            if incl:
                partes.append(f"{prod}: actualizar a una versión posterior a la {ver}")
            else:
                partes.append(f"{prod}: actualizar a la versión {ver} o superior")
        sol = "; ".join(partes)
        if len(fixes) > 3:
            sol += f" (y {len(fixes)-3} producto(s) más)"
        return sol
    # Sin versión limpia: apuntar al parche del fabricante
    for r in rec.get("refs", []):
        if {"Vendor Advisory", "Patch"} & set(r.get("tags", [])):
            return f"Aplicar el parche/aviso del fabricante: {r['url']}"
    if rec.get("refs"):
        return f"Revisar el aviso de referencia y aplicar la actualización indicada: {rec['refs'][0]['url']}"
    return "Aplicar la actualización de seguridad del fabricante correspondiente."


def _resumen_productos(fixes: list, maximo: int = 3) -> str:
    """'Firefox, Chrome, Edge y 5 más' — evita listados kilométricos."""
    prods = sorted({p for p, _, _ in (fixes or [])})
    if not prods:
        return ""
    if len(prods) <= maximo:
        return ", ".join(prods)
    return ", ".join(prods[:maximo]) + f" y {len(prods) - maximo} más"


def solucion_para_producto(rec: dict, contexto: str) -> str:
    """
    Dado el registro NVD y el texto del producto afectado en el activo
    (columna 'OS/Application' del CSV, p. ej. 'Mozilla Firefox 130'), devuelve
    la solución del producto que coincide, ignorando los otros N productos del CVE.
    Si no hay coincidencia, cae a la solución general.
    """
    fixes = rec.get("fixes") or []
    if not fixes or not contexto:
        return rec.get("solucion", "")
    ctx = str(contexto).lower()
    coincid = []
    for prod, ver, incl in fixes:
        # ¿alguna palabra significativa del producto NVD aparece en el contexto?
        tokens = [t for t in prod.lower().replace("-", " ").split() if len(t) > 2]
        if any(t in ctx for t in tokens):
            coincid.append((prod, ver, incl))
    if not coincid:
        return rec.get("solucion", "")
    partes = [(f"{p}: actualizar a una versión posterior a la {v}" if i
               else f"{p}: actualizar a la versión {v} o superior")
              for p, v, i in coincid[:3]]
    return "; ".join(partes)


def construir_desc_es(rec: dict, cve_id: str) -> str:
    """Descripción legible en español a partir de datos estructurados."""
    cwe = rec.get("cwe", "")
    nombre, impacto = CWE_ES.get(cwe, ("", ""))
    prods = _resumen_productos(rec.get("fixes"))
    sev = _SEV_ES.get(rec.get("severidad", ""), "")
    cvss = rec.get("cvss")

    if nombre:
        frase = f"{nombre}"
        if prods:
            frase += f" en {prods}"
        frase += "."
        if impacto:
            frase += f" Permitiría a un atacante {impacto}."
    else:
        # Sin CWE mapeado: usa la descripción original (inglés) recortada
        en = rec.get("desc_en", "").strip()
        frase = (en[:220] + "…") if len(en) > 220 else en
        if not frase:
            frase = f"Vulnerabilidad {cve_id}."
    if sev and cvss is not None:
        frase += f" Gravedad {sev} (CVSS {cvss})."
    return frase


# ── API pública ──────────────────────────────────────────────────────────────
def enrich(cve_ids: Iterable[str],
           cache_dir: Path,
           nvd_api_key: Optional[str] = None,
           want_kev: bool = True,
           want_epss: bool = True,
           max_nvd: Optional[int] = None,
           log: Optional[Callable] = None) -> Dict[str, dict]:
    """
    Enriquece un conjunto de CVE IDs. Devuelve {cve_id: registro}.
    Cada registro incluye: found, cvss, severidad, cwe, fixes, refs, solucion,
    descripcion_es, kev, epss, percentil.

    Usa caché en disco (cache_dir/cve_cache.json) y solo descarga de NVD los CVE
    que faltan o cuyo esquema cambió. KEV/EPSS se refrescan por lote.
    """
    log = log or (lambda *_: None)
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    ids = [c for c in dict.fromkeys(cve_ids) if str(c).startswith("CVE-")]

    # 1) Cargar caché existente
    cache_file = cache_dir / "cve_cache.json"
    cache: Dict[str, dict] = {}
    if cache_file.exists():
        try:
            raw = json.loads(cache_file.read_text(encoding="utf-8"))
            if raw.get("schema") == CACHE_SCHEMA:
                cache = raw.get("cves", {})
        except Exception:
            cache = {}

    # 2) NVD: descargar solo los que faltan
    #    (se re-descargan también los cacheados con 'error' → fallos transitorios)
    faltan = [c for c in ids if c not in cache or cache[c].get("error")]
    if max_nvd is not None:
        faltan = faltan[:max_nvd]
    if faltan:
        # Validar la key: si NVD la rechaza (404 a un CVE conocido), caer a modo
        # sin-key para no cachear falsos negativos en toda la ejecución.
        if nvd_api_key and not _validar_nvd_key(nvd_api_key):
            log("NVD: la API key fue RECHAZADA por NVD (404) — se usa modo sin key "
                "(5 req/30s). Revisa/reactiva la clave en nvd.nist.gov.")
            nvd_api_key = None
        pausa = 0.7 if nvd_api_key else 6.5      # respeta rate-limit de NVD
        log(f"NVD: consultando {len(faltan)} CVE nuevos "
            f"({'con' if nvd_api_key else 'sin'} API key, ~{pausa:.1f}s/petición)…")
        for n, cid in enumerate(faltan, 1):
            rec = _fetch_nvd(cid, nvd_api_key)
            rec["_ts"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            # No cachear fallos transitorios (red/rate-limit): que se reintenten
            if rec.get("error"):
                cache.pop(cid, None)
            else:
                cache[cid] = rec
            if n % 25 == 0:
                log(f"  NVD: {n}/{len(faltan)}")
                _guardar_cache(cache_file, cache)   # checkpoint por si se interrumpe
            if n < len(faltan):
                time.sleep(pausa)
        _guardar_cache(cache_file, cache)

    # 3) KEV (1 descarga cacheada)
    kev = _load_kev(cache_dir, log) if want_kev else {}

    # 4) EPSS (por lotes; no se cachea en disco — cambia a diario)
    epss = _fetch_epss(ids, log) if want_epss else {}

    # 5) Componer registros finales
    out: Dict[str, dict] = {}
    for cid in ids:
        rec = dict(cache.get(cid, {"found": False}))
        if rec.get("found"):
            rec["solucion"] = construir_solucion(rec)
            rec["descripcion_es"] = construir_desc_es(rec, cid)
        else:
            rec["solucion"] = ""
            rec["descripcion_es"] = ""
        if cid in kev:
            rec["kev"] = kev[cid]
        if cid in epss:
            rec.update(epss[cid])
        out[cid] = rec
    return out


def _guardar_cache(path: Path, cves: dict) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps({"schema": CACHE_SCHEMA, "cves": cves},
                              ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


# ── CLI de prueba ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys, os
    os.chdir(Path(__file__).resolve().parent)
    ids = sys.argv[1:] or ["CVE-2024-9680", "CVE-2023-48795", "CVE-2023-4863"]
    res = enrich(ids, cache_dir=Path("cve_cache"),
                 nvd_api_key=os.environ.get("NVD_API_KEY"), log=print)
    print()
    for cid, r in res.items():
        print(f"── {cid} ──")
        if not r.get("found"):
            print("   (no encontrado en NVD)")
            continue
        print(f"   Descripción: {r.get('descripcion_es')}")
        print(f"   Solución:    {r.get('solucion')}")
        extra = []
        if "epss" in r: extra.append(f"EPSS {r['epss']*100:.1f}%")
        if "kev" in r:  extra.append("★ KEV (explotado activamente)")
        if extra: print(f"   Prioridad:   {' · '.join(extra)}")
        print()
