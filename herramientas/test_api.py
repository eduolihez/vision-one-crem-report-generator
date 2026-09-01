#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_api.py — Test de extracción Vision One API
Prueba todos los endpoints disponibles y reporta cuántos datos devuelven.

Uso:
    python test_api.py                          # usa CLIENTES/ACME/.env
    python test_api.py --empresa ACME        # usa CLIENTES/ACME/.env
    python test_api.py --env path/to/.env       # ruta explícita al .env
    python test_api.py --mes "Mayo 2026"        # mes específico
    python test_api.py --quick                  # solo descubrimiento + test conexión
"""

import argparse
import importlib.util
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ── Colores ANSI ──────────────────────────────────────────────────────────────
_USE_COLOR = sys.stdout.isatty() or sys.platform == "win32"

def _c(code, text):
    if not _USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"

OK    = lambda t: _c("32;1", t)
WARN  = lambda t: _c("33;1", t)
ERR   = lambda t: _c("31;1", t)
INFO  = lambda t: _c("36", t)
DIM   = lambda t: _c("90", t)
BOLD  = lambda t: _c("1", t)
BLUE  = lambda t: _c("34;1", t)

# ── Helpers ───────────────────────────────────────────────────────────────────
def _bar(frac, width=20):
    filled = int(frac * width)
    return "#" * filled + "." * (width - filled)

def _resolve_env(empresa=None, env_explicit=None) -> Path:
    here = Path(__file__).parent
    if env_explicit:
        p = Path(env_explicit)
        if not p.exists():
            sys.exit(ERR(f"ERROR: No existe: {env_explicit}"))
        return p
    cli = here / "CLIENTES"
    name = empresa or "ACME"
    candidates = [
        cli / name / ".env",
        here / name / ".env",
        here / ".env",
    ]
    for c in candidates:
        if c.exists():
            return c
    sys.exit(ERR(f"ERROR: No se encontro .env para '{name}'. "
                 f"Busqué en:\n" + "\n".join(f"  {c}" for c in candidates)))


# ── Módulos a probar con metadatos ────────────────────────────────────────────
MODULE_META = {
    # (icono, descripción, grupo)
    "workbench":           ("🎯", "Alertas XDR correlacionadas",         "Core XDR"),
    "oat":                 ("⚔️",  "Técnicas MITRE ATT&CK observadas",   "Core XDR"),
    "search":              ("🔍", "Search API (detecciones históricas)",  "Core XDR"),
    "endpoint_inventory":  ("💻", "Inventario de endpoints",             "Endpoint"),
    "endpoint_eiqs":       ("💻", "Inventario EIQS",                     "Endpoint"),
    "endpoint_health":     ("💚", "Estado de agentes (health)",          "Endpoint"),
    "endpoint_tasks":      ("📋", "Tareas en endpoints",                 "Endpoint"),
    "endpoint_vuln_agg":   ("-",  "CVE agregado (Endpoint Security)",    "Endpoint"),
    "endpoint_vuln_detail":("-",  "CVE por dispositivo (per-endpoint)",  "Endpoint"),
    "asm_vuln":            ("🔓", "Vulnerabilidades CVE (ASM)",          "ASM / Riesgo"),
    "asm_endpoints":       ("🖥️",  "Activos con riesgo ASM",             "ASM / Riesgo"),
    "asm_assessments":     ("📐", "Evaluaciones de postura",             "ASM / Riesgo"),
    "asm_risk":            ("📊", "Risk Score global",                   "ASM / Riesgo"),
    "asm_attack_paths":    ("🗺️",  "Rutas de ataque (predictivo)",       "ASM / Riesgo"),
    "cloud_access":        ("☁️",  "Acceso cloud en riesgo (SaaS)",      "Cloud & Email"),
    "cloud_email":         ("📧", "Email Security (phishing/BEC)",       "Cloud & Email"),
    "cloud_file_security": ("📁", "File Security en cloud",              "Cloud & Email"),
    "sandbox":             ("🧪", "Análisis Sandbox",                    "Threat Intel"),
    "suspicious_objects":  ("🕵️",  "Objetos sospechosos (IOCs)",         "Threat Intel"),
    "intel_reports":       ("📜", "Informes de inteligencia",            "Threat Intel"),
    "intel_tasks":         ("🔎", "STIX Sweeping tasks",                 "Threat Intel"),
    "risk_insights":       ("📈", "Risk Insights (cuenta global)",       "Identity"),
    "identity_accounts":   ("👤", "Cuentas IAM",                         "Identity"),
    "identity_risk":       ("🚨", "Cuentas con riesgo elevado",          "Identity"),
    "network_sensor":      ("🌐", "Sensores de red",                     "Network"),
    "network_policy":      ("🛡️",  "Políticas de red",                   "Network"),
    "audit_logs":          ("📝", "Logs de auditoria",                   "Auditoria"),
    "response_tasks":      ("!", "Tareas de respuesta",                  "Respuesta"),
    "container_security":  (">", "Alertas Container Security",           "Contenedores"),
    "asm_internet_facing": ("*", "Activos expuestos a internet",         "ASM / Riesgo"),
    "asrm_high_risk":      ("!", "Dispositivos alto riesgo (ASRM)",      "ASM / Riesgo"),
    "asrm_asset_groups":   ("#", "Grupos de activos (ASRM)",             "ASM / Riesgo"),
    "email_quarantine":    ("-", "Email en cuarentena",                  "Cloud & Email"),
    "cloud_posture":       ("~", "Cloud Posture / Conformity",           "Cloud & Email"),
    "endpoint_isolation":  ("!", "Endpoints aislados",                   "Endpoint"),
    "xdr_entities":        ("@", "Entidades XDR afectadas",              "Core XDR"),
}


# ── Fetch rápido de muestra por módulo ────────────────────────────────────────
def _sample_fetch(client, name: str, start: datetime, end: datetime):
    """
    Intenta obtener una muestra real (top=5–10) de cada módulo.
    Devuelve (count_sample, count_str, error_str | None)
    """
    s = start.strftime("%Y-%m-%dT%H:%M:%SZ")
    e = end.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _get(path, params=None):
        return client._req("GET", path, params or {})

    def _items(r):
        return r.get("items", r.get("data", r.get("value", [])))

    try:
        if name == "workbench":
            r = _get("/v3.0/workbench/alerts", {"top": 10, "startDateTime": s, "endDateTime": e})
            items = _items(r)
            # Si sin fechas hay más
            if not items:
                r2 = _get("/v3.0/workbench/alerts", {"top": 10})
                items = _items(r2)
            return len(items), f"{len(items)} alertas (muestra)", None

        if name == "oat":
            for _oat_path in ("/v3.0/oat/detections", "/v3.0/workbench/detections"):
                try:
                    r = _get(_oat_path, {"top": 10, "startDateTime": s, "endDateTime": e})
                    items = _items(r)
                    return len(items), f"{len(items)} técnicas ATT&CK ({_oat_path})", None
                except Exception:
                    pass
            return 0, "", "sin datos"

        if name == "search":
            r = client._req("POST", "/v3.0/search/detections", body={
                "query": "*", "from": s, "to": e, "source": "detections"
            })
            items = r.get("items", r.get("logs", []))
            return len(items), f"{len(items)} detecciones (muestra)", None

        if name == "endpoint_inventory":
            r = _get("/v3.0/endpointSecurity/endpoints")
            items = _items(r)
            return len(items), f"{len(items)} endpoints", None

        if name == "endpoint_eiqs":
            for _path in ("/v3.0/eiqs/endpoints", "/v3.0/endpointSecurity/eiqs/endpoints"):
                for _p in ({"top": 50}, {"limit": 50}, None):
                    try:
                        r = _get(_path, _p)
                        items = _items(r)
                        if items:
                            return len(items), f"{len(items)} endpoints EIQS ({_path})", None
                    except Exception:
                        pass
            return 0, "0 items (sin datos o 400)", None

        if name == "endpoint_health":
            r = _get("/v3.0/endpointSecurity/agentHealth", {"top": 10})
            items = _items(r)
            return len(items), f"{len(items)} agentes (muestra)", None

        if name == "endpoint_tasks":
            r = _get("/v3.0/endpointSecurity/tasks", {"top": 10})
            items = _items(r)
            return len(items), f"{len(items)} tareas (muestra)", None

        if name == "endpoint_vuln_agg":
            r = _get("/v3.0/endpointSecurity/vulnerabilities", {"top": 10})
            items = _items(r)
            return len(items), f"{len(items)} CVEs agregados (muestra)", None

        if name == "endpoint_vuln_detail":
            # Necesita un agentGuid real — obtener del inventario primero
            try:
                ri = _get("/v3.0/endpointSecurity/endpoints")
                batch = _items(ri)
                if batch:
                    guid = batch[0].get("agentGuid") or batch[0].get("endpointId") or ""
                    if guid:
                        rv = _get(f"/v3.0/endpointSecurity/endpoints/{guid}/vulnerabilities", {"top": 10})
                        items = _items(rv)
                        host = batch[0].get("displayName") or batch[0].get("name","")
                        return len(items), f"{len(items)} CVEs en '{host}' (muestra)", None
            except Exception:
                pass
            return 0, "", "sin datos"

        if name == "asm_vuln":
            r = _get("/v3.0/asrm/vulnerableDevices", {"top": 10, "cveDetectionStatus": "any"})
            items = _items(r)
            return len(items), f"{len(items)} CVEs muestra (vulnerableDevices)", None

        if name == "asm_endpoints":
            r = _get("/v3.0/asrm/attackSurfaceDevices", {"top": 10})
            items = _items(r)
            return len(items), f"{len(items)} activos (attackSurfaceDevices)", None

        if name == "asm_assessments":
            r = _get("/v3.0/asrm/securityPosture", {"top": 10})
            items = _items(r)
            return len(items), f"{len(items)} evaluaciones (securityPosture)", None

        if name == "asm_risk":
            r = _get("/v3.0/asm/riskScore")
            score = r.get("riskScore", r.get("score", r.get("data", {}).get("riskScore", "—")))
            return 1, f"score={score}", None

        if name == "asm_attack_paths":
            r = _get("/v3.0/asm/attackPaths", {"top": 5})
            items = _items(r)
            return len(items), f"{len(items)} rutas de ataque (muestra)", None

        if name == "cloud_access":
            r = _get("/v3.0/cloudAccess/riskAccessEvents",
                     {"top": 10, "startDateTime": s, "endDateTime": e})
            items = _items(r)
            return len(items), f"{len(items)} eventos cloud (muestra)", None

        if name == "cloud_email":
            r = _get("/v3.0/emailSecurity/alerts",
                     {"top": 10, "startDateTime": s, "endDateTime": e})
            items = _items(r)
            return len(items), f"{len(items)} alertas email (muestra)", None

        if name == "cloud_file_security":
            r = _get("/v3.0/cloudFileSecurity/events",
                     {"top": 10, "startDateTime": s, "endDateTime": e})
            items = _items(r)
            return len(items), f"{len(items)} eventos archivo (muestra)", None

        if name == "sandbox":
            for _sb_path, _sb_p in [
                ("/v3.0/sandbox/tasks", {"top": 10, "startDateTime": s, "endDateTime": e}),
                ("/v3.0/sandbox/tasks", {"top": 10}),
                ("/v3.0/sandbox/submissionList", {"top": 10, "startDateTime": s, "endDateTime": e}),
            ]:
                try:
                    r = _get(_sb_path, _sb_p)
                    items = _items(r)
                    return len(items), f"{len(items)} submissions ({_sb_path})", None
                except Exception:
                    pass
            return 0, "", "sin datos"

        if name == "suspicious_objects":
            r = _get("/v3.0/threatintel/suspiciousObjects", {"top": 10})
            items = _items(r)
            return len(items), f"{len(items)} IOCs activos (muestra)", None

        if name == "intel_reports":
            r = _get("/v3.0/threatintel/intelligenceReports")
            items = _items(r)
            return len(items), f"{len(items)} informes", None

        if name == "intel_tasks":
            r = _get("/v3.0/threatintel/stixSweepingTasks", {"top": 10})
            items = _items(r)
            return len(items), f"{len(items)} tareas STIX (muestra)", None

        if name == "risk_insights":
            r = _get("/v3.0/riskInsights/riskScore")
            score = r.get("riskScore", r.get("score", "—"))
            return 1, f"score={score}", None

        if name == "identity_accounts":
            # IAM accounts no siempre acepta top — intentar sin params primero
            for p in [{}, {"top": 10}]:
                try:
                    r = _get("/v3.0/iam/accounts", p or None)
                    items = _items(r)
                    return len(items), f"{len(items)} cuentas (muestra)", None
                except Exception:
                    pass
            return 0, "", "sin datos"

        if name == "identity_risk":
            r = _get("/v3.0/iam/accountsRiskInsight", {"top": 10})
            items = _items(r)
            return len(items), f"{len(items)} cuentas en riesgo (muestra)", None

        if name == "network_sensor":
            r = _get("/v3.0/networkSecurity/sensors", {"top": 10})
            items = _items(r)
            return len(items), f"{len(items)} sensores", None

        if name == "network_policy":
            r = _get("/v3.0/networkSecurity/policies", {"top": 10})
            items = _items(r)
            return len(items), f"{len(items)} políticas", None

        if name == "audit_logs":
            for _al_path in ("/v3.0/audit/logs", "/v3.0/auditLogs"):
                for _al_p in [
                    {"top": 10, "startDateTime": s, "endDateTime": e},
                    {"startDateTime": s, "endDateTime": e},
                    {"top": 10},
                    {},
                ]:
                    try:
                        r = _get(_al_path, _al_p or None)
                        items = _items(r)
                        return len(items), f"{len(items)} logs ({_al_path})", None
                    except Exception as _ex:
                        if "404" in str(_ex):
                            break
            return 0, "", "sin datos o sin permiso"

        if name == "response_tasks":
            r = _get("/v3.0/response/tasks", {"top": 10})
            items = _items(r)
            return len(items), f"{len(items)} tareas respuesta (muestra)", None

        if name == "container_security":
            r = _get("/v3.0/containerSecurity/alerts", {"top": 10})
            items = _items(r)
            return len(items), f"{len(items)} alertas contenedor (muestra)", None

        if name == "asm_internet_facing":
            r = _get("/v3.0/asrm/attackSurfacePublicIpAddresses", {"top": 10})
            items = _items(r)
            return len(items), f"{len(items)} activos expuestos (attackSurfacePublicIpAddresses)", None

        if name == "asrm_high_risk":
            r = _get("/v3.0/asrm/highRiskDevices", {"top": 10})
            items = _items(r)
            return len(items), f"{len(items)} dispositivos alto riesgo (muestra)", None

        if name == "asrm_asset_groups":
            r = _get("/v3.0/asrm/assetGroups", {"top": 10})
            items = _items(r)
            return len(items), f"{len(items)} grupos de activos (muestra)", None

        if name == "email_quarantine":
            r = _get("/v3.0/emailSecurity/quarantineMessages",
                     {"top": 10, "startDateTime": s, "endDateTime": e})
            items = _items(r)
            return len(items), f"{len(items)} mensajes cuarentena (muestra)", None

        if name == "cloud_posture":
            for path in ["/v3.0/cloudPosture/assessmentSummaries",
                         "/v3.0/cloudPosture/checks"]:
                try:
                    r = _get(path, {"top": 10})
                    items = _items(r)
                    if items:
                        return len(items), f"{len(items)} checks postura (muestra)", None
                except Exception:
                    pass
            return 0, "sin datos", None

        if name == "endpoint_isolation":
            for p in [{"top": 10}, {}]:
                try:
                    r = _get("/v3.0/endpointSecurity/isolatedEndpoints", p or None)
                    items = _items(r)
                    return len(items), f"{len(items)} endpoints aislados", None
                except Exception:
                    pass
            return 0, "", "sin datos"

        if name == "xdr_entities":
            for path in ["/v3.0/xdr/impactedEntities", "/v3.0/workbench/impactedEntities"]:
                try:
                    r = _get(path, {"top": 10, "startDateTime": s, "endDateTime": e})
                    items = _items(r)
                    return len(items), f"{len(items)} entidades XDR (muestra)", None
                except Exception:
                    pass
            return 0, "", "sin datos"

        return 0, "sin handler", None

    except Exception as ex:
        msg = str(ex)
        # Extraer código HTTP si está en el mensaje
        m = re.search(r"HTTP (\d+)", msg)
        code = m.group(1) if m else "?"
        return 0, "", f"HTTP {code}" if m else msg[:60]


# ── Presentación ──────────────────────────────────────────────────────────────
def _print_header(empresa: str, mes: str, region: str, env_path: Path):
    print()
    print(BOLD("=" * 66))
    print(BOLD(f"  TrendAI Vision One -- Test de extraccion API"))
    print(BOLD("=" * 66))
    print(f"  Empresa : {BLUE(empresa)}")
    print(f"  Periodo : {INFO(mes)}")
    print(f"  Region  : {INFO(region)}")
    print(f"  .env    : {DIM(str(env_path))}")
    print(BOLD("-" * 66))
    print()

def _print_group(group: str, rows: list):
    print(f"\n  {BOLD(group)}")
    print(f"  {'-' * 62}")
    for (name, avail, count_str, err, http_status) in rows:
        _, desc, _ = MODULE_META.get(name, ("?", name, ""))
        if avail and not err:
            tag  = OK("  [OK]   ")
            data = f"  {DIM(count_str)}" if count_str else ""
        elif avail and err:
            tag  = WARN("  [WARN] ")
            data = f"  {WARN(err)}"
        elif http_status == 403:
            tag  = WARN("  [403]  ")
            data = f"  {WARN('API key sin permiso — revisa los roles')}"
        elif http_status == 404:
            tag  = DIM("  [404]  ")
            data = f"  {DIM('modulo no contratado')}"
        elif http_status == 0:
            tag  = ERR("  [NET]  ")
            data = f"  {ERR('error de red')}"
        else:
            tag  = ERR(f"  [{http_status}]  ")
            data = ""
        print(f"  {desc:<44}{tag}{data}")

def _print_summary(total_mods: int, avail: int, forbidden: int, not_contracted: int,
                   total_rows: int, elapsed: float, errors: list, mod_status: dict = None):
    print()
    print(BOLD("=" * 66))
    pct = avail / total_mods if total_mods else 0
    bar = _bar(pct, 30)
    print(f"  Modulos accesibles  : {OK(str(avail))}/{total_mods}  [{bar}]  {pct*100:.0f}%")
    if forbidden:
        print(f"  Modulos bloqueados  : {WARN(str(forbidden))}  {WARN('(403 - API key sin permisos)')} ")
    if not_contracted:
        print(f"  No contratados      : {DIM(str(not_contracted))}  {DIM('(404 - no en este tenant)')}")
    print(f"  Registros (muestra) : {INFO(str(total_rows))}")
    print(f"  Tiempo total        : {elapsed:.1f}s")
    if forbidden:
        # Mapeo módulo → (App en Vision One console, Permiso exacto según docs oficiales)
        _PERM_MAP = {
            "workbench":          ("Workbench",                    "View, filter, and search"),
            "oat":                ("Observed Attack Techniques",   "View, filter, and search"),
            "search":             ("Search",                       "View, filter, and search"),
            "xdr_entities":       ("Workbench",                    "View, filter, and search"),
            "sandbox":            ("Sandbox Analysis",             "View, filter, and search"),
            "suspicious_objects": ("Suspicious Object Management", "View, filter, and search"),
            "intel_reports":      ("Intelligence Feeds",           "View, filter, search, and download results"),
            "intel_tasks":        ("Intelligence Feeds",           "Start sweeping (STIX-Shifter)"),
            "response_tasks":     ("Response Management",          "View, filter, and search (Task List tab)"),
            "container_security": ("Container Security",           "View, filter, and search"),
            "audit_logs":         ("Audit Logs",                   "View, filter, and search"),
            "cloud_access":       ("Risk Insights / Reports",      "View, configure, and download"),
            "cloud_email":        ("Risk Insights / Reports",      "View, configure, and download"),
            "identity_risk":      ("Risk Insights / Reports",      "View, configure, and download"),
        }
        print()
        print(WARN("  ACCION REQUERIDA:"))
        print(WARN("  Administration > User Roles > (tu rol o nuevo rol) > Editar permisos"))
        print(WARN("  O bien: Administration > API Keys > Edit key > cambiar Role a 'Senior Analyst'"))
        print()
        print(BOLD("  Permisos exactos a activar (según documentación oficial):"))
        print()
        app_to_mods: dict = {}
        for mod, st in (mod_status or {}).items():
            if st == 403:
                app, perm = _PERM_MAP.get(mod, ("(app desconocida)", mod))
                app_to_mods.setdefault((app, perm), []).append(mod)
        for (app, perm), mods in sorted(app_to_mods.items()):
            print(WARN(f"  App: {BOLD(app)}"))
            print(f"       Permiso: {INFO(perm)}")
            print(f"       Desbloquea: {DIM(', '.join(mods))}")
            print()
        print(INFO("  Alternativa rapida: asignar rol predefinido 'Senior Analyst' o 'Analyst'"))
        print(INFO("  cubre Workbench, OAT, Response. Para Sandbox e Intel necesitas permisos custom."))
    if errors:
        print()
        print(WARN(f"  Errores en fetch ({len(errors)}):"))
        for e in errors[:5]:
            print(f"    - {DIM(e)}")
    print(BOLD("=" * 66))
    print()


# ── All-modules path probe ────────────────────────────────────────────────────
def _probe_all_paths(client, first_guid: str = ""):
    """Prueba rutas alternativas para TODOS los módulos que fallan. Igual que --probe-cve pero para todo."""

    def _st(method, path, params=None, body=None):
        try:
            client._req(method, path, params, body)
            return 200
        except Exception as ex:
            import re as _re
            m = _re.search(r"(\d{3})", str(ex))
            return int(m.group(1)) if m else 0

    G = first_guid  # alias corto

    # Cada módulo: lista de (método, path, params, body, descripción)
    ALL_PROBES = {

        # ── Core XDR ─────────────────────────────────────────────────────────
        "workbench (403)": [
            ("GET", "/v3.0/workbench/alerts",                   {"top":1}, None,  "ruta actual"),
            ("GET", "/v3.0/workbench/incidents",                {"top":1}, None,  "incidents"),
            ("GET", "/v3.0/xdr/alerts",                         {"top":1}, None,  "xdr/alerts"),
            ("GET", "/v3.0/alerts",                             {"top":1}, None,  "alerts top-level"),
            ("GET", "/v3.0/workbench/detectionAlerts",          {"top":1}, None,  "detectionAlerts"),
        ],
        "oat / detecciones MITRE": [
            ("GET", "/v3.0/workbench/detections",               {"top":1}, None,  "ruta actual"),
            ("GET", "/v3.0/oat/events",                         {"top":1}, None,  "oat/events"),
            ("GET", "/v3.0/oat/detections",                     {"top":1}, None,  "oat/detections"),
            ("GET", "/v3.0/xdr/detections",                     {"top":1}, None,  "xdr/detections"),
            ("GET", "/v3.0/detections",                         {"top":1}, None,  "detections top-level"),
            ("GET", "/v3.0/workbench/observedAttackTechniques", {"top":1}, None,  "observedAttackTechniques"),
        ],
        "search API": [
            ("POST", "/v3.0/search/detections",      None, {"query":"*","source":"detections","size":1}, "ruta actual"),
            ("POST", "/v3.0/search/events",          None, {"query":"*","size":1},                       "search/events"),
            ("GET",  "/v3.0/search",                 {"top":1}, None,                                    "search GET"),
            ("POST", "/v3.0/detections/search",      None, {"query":"*","size":1},                       "detections/search"),
            ("POST", "/v3.0/xdr/search",             None, {"query":"*","size":1},                       "xdr/search"),
        ],
        "xdr entities": [
            ("GET", "/v3.0/xdr/impactedEntities",               {"top":1}, None,  "ruta actual"),
            ("GET", "/v3.0/workbench/impactedEntities",         {"top":1}, None,  "workbench/impactedEntities"),
            ("GET", "/v3.0/workbench/entities",                 {"top":1}, None,  "workbench/entities"),
            ("GET", "/v3.0/xdr/entities",                       {"top":1}, None,  "xdr/entities"),
        ],

        # ── Endpoint Security ─────────────────────────────────────────────────
        "endpoint agent health": [
            ("GET", "/v3.0/endpointSecurity/agentHealth",       {"top":1}, None,  "ruta actual"),
            ("GET", "/v3.0/endpointSecurity/agents",            {"top":1}, None,  "agents"),
            ("GET", "/v3.0/endpointSecurity/health",            {"top":1}, None,  "health"),
            ("GET", "/v3.0/endpointSecurity/agents/health",     {"top":1}, None,  "agents/health"),
            ("GET", "/v3.0/endpointSecurity/endpoints/health",  {"top":1}, None,  "endpoints/health"),
            ("GET", f"/v3.0/endpointSecurity/endpoints/{G}",    None,      None,  "single endpoint detail"),
        ],
        "endpoint isolation": [
            ("GET", "/v3.0/endpointSecurity/isolatedEndpoints", {"top":1}, None,  "ruta actual"),
            ("GET", "/v3.0/endpointSecurity/isolation",         {"top":1}, None,  "isolation"),
            ("GET", "/v3.0/endpointSecurity/endpoints/isolated",{"top":1}, None,  "endpoints/isolated"),
            ("GET", "/v3.0/endpointSecurity/endpointIsolation", {"top":1}, None,  "endpointIsolation"),
        ],
        "endpoint tasks": [
            ("GET", "/v3.0/endpointSecurity/tasks",             {"top":1}, None,  "ruta actual"),
            ("GET", "/v3.0/endpointSecurity/agentTasks",        {"top":1}, None,  "agentTasks"),
            ("GET", "/v3.0/endpointSecurity/operations",        {"top":1}, None,  "operations"),
            ("GET", "/v3.0/tasks",                              {"top":1}, None,  "tasks top-level"),
        ],

        # ── ASM / Riesgo ─────────────────────────────────────────────────────
        "asm endpoints / activos": [
            ("GET", "/v3.0/asrm/attackSurfaceDevices",          {"top":1}, None,  "ruta correcta (CREM/ASRM)"),
            ("GET", "/v3.0/asm/endpoints",                      {"top":1}, None,  "ruta antigua (404)"),
            ("GET", "/v3.0/asm/assets",                         {"top":1}, None,  "asm/assets"),
            ("GET", "/v3.0/asm/devices",                        {"top":1}, None,  "asm/devices"),
            ("GET", "/v3.0/asm/discoveredAssets",               {"top":1}, None,  "discoveredAssets"),
            ("GET", "/v3.0/attackSurface/endpoints",            {"top":1}, None,  "attackSurface/endpoints"),
            ("GET", "/v3.0/attackSurface/assets",               {"top":1}, None,  "attackSurface/assets"),
            ("GET", "/v3.0/assetManagement/endpoints",          {"top":1}, None,  "assetManagement/endpoints"),
        ],
        "asm vulnerable devices": [
            ("GET", "/v3.0/asrm/vulnerableDevices", {"top":1,"cveDetectionStatus":"any"}, None, "ruta correcta (CREM/ASRM)"),
            ("GET", "/v3.0/asm/vulnerabilities",                {"top":1}, None,  "ruta antigua (404)"),
        ],
        "asm assessments / postura": [
            ("GET", "/v3.0/asrm/securityPosture",               {"top":1}, None,  "ruta correcta (CREM/ASRM)"),
            ("GET", "/v3.0/asm/assessments",                    {"top":1}, None,  "ruta antigua (404)"),
            ("GET", "/v3.0/asm/checks",                         {"top":1}, None,  "asm/checks"),
            ("GET", "/v3.0/asm/findings",                       {"top":1}, None,  "asm/findings"),
            ("GET", "/v3.0/posture/assessments",                {"top":1}, None,  "posture/assessments"),
            ("GET", "/v3.0/assessments",                        {"top":1}, None,  "assessments top-level"),
            ("GET", "/v3.0/complianceManagement/assessments",   {"top":1}, None,  "complianceManagement"),
        ],
        "asm high risk devices / asset groups": [
            ("GET", "/v3.0/asrm/highRiskDevices",               {"top":1}, None,  "ruta correcta (CREM/ASRM)"),
            ("GET", "/v3.0/asrm/assetGroups",                   {"top":1}, None,  "ruta correcta (CREM/ASRM)"),
        ],
        "risk score global": [
            ("GET", "/v3.0/asm/riskScore",                      None,      None,  "ruta actual"),
            ("GET", "/v3.0/riskInsights/riskScore",             None,      None,  "riskInsights/riskScore"),
            ("GET", "/v3.0/riskScore",                          None,      None,  "riskScore top-level"),
            ("GET", "/v3.0/cyberRisk/score",                    None,      None,  "cyberRisk/score"),
            ("GET", "/v3.0/cyberRisk/riskScore",                None,      None,  "cyberRisk/riskScore"),
            ("GET", "/v3.0/riskInsights/score",                 None,      None,  "riskInsights/score"),
            ("GET", "/v3.0/riskInsights/summary",               None,      None,  "riskInsights/summary"),
        ],
        "attack paths (predictivo)": [
            ("GET", "/v3.0/asm/attackPaths",                    {"top":1}, None,  "ruta actual"),
            ("GET", "/v3.0/asm/attackPath",                     {"top":1}, None,  "attackPath (singular)"),
            ("GET", "/v3.0/attackPaths",                        {"top":1}, None,  "attackPaths top-level"),
            ("GET", "/v3.0/tem/attackPaths",                    {"top":1}, None,  "tem/attackPaths"),
            ("GET", "/v3.0/threatAndExposureManagement/attackPaths", {"top":1}, None, "tem full path"),
            ("GET", "/v3.0/predictive/attackPaths",             {"top":1}, None,  "predictive/attackPaths"),
        ],
        "internet facing assets": [
            ("GET", "/v3.0/asrm/attackSurfacePublicIpAddresses",{"top":1}, None,  "ruta correcta (CREM/ASRM)"),
            ("GET", "/v3.0/asm/internetFacingAssets",           {"top":1}, None,  "ruta antigua (404)"),
            ("GET", "/v3.0/asm/internetFacing",                 {"top":1}, None,  "internetFacing"),
            ("GET", "/v3.0/asm/publicAssets",                   {"top":1}, None,  "publicAssets"),
            ("GET", "/v3.0/exposures/internet",                 {"top":1}, None,  "exposures/internet"),
            ("GET", "/v3.0/attackSurface/internetFacing",       {"top":1}, None,  "attackSurface/internetFacing"),
        ],

        # ── Cloud & Email ─────────────────────────────────────────────────────
        "cloud access / SaaS": [
            ("GET", "/v3.0/cloudAccess/riskAccessEvents",       {"top":1}, None,  "ruta actual"),
            ("GET", "/v3.0/cloudAccess/events",                 {"top":1}, None,  "cloudAccess/events"),
            ("GET", "/v3.0/cloudAccess/alerts",                 {"top":1}, None,  "cloudAccess/alerts"),
            ("GET", "/v3.0/saas/events",                        {"top":1}, None,  "saas/events"),
            ("GET", "/v3.0/saas/alerts",                        {"top":1}, None,  "saas/alerts"),
            ("GET", "/v3.0/cloudSecurity/events",               {"top":1}, None,  "cloudSecurity/events"),
            ("GET", "/v3.0/cloud/events",                       {"top":1}, None,  "cloud/events"),
        ],
        "email security / phishing": [
            ("GET", "/v3.0/emailSecurity/alerts",               {"top":1}, None,  "ruta actual"),
            ("GET", "/v3.0/emailSecurity/threats",              {"top":1}, None,  "threats"),
            ("GET", "/v3.0/emailSecurity/events",               {"top":1}, None,  "events"),
            ("GET", "/v3.0/emailSecurity/detections",           {"top":1}, None,  "detections"),
            ("GET", "/v3.0/email/alerts",                       {"top":1}, None,  "email/alerts"),
            ("GET", "/v3.0/cloudEmail/alerts",                  {"top":1}, None,  "cloudEmail/alerts"),
        ],
        "email quarantine": [
            ("GET", "/v3.0/emailSecurity/quarantineMessages",   {"top":1}, None,  "ruta actual"),
            ("GET", "/v3.0/emailSecurity/quarantine",           {"top":1}, None,  "quarantine (short)"),
            ("GET", "/v3.0/quarantine/messages",                {"top":1}, None,  "quarantine top-level"),
            ("GET", "/v3.0/emailSecurity/quarantinedMessages",  {"top":1}, None,  "quarantinedMessages"),
        ],
        "cloud file security": [
            ("GET", "/v3.0/cloudFileSecurity/events",           {"top":1}, None,  "ruta actual"),
            ("GET", "/v3.0/cloudFileSecurity/alerts",           {"top":1}, None,  "alerts"),
            ("GET", "/v3.0/cloudFile/events",                   {"top":1}, None,  "cloudFile/events"),
            ("GET", "/v3.0/filesSecurity/events",               {"top":1}, None,  "filesSecurity"),
            ("GET", "/v3.0/cloudStorage/events",                {"top":1}, None,  "cloudStorage"),
        ],
        "cloud posture / conformity": [
            ("GET", "/v3.0/cloudPosture/assessmentSummaries",   {"top":1}, None,  "ruta actual"),
            ("GET", "/v3.0/cloudPosture/checks",                {"top":1}, None,  "checks"),
            ("GET", "/v3.0/cloudPosture/findings",              {"top":1}, None,  "findings"),
            ("GET", "/v3.0/cloudSecurity/posture",              {"top":1}, None,  "cloudSecurity/posture"),
            ("GET", "/v3.0/conformity/checks",                  {"top":1}, None,  "conformity/checks"),
            ("GET", "/v3.0/cloudPosture/summary",               None,      None,  "summary"),
        ],

        # ── Threat Intelligence ───────────────────────────────────────────────
        "sandbox": [
            ("GET", "/v3.0/sandbox/submissionList",             {"top":1}, None,  "ruta actual"),
            ("GET", "/v3.0/sandbox/submissions",                {"top":1}, None,  "submissions"),
            ("GET", "/v3.0/sandbox/tasks",                      {"top":1}, None,  "tasks"),
            ("GET", "/v3.0/sandbox/results",                    {"top":1}, None,  "results"),
            ("GET", "/v3.0/sandbox/analyses",                   {"top":1}, None,  "analyses"),
        ],
        "suspicious objects (403)": [
            ("GET", "/v3.0/threatintel/suspiciousObjects",      {"top":1}, None,  "ruta actual"),
            ("GET", "/v3.0/threatIntelligence/suspiciousObjects",{"top":1},None,  "camelCase"),
            ("GET", "/v3.0/ioc/objects",                        {"top":1}, None,  "ioc/objects"),
            ("GET", "/v3.0/ioc/suspiciousObjects",              {"top":1}, None,  "ioc/suspiciousObjects"),
            ("GET", "/v3.0/intel/suspiciousObjects",            {"top":1}, None,  "intel/suspiciousObjects"),
        ],
        "intel reports (403)": [
            ("GET", "/v3.0/threatintel/intelligenceReports",    None,      None,  "ruta actual"),
            ("GET", "/v3.0/threatIntelligence/reports",         None,      None,  "threatIntelligence/reports"),
            ("GET", "/v3.0/intel/reports",                      None,      None,  "intel/reports"),
            ("GET", "/v3.0/intelligenceReports",                None,      None,  "top-level"),
        ],
        "stix sweeping": [
            ("GET", "/v3.0/threatintel/stixSweepingTasks",      {"top":1}, None,  "ruta actual"),
            ("GET", "/v3.0/stix/tasks",                         {"top":1}, None,  "stix/tasks"),
            ("GET", "/v3.0/threatIntelligence/stix",            {"top":1}, None,  "threatIntelligence/stix"),
            ("GET", "/v3.0/sweeping/tasks",                     {"top":1}, None,  "sweeping/tasks"),
            ("GET", "/v3.0/ioc/sweepingTasks",                  {"top":1}, None,  "ioc/sweepingTasks"),
        ],

        # ── Identity ──────────────────────────────────────────────────────────
        "risk insights global": [
            ("GET", "/v3.0/riskInsights/riskScore",             None,      None,  "ruta actual"),
            ("GET", "/v3.0/riskInsights",                       None,      None,  "riskInsights top-level"),
            ("GET", "/v3.0/riskInsights/summary",               None,      None,  "summary"),
            ("GET", "/v3.0/cyberRisk/riskScore",                None,      None,  "cyberRisk/riskScore"),
            ("GET", "/v3.0/risk/score",                         None,      None,  "risk/score"),
        ],
        "identity accounts": [
            ("GET", "/v3.0/iam/accounts",                       {"top":1}, None,  "ruta actual"),
            ("GET", "/v3.0/iam/accounts",                       None,      None,  "sin params"),
            ("GET", "/v3.0/identity/accounts",                  {"top":1}, None,  "identity/accounts"),
            ("GET", "/v3.0/accounts",                           {"top":1}, None,  "accounts top-level"),
            ("GET", "/v3.0/iam/users",                          {"top":1}, None,  "iam/users"),
        ],
        "identity risk": [
            ("GET", "/v3.0/iam/accountsRiskInsight",            {"top":1}, None,  "ruta actual"),
            ("GET", "/v3.0/iam/riskInsight",                    {"top":1}, None,  "riskInsight (short)"),
            ("GET", "/v3.0/identity/risk",                      {"top":1}, None,  "identity/risk"),
            ("GET", "/v3.0/iam/riskyAccounts",                  {"top":1}, None,  "riskyAccounts"),
            ("GET", "/v3.0/riskInsights/accounts",              {"top":1}, None,  "riskInsights/accounts"),
        ],

        # ── Network ───────────────────────────────────────────────────────────
        "network sensors": [
            ("GET", "/v3.0/networkSecurity/sensors",            {"top":1}, None,  "ruta actual"),
            ("GET", "/v3.0/networkSecurity/appliances",         {"top":1}, None,  "appliances"),
            ("GET", "/v3.0/networkSecurity/devices",            {"top":1}, None,  "devices"),
            ("GET", "/v3.0/network/sensors",                    {"top":1}, None,  "network/sensors"),
            ("GET", "/v3.0/networkSensor/sensors",              {"top":1}, None,  "networkSensor"),
            ("GET", "/v3.0/networkSecurity/agents",             {"top":1}, None,  "networkSecurity/agents"),
        ],
        "network policies": [
            ("GET", "/v3.0/networkSecurity/policies",           {"top":1}, None,  "ruta actual"),
            ("GET", "/v3.0/networkSecurity/rules",              {"top":1}, None,  "rules"),
            ("GET", "/v3.0/network/policies",                   {"top":1}, None,  "network/policies"),
            ("GET", "/v3.0/networkSecurity/firewallPolicies",   {"top":1}, None,  "firewallPolicies"),
        ],

        # ── Auditoría ─────────────────────────────────────────────────────────
        "audit logs": [
            ("GET", "/v3.0/auditLogs",                          {"top":1}, None,  "ruta actual"),
            ("GET", "/v3.0/audit/logs",                         {"top":1}, None,  "audit/logs"),
            ("GET", "/v3.0/audit",                              {"top":1}, None,  "audit top-level"),
            ("GET", "/v3.0/logs/audit",                         {"top":1}, None,  "logs/audit"),
            ("GET", "/v3.0/activityLogs",                       {"top":1}, None,  "activityLogs"),
            ("GET", "/v3.0/administration/auditLogs",           {"top":1}, None,  "administration/auditLogs"),
        ],

        # ── Respuesta ─────────────────────────────────────────────────────────
        "response tasks (403)": [
            ("GET", "/v3.0/response/tasks",                     {"top":1}, None,  "ruta actual"),
            ("GET", "/v3.0/responseManagement/tasks",           {"top":1}, None,  "responseManagement/tasks"),
            ("GET", "/v3.0/tasks",                              {"top":1}, None,  "tasks top-level"),
            ("GET", "/v3.0/response/actions",                   {"top":1}, None,  "response/actions"),
            ("GET", "/v3.0/responseManagement/actions",         {"top":1}, None,  "responseManagement/actions"),
        ],

        # ── Contenedores ──────────────────────────────────────────────────────
        "container security": [
            ("GET", "/v3.0/containerSecurity/alerts",           {"top":1}, None,  "ruta actual"),
            ("GET", "/v3.0/containerSecurity/events",           {"top":1}, None,  "events"),
            ("GET", "/v3.0/container/alerts",                   {"top":1}, None,  "container/alerts"),
            ("GET", "/v3.0/containers/security/alerts",         {"top":1}, None,  "containers/security"),
            ("GET", "/v3.0/containerSecurity/findings",         {"top":1}, None,  "findings"),
            ("GET", "/v3.0/containerSecurity/vulnerabilities",  {"top":1}, None,  "vulnerabilities"),
        ],
    }

    total_paths = sum(len(v) for v in ALL_PROBES.values())
    print(f"\n  {BOLD('Descubrimiento exhaustivo de rutas — ' + str(total_paths) + ' paths para ' + str(len(ALL_PROBES)) + ' módulos')}")

    found_any = []
    for mod_name, probes in ALL_PROBES.items():
        found_here = []
        rows = []
        for method, path, params, body, desc in probes:
            p = path.replace(G, "{guid}") if G and G in path else path
            display = f"{method} {p}"
            if G == "" and "{G}" in path:
                rows.append((display, None, desc))
                continue
            st = _st(method, path, params, body)
            rows.append((display, st, desc))
            if st in (200, 400, 405):
                found_here.append((method, path, st, desc))

        # Imprimir cabecera del módulo
        status_icon = OK("✓") if found_here else DIM("✗")
        print(f"\n  {status_icon} {BOLD(mod_name.upper())}")
        print(f"  {'─'*70}")
        for display, st, desc in rows:
            if st is None:
                print(f"    {DIM('(sin GUID)'):<64}")
                continue
            if st == 200:
                tag = OK(f"[{st}]")
                note = OK("← DATOS")
            elif st in (400, 405):
                tag = WARN(f"[{st}]")
                note = WARN("← EXISTE (params incorrectos)")
            elif st == 403:
                tag = WARN(f"[{st}]")
                note = WARN("← CONTRATADO, sin permiso API key")
            elif st == 404:
                tag = DIM(f"[{st}]")
                note = DIM("no disponible")
            else:
                tag = ERR(f"[{st}]")
                note = ERR("error red")
            print(f"    {display:<62} {tag}  {DIM(desc)}  {note}")

        if found_here:
            found_any.extend(found_here)

    print(f"\n  {'='*70}")
    if found_any:
        print(OK(f"  RUTAS NUEVAS ENCONTRADAS ({len(found_any)}):"))
        for method, path, st, desc in found_any:
            p = path.replace(G, "{guid}") if G and G in path else path
            print(f"    [{st}] {method} {p}  ({desc})")
    else:
        print(DIM("  Ninguna ruta alternativa devuelve datos. Los módulos probados no"))
        print(DIM("  están disponibles en este tenant vía API o necesitan otros permisos."))
    print()


# ── CVE path probe ───────────────────────────────────────────────────────────
def _probe_cve_paths(client, first_guid: str = ""):
    """Prueba todas las rutas CVE conocidas y muestra el HTTP status de cada una."""
    import urllib.error

    def _st(method, path, params=None, body=None):
        try:
            client._req(method, path, params, body)
            return 200
        except Exception as ex:
            msg = str(ex)
            import re as _re
            m = _re.search(r"(\d{3})", msg)
            return int(m.group(1)) if m else 0

    paths = [
        # ── CREM / ASRM — ruta correcta confirmada ────────────────────────────
        ("GET",  "/v3.0/asrm/vulnerableDevices",           {"top":1,"cveDetectionStatus":"any"}, None),
        # ── Threat and Exposure Management (TEM) — módulo que ves en la consola ──
        ("GET",  "/v3.0/threatAndExposureManagement/vulnerabilities",           {"top":1}, None),
        ("GET",  "/v3.0/threatAndExposureManagement/endpoints",                 {"top":1}, None),
        ("GET",  "/v3.0/threatAndExposureManagement/cves",                      {"top":1}, None),
        ("GET",  "/v3.0/tem/vulnerabilities",                                   {"top":1}, None),
        ("GET",  "/v3.0/tem/endpoints",                                         {"top":1}, None),
        # ── Exposure Management ───────────────────────────────────────────────
        ("GET",  "/v3.0/exposureManagement/vulnerabilities",                    {"top":1}, None),
        ("GET",  "/v3.0/exposureManagement/endpoints",                          {"top":1}, None),
        ("GET",  "/v3.0/exposures/vulnerabilities",                             {"top":1}, None),
        # ── Attack Surface / Cyber Risk ───────────────────────────────────────
        ("GET",  "/v3.0/attackSurface/vulnerabilities",                         {"top":1}, None),
        ("GET",  "/v3.0/cyberRisk/vulnerabilities",                             {"top":1}, None),
        ("GET",  "/v3.0/cyberRisk/endpoints",                                   {"top":1}, None),
        # ── Asset Management ──────────────────────────────────────────────────
        ("GET",  "/v3.0/assetManagement/vulnerabilities",                       {"top":1}, None),
        ("GET",  "/v3.0/assetManagement/endpoints",                             {"top":1}, None),
        # ── Aggregate CVE via Endpoint Security ───────────────────────────────
        ("GET",  "/v3.0/endpointSecurity/vulnerabilities",                      {"top":1}, None),
        ("GET",  "/v3.0/endpointSecurity/vulnerabilityManagement/vulnerabilities",{"top":1},None),
        ("GET",  "/v3.0/endpointSecurity/vulnerability",                        {"top":1}, None),
        # ── Per-endpoint CVE (si tenemos GUID) ────────────────────────────────
        ("GET",  f"/v3.0/endpointSecurity/endpoints/{first_guid}/vulnerabilities",  {"top":1}, None),
        ("GET",  f"/v3.0/endpointSecurity/endpoints/{first_guid}/exposures",        {"top":1}, None),
        # ── ASM ──────────────────────────────────────────────────────────────
        ("GET",  "/v3.0/asm/vulnerabilities",                                   {"top":1}, None),
        ("GET",  "/v3.0/asm/findings",                                          {"top":1}, None),
        # ── Risk Insights / Vulnerability Management standalone ───────────────
        ("GET",  "/v3.0/vulnerabilityManagement/vulnerabilities",               {"top":1}, None),
        ("GET",  "/v3.0/riskInsights/vulnerabilities",                          {"top":1}, None),
        ("GET",  "/v3.0/riskInsights/endpoints",                                {"top":1}, None),
        # ── Endpoint Security agent details ───────────────────────────────────
        ("GET",  f"/v3.0/endpointSecurity/endpoints/{first_guid}",              None,      None),
        # ── Legacy / v2 ──────────────────────────────────────────────────────
        ("GET",  "/v2.0/endpointSecurity/vulnerabilities",                      {"top":1}, None),
        ("GET",  f"/v2.0/endpointSecurity/endpoints/{first_guid}/vulnerabilities",{"top":1},None),
        # ── Search-based CVE detection ────────────────────────────────────────
        ("POST", "/v3.0/search/detections", None,
         {"query":"eventSubType:VULNERABILITY_DETECTION","source":"detections","size":1}),
    ]

    print(f"\n  {BOLD('CVE Path Discovery — probando ' + str(len(paths)) + ' rutas...')}")
    print(f"  {'Ruta':<65} {'HTTP':>5}  Estado")
    print(f"  {'-'*74}")
    found = []
    for method, path, params, body in paths:
        display = f"{method} {path}"
        if not first_guid and "{first_guid}" in path or (first_guid and first_guid in path and not first_guid):
            st_str = DIM("  (sin GUID)  ")
            print(f"  {display:<65} {DIM('  N/A'):>5}  {st_str}")
            continue
        st = _st(method, path, params, body)
        if st == 200:
            tag = OK(f"{st:>5}")
            note = OK("DATOS DISPONIBLES ← usa esta ruta")
            found.append((method, path))
        elif st in (400, 405):
            tag = WARN(f"{st:>5}")
            note = WARN("endpoint existe (params incorrectos, pero accesible)")
            found.append((method, path))
        elif st == 403:
            tag = WARN(f"{st:>5}")
            note = WARN("contratado pero API key sin permiso")
        elif st == 404:
            tag = DIM(f"{st:>5}")
            note = DIM("no disponible en este tenant")
        else:
            tag = ERR(f"{st:>5}")
            note = ERR("error")
        print(f"  {display:<65} {tag}  {note}")

    if found:
        print()
        print(OK(f"  RUTAS FUNCIONANDO ({len(found)}):"))
        for m, p in found:
            print(f"    {m} {p}")
    else:
        print()
        print(ERR("  Ninguna ruta CVE devuelve datos. "))
        print(ERR("  Posibles causas:"))
        print(ERR("  1. El módulo 'Vulnerability Management' no está habilitado en Vision One"))
        print(ERR("  2. La API key necesita rol 'Attack Surface Risk Management'"))
        print(ERR("  3. Los datos CVE solo están disponibles en la consola, no por API"))


def _dump_endpoint_fields(client):
    """Imprime todos los campos del primer endpoint (lista y detalle) para ver qué datos hay."""
    try:
        r = client._req("GET", "/v3.0/endpointSecurity/endpoints")
        items = r.get("items", r.get("data", r.get("value", [])))
        if not items:
            print(WARN("  No hay endpoints en el inventario"))
            return
        ep = items[0]
        guid = ep.get("agentGuid") or ep.get("endpointId") or ep.get("id") or ""
        name = ep.get("endpointName") or ep.get("displayName") or ep.get("name", "?")

        # ── Campos del listado ────────────────────────────────────────────────
        print(f"\n  {BOLD('Campos en el listado (/endpoints) — ' + name)}")
        print(f"  {'-'*66}")
        _print_ep_fields(ep)

        # ── Campos del detalle ────────────────────────────────────────────────
        if guid:
            try:
                detail = client._req("GET", f"/v3.0/endpointSecurity/endpoints/{guid}")
                if detail:
                    print(f"\n  {BOLD('Campos en el detalle (/endpoints/' + guid[:8] + '...) — campos EXTRA:')}")
                    print(f"  {'-'*66}")
                    extra = {k: v for k, v in detail.items() if k not in ep}
                    if extra:
                        _print_ep_fields(extra)
                    else:
                        print(f"  {DIM('(sin campos extra respecto al listado)')}")
            except Exception as ex:
                print(WARN(f"  No se pudo obtener detalle: {ex}"))
    except Exception as ex:
        print(ERR(f"  Error obteniendo endpoint: {ex}"))


def _print_ep_fields(ep: dict):
    import json as _json
    interesting = []
    for k, v in sorted(ep.items()):
        if isinstance(v, (dict, list)):
            v_str = _json.dumps(v, ensure_ascii=False)[:120]
        else:
            v_str = str(v)
        v_str = v_str[:120] + ("…" if len(str(v)) > 120 else "")
        k_lower = k.lower()
        is_key = any(x in k_lower for x in (
            "vuln","cve","cvss","risk","score","patch","security","protect",
            "threat","malware","antivirus","firewall","ips","dlp","status","health",
            "detect","sensor","edr","epp","license","credit"
        ))
        if is_key:
            print(f"  {OK('★')} {k:<42} {INFO(v_str)}")
            interesting.append(k)
        else:
            print(f"    {k:<42} {DIM(v_str)}")
    if interesting:
        print()
        print(OK(f"  Campos relevantes: {', '.join(interesting)}"))


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    # Forzar UTF-8 en la salida para evitar errores de encoding en Windows
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    parser = argparse.ArgumentParser(
        description="Test de extracción Vision One API",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--empresa", default="ACME",
                        help="Nombre de la empresa (busca en CLIENTES/[empresa]/.env)")
    parser.add_argument("--env",     dest="env_file", default=None,
                        help="Ruta explícita al archivo .env")
    parser.add_argument("--mes",     default=None,
                        help='Período del informe, ej. "Mayo 2026". Por defecto: mes actual')
    parser.add_argument("--quick",   action="store_true",
                        help="Solo descubrimiento + test conexión, sin fetch de datos")
    parser.add_argument("--probe-cve", action="store_true",
                        help="Prueba exhaustiva de rutas CVE alternativas para diagnosticar")
    parser.add_argument("--probe-all", action="store_true",
                        help="Prueba rutas alternativas para TODOS los módulos que fallan")
    parser.add_argument("--dump-endpoint", action="store_true",
                        help="Muestra todos los campos del primer endpoint (para ver qué datos hay)")
    parser.add_argument("--json",    dest="out_json", default=None,
                        help="Guarda resultados en JSON en la ruta indicada")
    args = parser.parse_args()

    # Mes por defecto = mes actual
    if args.mes:
        mes = args.mes
    else:
        MESES_ES = ["Enero","Febrero","Marzo","Abril","Mayo","Junio",
                    "Julio","Agosto","Septiembre","Octubre","Noviembre","Diciembre"]
        now = datetime.now()
        mes = f"{MESES_ES[now.month - 1]} {now.year}"

    env_path = _resolve_env(args.empresa, args.env_file)

    # Importar cliente
    here = Path(__file__).parent
    api_path = here / "trendai_api.py"
    if not api_path.exists():
        sys.exit(ERR(f"ERROR: No se encontro trendai_api.py en {here}"))

    spec    = importlib.util.spec_from_file_location("trendai_api", str(api_path))
    trendai = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(trendai)

    # Conectar
    try:
        client = trendai.TrendAIClient.from_env(str(env_path))
    except Exception as ex:
        sys.exit(ERR(f"ERROR leyendo .env: {ex}"))

    region_label = next((k for k, v in trendai.REGIONS.items() if v == client.base_url), "?")
    _print_header(args.empresa, mes, region_label, env_path)

    # Test conexión
    print(f"  {INFO('Verificando conexion...')}  ", end="", flush=True)
    t0 = time.monotonic()
    conn = client.test_connection()
    elapsed_conn = time.monotonic() - t0
    if conn.get("ok"):
        print(OK(f"[OK] {conn['message']}") + DIM(f"  ({elapsed_conn:.2f}s)"))
    else:
        print(ERR(f"[FAIL] {conn['message']}"))
        sys.exit(1)

    # Descubrir módulos
    print(f"\n  {INFO('Descubriendo modulos disponibles...')}  ", end="", flush=True)
    t1 = time.monotonic()
    modules = client.discover_modules()
    mod_status = getattr(client, "module_status", {})
    elapsed_disc = time.monotonic() - t1
    avail_count      = sum(1 for v in modules.values() if v)
    forbidden_count  = sum(1 for s in mod_status.values() if s == 403)
    not_cont_count   = sum(1 for s in mod_status.values() if s == 404)
    print(OK(f"[OK] {avail_count}/{len(modules)} accesibles") +
          (WARN(f"  {forbidden_count} bloqueados (403)") if forbidden_count else "") +
          DIM(f"  ({elapsed_disc:.1f}s)"))

    if args.quick:
        print()
        groups: dict = {}
        for name, avail in modules.items():
            _, _, grp = MODULE_META.get(name, ("?", name, "Otros"))
            groups.setdefault(grp, []).append(
                (name, avail, "", None, mod_status.get(name, 0))
            )
        for grp, rows in groups.items():
            _print_group(grp, rows)
        _print_summary(len(modules), avail_count, forbidden_count, not_cont_count,
                       0, time.monotonic() - t0, [], mod_status)
        return

    # Rango de fechas del mes
    try:
        start, end = trendai._month_range(mes)
    except Exception:
        now2 = datetime.now(tz=timezone.utc)
        start = now2.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        end   = now2

    print(f"  Periodo  : {DIM(start.strftime('%Y-%m-%d'))} -> {DIM(end.strftime('%Y-%m-%d'))}")

    # Fetch muestras
    print(f"\n  {INFO('Probando extraccion de datos...')}\n")

    groups: dict = {}
    results: dict = {}
    errors: list  = []
    total_sample  = 0

    for name, avail in modules.items():
        _, _, grp = MODULE_META.get(name, ("?", name, "Otros"))
        http_st = mod_status.get(name, 0)
        if avail:
            print(f"  {DIM(f'  [{name}]...'): <40}", end="", flush=True)
            t_s = time.monotonic()
            cnt, count_str, err = _sample_fetch(client, name, start, end)
            elapsed_s = time.monotonic() - t_s
            print(f"\r  ", end="")  # limpiar línea
            if err:
                errors.append(f"{name}: {err}")
            else:
                total_sample += cnt
            results[name] = {"available": True, "http_status": http_st, "count": cnt,
                             "label": count_str, "error": err, "elapsed": round(elapsed_s, 2)}
        else:
            results[name] = {"available": False, "http_status": http_st,
                             "count": 0, "label": "", "error": None, "elapsed": 0}

        groups.setdefault(grp, []).append(
            (name, avail, results[name]["label"], results[name]["error"], http_st)
        )

    # Mostrar resultados por grupo
    for grp, rows in groups.items():
        _print_group(grp, rows)

    total_elapsed = time.monotonic() - t0
    _print_summary(len(modules), avail_count, forbidden_count, not_cont_count,
                   total_sample, total_elapsed, errors, mod_status)

    # ── Diagnósticos opcionales ───────────────────────────────────────────────
    if args.dump_endpoint or args.probe_cve or args.probe_all:
        # Obtener GUID del primer endpoint (necesario para rutas per-endpoint)
        first_guid = ""
        try:
            ri = client._req("GET", "/v3.0/endpointSecurity/endpoints")
            batch = ri.get("items", ri.get("data", ri.get("value", [])))
            if batch:
                first_guid = (batch[0].get("agentGuid") or
                              batch[0].get("endpointId") or
                              batch[0].get("id") or "")
        except Exception:
            pass

        if args.dump_endpoint:
            _dump_endpoint_fields(client)
        if args.probe_all:
            _probe_all_paths(client, first_guid)
        if args.probe_cve:
            _probe_cve_paths(client, first_guid)
        print()

    # Guardar JSON si se pidió
    if args.out_json:
        out = {
            "empresa":          args.empresa,
            "mes":              mes,
            "region":           region_label,
            "tested_at":        datetime.now().isoformat(),
            "elapsed_s":        round(total_elapsed, 2),
            "modules":          results,
            "avail_count":      avail_count,
            "forbidden_count":  forbidden_count,
            "not_contracted":   not_cont_count,
            "total_mods":       len(modules),
            "sample_rows":      total_sample,
            "errors":           errors,
            "module_status":    mod_status,
        }
        Path(args.out_json).write_text(
            json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"  Resultados guardados en {INFO(args.out_json)}\n")


if __name__ == "__main__":
    main()
