#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
trendai_api.py v3 — Cliente Vision One API
Descubrimiento automático de módulos disponibles (paralelo) + extracción máxima de datos.

Uso:
    python trendai_api.py --empresa ACME --mes "Mayo 2026" --test
    python trendai_api.py --empresa ACME --mes "Mayo 2026"
    python trendai_api.py --empresa ACME --mes "Mayo 2026" --verbose
    python trendai_api.py --empresa ACME --mes "Mayo 2026" --discover
"""

import ipaddress
import json, os, sys, time, logging
import urllib.request, urllib.parse, urllib.error
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Tuple

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

logger = logging.getLogger(__name__)


# ── Regiones ──────────────────────────────────────────────────────────────────
REGIONS = {
    "EU":  "https://api.eu.xdr.trendmicro.com",
    "US":  "https://api.xdr.trendmicro.com",
    "AU":  "https://api.au.xdr.trendmicro.com",
    "IN":  "https://api.in.xdr.trendmicro.com",
    "SG":  "https://api.sg.xdr.trendmicro.com",
    "JP":  "https://api.jp.xdr.trendmicro.com",
}

SEV_MAP = {"critical":"Critical","high":"High","medium":"Medium","low":"Low","info":"Low","informational":"Low"}

def _sev(s): return SEV_MAP.get(str(s).lower(), str(s).capitalize() if s else "Medium")

def _fmt(iso):
    if not iso: return ""
    try:
        dt = datetime.fromisoformat(str(iso).replace("Z","+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception: return str(iso)[:19].replace("T"," ")

def _month_range(mes_es: str) -> Tuple[datetime, datetime]:
    MESES = {"Enero":1,"Febrero":2,"Marzo":3,"Abril":4,"Mayo":5,"Junio":6,
             "Julio":7,"Agosto":8,"Septiembre":9,"Octubre":10,"Noviembre":11,"Diciembre":12}
    parts = str(mes_es).strip().split()
    m = MESES.get(parts[0], 1)
    y = int(parts[1]) if len(parts) > 1 else datetime.now().year
    s = datetime(y, m, 1, tzinfo=timezone.utc)
    e = datetime(y+1 if m==12 else y, 1 if m==12 else m+1, 1, tzinfo=timezone.utc)
    return s, e

def _defang(t):
    if not t: return t
    return str(t).replace("https://","hxxps://").replace("http://","hxxp://").replace("www.","www[.]")


class TrendAIError(RuntimeError):
    """Error HTTP de Vision One. Expone .status para distinguir 400/403/404."""
    def __init__(self, status: int, path: str, body: str = ""):
        self.status = status
        self.path   = path
        self.body   = body
        super().__init__(f"HTTP {status or 'red'} en {path}" + (f": {body[:200]}" if body else ""))


# ══════════════════════════════════════════════════════════════════════════════
class TrendAIClient:
    """
    Cliente Vision One API v3.
    Auto-descubre módulos disponibles y extrae el máximo de datos posible.
    """

    def __init__(self, api_key: str, region: str = "EU", timeout: int = 30, discovered_by_filter: str = ""):
        self.api_key   = api_key.strip()
        self.base_url  = REGIONS.get(region.upper(), REGIONS["EU"])
        self.timeout   = timeout
        self.modules: Dict[str, bool] = {}   # módulos descubiertos
        # Filtro opcional TMV1-Filter aplicado a los endpoints ASRM (discoveredBy)
        # ej: "discoveredBy hassubset(['Server & Workload Protection'])"
        self.discovered_by_filter = discovered_by_filter.strip()

    @classmethod
    def from_env(cls, env_path: str) -> "TrendAIClient":
        p = Path(env_path)
        if not p.exists(): raise FileNotFoundError(f"No existe {env_path}")
        cfg = {}
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line: continue
            k, _, v = line.partition("=")
            cfg[k.strip()] = v.strip().strip('"').strip("'")
        key = cfg.get("TRENDAI_API_KEY","")
        if not key: raise ValueError(f"TRENDAI_API_KEY no encontrada en {env_path}")
        return cls(key, cfg.get("TRENDAI_REGION","EU"),
                   discovered_by_filter=cfg.get("TRENDAI_DISCOVERED_BY_FILTER",""))

    # ── HTTP ──────────────────────────────────────────────────────────────────
    def _req(self, method: str, path: str, params=None, body=None, retries=3, tmv1_filter: str = "") -> dict:
        url = self.base_url + path
        if params:
            url += "?" + urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type":  "application/json;charset=utf-8",
            "Accept":        "application/json",
        }
        if tmv1_filter:
            headers["TMV1-Filter"] = tmv1_filter
        data = json.dumps(body).encode("utf-8") if body else None
        req  = urllib.request.Request(url, data=data, headers=headers, method=method)
        for attempt in range(retries):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    raw = r.read().decode("utf-8")
                    return json.loads(raw) if raw.strip() else {}
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    # En el ultimo intento hay que propagar el 429 REAL. Si se cae
                    # por el final del bucle se lanza status 0, y quien sondea
                    # modulos lo interpreta como "no contratado" y termina
                    # borrando la seccion entera del informe sin avisar.
                    if attempt >= retries - 1:
                        raise TrendAIError(429, path,
                                           f"Rate limit persistente tras {retries} intentos")
                    try:
                        retry_after = int(e.headers.get("Retry-After", "10"))
                    except ValueError:
                        retry_after = 10  # Retry-After puede venir como fecha HTTP en vez de segundos
                    retry_after = min(max(retry_after, 1), 60)  # tope para no colgar el proceso
                    logger.warning(f"Rate limited on {path} — esperando {retry_after}s (intento {attempt+1}/{retries})")
                    time.sleep(retry_after)
                    continue
                body_e = ""
                try: body_e = e.read().decode("utf-8")[:500]
                except Exception: pass
                if e.code >= 500 and attempt < retries - 1:
                    wait = 2 ** attempt
                    logger.warning(f"HTTP {e.code} en {path}, reintento {attempt+1}/{retries} en {wait}s")
                    time.sleep(wait)
                    continue
                raise TrendAIError(e.code, path, body_e)
            except urllib.error.URLError as ex:
                reason = str(ex.reason) if hasattr(ex, "reason") else str(ex)
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                raise TrendAIError(0, path, f"Error de red: {reason}")
            except Exception as ex:
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                raise TrendAIError(0, path, str(ex))
        raise TrendAIError(0, path, f"Agotados {retries} intentos en {path}")

    def _is_available(self, method: str, path: str, params=None, body=None) -> bool:
        """
        True si el módulo está disponible y accesible con esta API key.
          200 / 400 / 405  → disponible (400/405 = endpoint existe, params erróneos)
          403              → módulo contratado pero API key sin permiso → False
          401 / 404        → no contratado o key inválida → False
          0 (red)          → sin conexión → False
        """
        try:
            self._req(method, path, params=params, body=body)
            return True
        except TrendAIError as e:
            return e.status in (400, 405)

    def _probe_status(self, method: str, path: str, params=None, body=None) -> int:
        """
        Devuelve el HTTP status real de un endpoint para diagnóstico.
          200       → disponible y OK
          400/405   → endpoint existe (params o método incorrecto, pero accesible)
          403       → contratado pero API key sin permisos suficientes
          404       → módulo no contratado en este tenant
          401       → API key inválida
          0         → error de red / timeout
        """
        try:
            self._req(method, path, params=params, body=body)
            return 200
        except TrendAIError as e:
            return e.status
        except Exception:
            return 0

    def _probe(self, path: str, params=None) -> Tuple[bool, List[dict]]:
        """Compat: prueba GET y devuelve (disponible, items)."""
        try:
            r = self._req("GET", path, params or {"top":1})
            items = r.get("items", r.get("data", r.get("value", [])))
            return True, items
        except TrendAIError as e:
            return (e.status in (400, 405)), []

    def _pages(self, path: str, params=None, max_items=3000, tmv1_filter: str = "") -> List[dict]:
        """Obtiene todas las páginas."""
        items, p, current = [], dict(params or {}), path
        p.setdefault("top", 200)
        total_count = None
        while current and len(items) < max_items:
            r = self._req("GET", current if current.startswith("/") else path,
                          p if current == path else None, tmv1_filter=tmv1_filter)
            batch = r.get("items", r.get("data", r.get("value", [])))
            items.extend(batch)
            if total_count is None:
                total_count = r.get("totalCount")
            nl = r.get("nextLink","") or r.get("@odata.nextLink","")
            if nl:
                prs = urllib.parse.urlparse(nl)
                current = prs.path + ("?" + prs.query if prs.query else "")
                p = None
            else:
                break
        # Si la API reporta más registros de los que el scope de la key permite ver,
        # aquí no llega error (200 OK) — solo se ven menos filas de las reales.
        if total_count is not None and total_count > len(items):
            logger.warning(
                f"{path}: API reporta totalCount={total_count} pero solo se obtuvieron "
                f"{len(items)} — revisa el 'Data and app assets' scope del rol asignado a la API key"
            )
        return items[:max_items]

    def _search(self, query: str, start_str: str, end_str: str,
                source="detections", max_items=500) -> List[dict]:
        """Search API — POST /v3.0/search/detections"""
        try:
            r = self._req("POST", "/v3.0/search/detections", body={
                "query": query, "from": start_str, "to": end_str,
                "source": source,
            })
            return r.get("items", r.get("logs", []))[:max_items]
        except TrendAIError as e:
            logger.warning(f"search query='{query[:40]}': HTTP {e.status} — {e.body[:80]}")
            return []
        except Exception as e:
            logger.warning(f"search: {e}")
            return []

    # ── CONNECTION TEST ─────────────────────────────────────────────────────
    def test_connection(self) -> dict:
        """
        Verifica la API key probando varios endpoints en orden.
        Devuelve {ok, message, endpoint, region}.
        """
        region_label = next((k for k, v in REGIONS.items() if v == self.base_url), "?")
        tests = [
            ("/v3.0/workbench/alerts",                 {"top": 1}, "Workbench"),
            ("/v3.0/asrm/vulnerableDevices",            {"top": 1}, "CREM/ASRM"),
            ("/v3.0/endpointSecurity/endpoints",        None,       "Endpoint Security"),
        ]
        forbidden_modules = []
        for path, params, label in tests:
            try:
                self._req("GET", path, params)
                return {
                    "ok":       True,
                    "message":  f"Conexión OK — {label} ({region_label})",
                    "endpoint": label,
                    "region":   region_label,
                }
            except TrendAIError as e:
                if e.status == 401:
                    return {"ok": False, "message": "API key inválida — verifica la clave (HTTP 401)", "region": region_label}
                if e.status == 0:
                    return {"ok": False, "message": f"Sin conexión con {self.base_url} — verifica la región y la red", "region": region_label}
                if e.status in (400, 405):
                    # Endpoint existe, params son incorrectos — key válida
                    return {"ok": True, "message": f"Conexión OK — {label} disponible ({region_label})", "endpoint": label, "region": region_label}
                if e.status == 403:
                    # Módulo sin permiso — continuar probando los demás
                    forbidden_modules.append(label)
                    continue
                if e.status == 404:
                    continue
        # Todos los endpoints probados: si hay algunos con 403, la key es válida pero limitada
        if forbidden_modules:
            return {"ok": True,
                    "message": f"Conexión OK — key válida, módulos sin permiso: {', '.join(forbidden_modules)} ({region_label})",
                    "region": region_label}
        # Todos eran 404 (módulos no contratados)
        return {"ok": True, "message": f"Conexión OK — API key válida ({region_label})", "region": region_label}

    # ── MODULE DISCOVERY ──────────────────────────────────────────────────────
    def discover_modules(self) -> Dict[str, bool]:
        """
        Determina qué módulos tiene provisionados el cliente probando cada endpoint
        con su método HTTP real. 200/400/405 = provisionado; 401/403/404 = no disponible.
        """
        # name: (method, path, get_params, post_body)
        probes = {
            # ── Core XDR (siempre disponible) ──────────────────────────────
            "workbench":            ("GET",  "/v3.0/workbench/alerts",                       {"top":1}, None),
            "oat":                  ("GET",  "/v3.0/oat/detections",                        {"top":1}, None),
            "search":               ("POST", "/v3.0/search/detections",                      None, {"query":"*","source":"detections"}),
            # ── Endpoint Security ──────────────────────────────────────────
            "endpoint_inventory":   ("GET",  "/v3.0/endpointSecurity/endpoints",             None, None),
            "endpoint_eiqs":        ("GET",  "/v3.0/eiqs/endpoints",                         None, None),
            "endpoint_health":      ("GET",  "/v3.0/endpointSecurity/agentHealth",           {"top":1}, None),
            "endpoint_tasks":       ("GET",  "/v3.0/endpointSecurity/tasks",                 None, None),
            # ── CVE via Endpoint Security (fallback cuando ASM no disponible) ──
            "endpoint_vuln_agg":    ("GET",  "/v3.0/endpointSecurity/vulnerabilities",       {"top":1}, None),
            # ── CREM / ASRM (Cyber Risk Exposure Management) ───────────────
            # Rutas reales v3.0 (no llevan todas el prefijo "attackSurface"):
            #   vulnerableDevices, highRiskDevices NO llevan prefijo "attackSurface"
            #   attackSurfaceDevices y attackSurfacePublicIpAddresses SÍ lo llevan
            #   securityPosture y assetGroups no toman segmento de ID
            "asm_vuln":             ("GET",  "/v3.0/asrm/vulnerableDevices",                 {"top":1,"cveDetectionStatus":"any"}, None),
            "asm_endpoints":        ("GET",  "/v3.0/asrm/attackSurfaceDevices",              {"top":1}, None),
            "asm_assessments":      ("GET",  "/v3.0/asrm/securityPosture",                   {"top":1}, None),
            "asm_risk":             ("GET",  "/v3.0/asm/riskScore",                          None, None),
            "asm_attack_paths":     ("GET",  "/v3.0/asm/attackPaths",                        {"top":1}, None),
            "asrm_high_risk":       ("GET",  "/v3.0/asrm/highRiskDevices",                   {"top":1}, None),
            "asrm_asset_groups":    ("GET",  "/v3.0/asrm/assetGroups",                       {"top":1}, None),
            # ── Cloud & SaaS ───────────────────────────────────────────────
            "cloud_access":         ("GET",  "/v3.0/cloudAccess/riskAccessEvents",           {"top":1}, None),
            "cloud_email":          ("GET",  "/v3.0/emailSecurity/alerts",                   {"top":1}, None),
            "cloud_file_security":  ("GET",  "/v3.0/cloudFileSecurity/events",               {"top":1}, None),
            # ── Threat Intelligence ────────────────────────────────────────
            "sandbox":              ("GET",  "/v3.0/sandbox/tasks",                          {"top":1}, None),
            "suspicious_objects":   ("GET",  "/v3.0/threatintel/suspiciousObjects",          {"top":1}, None),
            "intel_reports":        ("GET",  "/v3.0/threatintel/intelligenceReports",        None, None),
            "intel_tasks":          ("GET",  "/v3.0/threatintel/stixSweepingTasks",          {"top":1}, None),
            # ── Risk & Identity ────────────────────────────────────────────
            "risk_insights":        ("GET",  "/v3.0/riskInsights/riskScore",                 None, None),
            "identity_accounts":    ("GET",  "/v3.0/iam/accounts",                           {"top":1}, None),
            "identity_risk":        ("GET",  "/v3.0/iam/accountsRiskInsight",                {"top":1}, None),
            # ── Network Security ───────────────────────────────────────────
            "network_sensor":       ("GET",  "/v3.0/networkSecurity/sensors",                {"top":1}, None),
            "network_policy":       ("GET",  "/v3.0/networkSecurity/policies",               {"top":1}, None),
            # ── Audit & Response ───────────────────────────────────────────
            "audit_logs":           ("GET",  "/v3.0/audit/logs",                              {"top":1}, None),
            "response_tasks":       ("GET",  "/v3.0/response/tasks",                         None, None),
            # ── Container Security ─────────────────────────────────────────
            "container_security":   ("GET",  "/v3.0/containerSecurity/vulnerabilities",      {"top":1}, None),
            # ── ASM Internet-Facing Assets ─────────────────────────────────
            "asm_internet_facing":  ("GET",  "/v3.0/asrm/attackSurfacePublicIpAddresses",    {"top":1}, None),
            # ── Email Quarantine ───────────────────────────────────────────
            "email_quarantine":     ("GET",  "/v3.0/emailSecurity/quarantineMessages",       {"top":1}, None),
            # ── Cloud Posture (Conformity) ─────────────────────────────────
            "cloud_posture":        ("GET",  "/v3.0/cloudPosture/assessmentSummaries",       {"top":1}, None),
            # ── Endpoint Isolation ─────────────────────────────────────────
            "endpoint_isolation":   ("GET",  "/v3.0/endpointSecurity/isolatedEndpoints",     {"top":1}, None),
            # ── XDR Observed Entities ──────────────────────────────────────
            "xdr_entities":         ("GET",  "/v3.0/xdr/impactedEntities",                   {"top":1}, None),
        }

        self.modules = {}
        self.module_status: Dict[str, int] = {}  # HTTP status real por módulo

        def _check_one(item):
            name, (method, path, params, body) = item
            status = self._probe_status(method, path, params, body)
            # disponible = 200 o 400/405 (endpoint existe aunque params sean incorrectos)
            available = status in (200, 400, 405)
            # 429 (rate limit) y 0 (red/timeout) NO significan "no contratado":
            # significan "no se ha podido determinar". Se siguen tratando como no
            # disponible, pero hay que avisar, porque el informe oculta la seccion
            # correspondiente y quedaria incompleto en silencio.
            if status in (0, 429):
                logger.warning(
                    f"Modulo '{name}': estado INDETERMINADO (HTTP {status}) — "
                    f"no se ha podido comprobar si esta contratado. "
                    f"La seccion correspondiente puede faltar en el informe.")
            return name, available, status

        # Probar en paralelo con máx 6 workers para evitar rate limiting
        with ThreadPoolExecutor(max_workers=6) as pool:
            for name, avail, status in pool.map(_check_one, probes.items()):
                self.modules[name]       = avail
                self.module_status[name] = status

        # Fase 2: probe per-endpoint CVE (necesita agentGuid real — no puede ir en paralelo)
        self.modules.setdefault("endpoint_vuln_detail", False)
        self.module_status.setdefault("endpoint_vuln_detail", 0)
        if self.modules.get("endpoint_inventory") and not self.modules.get("endpoint_vuln_agg"):
            try:
                resp  = self._req("GET", "/v3.0/endpointSecurity/endpoints")
                batch = resp.get("items", resp.get("data", []))
                if batch:
                    guid = batch[0].get("agentGuid") or batch[0].get("endpointId") or ""
                    if guid:
                        st = self._probe_status(
                            "GET",
                            f"/v3.0/endpointSecurity/endpoints/{guid}/vulnerabilities",
                            {"top": 1}
                        )
                        avail = st in (200, 400, 405)
                        self.modules["endpoint_vuln_detail"]       = avail
                        self.module_status["endpoint_vuln_detail"] = st
            except Exception as _ex:
                logger.debug(f"endpoint_vuln_detail probe: {_ex}")

        return self.modules

    # ── CYBER RISK INDEX ──────────────────────────────────────────────────────
    def get_cyber_risk_index(self) -> dict:
        """
        Consulta la API de Vision One únicamente para extraer el Cyber Risk Index / Risk Score.
        Devuelve dict:
            {"ok": True, "score": 36.2, "level": "Medium", "endpoint": "/v3.0/asrm/securityPosture", "raw": {...}}
        o {"ok": False, "message": "..."}
        """
        endpoints_to_try = [
            "/v3.0/asrm/securityPosture",
            "/v3.0/asrm/riskScore",
            "/v3.0/asm/riskScore",
            "/v3.0/riskInsights/riskScore",
            "/v3.0/asrm/riskIndicators",
        ]

        for path in endpoints_to_try:
            try:
                res = self._req("GET", path)
                if not res:
                    continue

                score = None
                level = None

                # Caso 1: objeto directo {"riskScore": 36.2, ...}
                for score_key in ["riskScore", "score", "value", "riskIndex", "overallRiskScore", "risk_score"]:
                    if score_key in res and res[score_key] is not None:
                        try:
                            score = float(res[score_key])
                            break
                        except (ValueError, TypeError):
                            pass

                # Caso 2: dentro de contenedor (items, data, value, securityPosture)
                if score is None:
                    container = res.get("items") or res.get("data") or res.get("value") or res.get("securityPosture")
                    if isinstance(container, list) and container:
                        item = container[0]
                        if isinstance(item, dict):
                            for score_key in ["riskScore", "score", "value", "riskIndex", "overallRiskScore"]:
                                if score_key in item and item[score_key] is not None:
                                    try:
                                        score = float(item[score_key])
                                        level = item.get("riskLevel") or item.get("level") or item.get("severity")
                                        break
                                    except (ValueError, TypeError):
                                        pass
                    elif isinstance(container, dict):
                        for score_key in ["riskScore", "score", "value", "riskIndex", "overallRiskScore"]:
                            if score_key in container and container[score_key] is not None:
                                try:
                                    score = float(container[score_key])
                                    level = container.get("riskLevel") or container.get("level") or container.get("severity")
                                    break
                                except (ValueError, TypeError):
                                    pass

                if score is not None:
                    if not level:
                        level = res.get("riskLevel") or res.get("level") or res.get("severity") or ""
                    level_str = str(level).capitalize() if level else (
                        "Critical" if score >= 75 else "High" if score >= 50 else "Medium" if score >= 25 else "Low"
                    )
                    return {
                        "ok": True,
                        "score": round(score, 1),
                        "level": level_str,
                        "endpoint": path,
                        "raw": res,
                    }
            except TrendAIError as e:
                logger.debug(f"get_cyber_risk_index: HTTP {e.status} en {path}")
            except Exception as ex:
                logger.debug(f"get_cyber_risk_index: error en {path}: {ex}")

        return {
            "ok": False,
            "message": "No se pudo obtener el Cyber Risk Index desde la API (endpoints ASRM no disponibles o API Key sin permiso ASRM)",
        }

    # ── FETCH METHODS ─────────────────────────────────────────────────────────


    def get_workbench_alerts(self, start: datetime, end: datetime) -> List[dict]:
        """
        Workbench Alerts: múltiples estrategias para maximizar cobertura.
        1. Por fecha del mes (Open + In Progress)
        2. Por fecha sin filtro de status
        3. Sin fechas (historial disponible)
        Deduplica por id.
        """
        if not self.modules.get("workbench"): return []
        all_items: List[dict] = []
        seen: set = set()

        def _merge(items):
            for a in items:
                aid = a.get("id","")
                if aid and aid not in seen:
                    all_items.append(a)
                    seen.add(aid)
                elif not aid:
                    all_items.append(a)

        s = start.strftime("%Y-%m-%dT%H:%M:%SZ")
        e = end.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Estrategia 1: con fecha + status Open
        for status in ("Open", "In Progress", None):
            params = {"startDateTime": s, "endDateTime": e}
            if status: params["investigationStatus"] = status
            try:
                _merge(self._pages("/v3.0/workbench/alerts", params, max_items=3000))
            except TrendAIError as e_:
                logger.warning(f"workbench status={status}: HTTP {e_.status} — {e_.body[:80]}")
            except Exception as e_:
                logger.warning(f"workbench status={status}: {e_}")

        # Estrategia 2: sin filtro de fecha (incluye alertas recientes fuera del rango)
        if len(all_items) < 5:
            try:
                _merge(self._pages("/v3.0/workbench/alerts", {}, max_items=1000))
            except Exception as e_:
                logger.warning(f"workbench sin fechas: {e_}")

        # Estrategia 3: por severidad si aún tenemos poco
        if len(all_items) < 5:
            for sev in ("critical", "high"):
                try:
                    _merge(self._pages("/v3.0/workbench/alerts",
                                       {"severity": sev, "startDateTime": s, "endDateTime": e},
                                       max_items=1000))
                except Exception as e_:
                    logger.warning(f"workbench sev={sev}: {e_}")

        logger.info(f"workbench_alerts total: {len(all_items)}")
        return all_items

    def get_oat_events(self, start: datetime, end: datetime) -> List[dict]:
        """Observed Attack Techniques — MITRE ATT&CK mappings"""
        if not self.modules.get("oat"): return []
        s = start.strftime("%Y-%m-%dT%H:%M:%SZ")
        e = end.strftime("%Y-%m-%dT%H:%M:%SZ")
        # Ruta correcta: /v3.0/oat/detections (no /v3.0/workbench/detections — devuelve 404)
        for path in ["/v3.0/oat/detections", "/v3.0/workbench/detections"]:
            for params in [
                {"startDateTime": s, "endDateTime": e, "top": 200},
                {"startDateTime": s, "endDateTime": e},
                {},
            ]:
                try:
                    items = self._pages(path, params, max_items=2000)
                    if items:
                        logger.info(f"oat_events: {len(items)} técnicas ({path})")
                        return items
                except TrendAIError as e_:
                    if e_.status == 404:
                        break  # probar siguiente path
                    logger.warning(f"oat_events ({path}): HTTP {e_.status}")
                except Exception as e_:
                    logger.warning(f"oat_events ({path}): {e_}")
        return []

    def get_endpoint_inventory(self) -> List[dict]:
        """
        Endpoint Inventory — /v3.0/endpointSecurity/endpoints
        IMPORTANTE: funciona sin params (top=N da 400).
        Devuelve todos los endpoints con agente instalado.
        """
        # Endpoint inventory: funciona SIN params de paginación
        if self.modules.get("endpoint_inventory"):
            try:
                # Sin params — devuelve hasta 100 en primera página
                items = []
                resp = self._req("GET", "/v3.0/endpointSecurity/endpoints")
                batch = resp.get("items", resp.get("data", []))
                items.extend(batch)
                # Paginar con nextLink si hay más
                nl = resp.get("nextLink","")
                while nl and len(items) < 5000:
                    prs = urllib.parse.urlparse(nl)
                    next_path = prs.path + ("?" + prs.query if prs.query else "")
                    resp2 = self._req("GET", next_path)
                    batch2 = resp2.get("items", resp2.get("data", []))
                    if not batch2: break
                    items.extend(batch2)
                    nl = resp2.get("nextLink","")
                logger.info(f"Endpoint inventory: {len(items)} endpoints")
                self._endpoint_cache = items  # cache para _get_endpoint_based_cves
                return items
            except Exception as e:
                logger.warning(f"endpoint_inventory: {e}")
        return []

    def _get_endpoint_based_cves(self) -> List[dict]:
        """
        Fallback CVE: extrae vulnerabilidades por endpoint vía Endpoint Security API.
        Usa GET /v3.0/endpointSecurity/endpoints/{agentGuid}/vulnerabilities por dispositivo.
        Se activa cuando el módulo ASM no está disponible.
        """
        endpoints = getattr(self, "_endpoint_cache", None)
        if not endpoints and self.modules.get("endpoint_inventory"):
            try:
                resp      = self._req("GET", "/v3.0/endpointSecurity/endpoints")
                endpoints = resp.get("items", resp.get("data", []))
                self._endpoint_cache = endpoints
            except Exception as e:
                logger.warning(f"_get_endpoint_based_cves — inventory: {e}")
                return []
        if not endpoints:
            return []

        # Priorizar endpoints que ya señalan tener CVEs para reducir llamadas
        candidates = [
            ep for ep in endpoints
            if (ep.get("cveScore") or ep.get("cvssScore") or ep.get("vulnerabilityCount")
                or ep.get("riskScore") or ep.get("hasVulnerabilities"))
        ] or endpoints  # si no hay campos de score, intentar todos

        all_cves: List[dict] = []
        seen_keys: set = set()

        def _fetch_ep(ep):
            guid = ep.get("agentGuid") or ep.get("endpointId") or ""
            if not guid:
                return []
            hostname = ep.get("displayName") or ep.get("hostName") or ep.get("name") or ""
            ips = ep.get("ip") or ""
            if isinstance(ep.get("ipv4Addresses"), list):
                ips = ", ".join(ep["ipv4Addresses"]) or ips
            try:
                items = self._pages(
                    f"/v3.0/endpointSecurity/endpoints/{guid}/vulnerabilities",
                    {"top": 200}, max_items=1000
                )
                for item in items:
                    if not item.get("deviceName"):       item["deviceName"]       = hostname
                    if not item.get("endpointHostname"): item["endpointHostname"] = hostname
                    if not item.get("ip"):               item["ip"]               = str(ips)
                logger.debug(f"endpoint_cves {hostname}: {len(items)} CVEs")
                return items
            except TrendAIError as e:
                if e.status not in (404, 400):
                    logger.warning(f"endpoint_cves {hostname}: HTTP {e.status}")
                return []
            except Exception as e:
                logger.warning(f"endpoint_cves {hostname}: {e}")
                return []

        with ThreadPoolExecutor(max_workers=4) as pool:
            for batch in pool.map(_fetch_ep, candidates[:100]):
                for item in batch:
                    cve_id = item.get("id") or item.get("cveId") or ""
                    dev    = item.get("deviceName") or ""
                    key    = f"{cve_id}|{dev}"
                    if cve_id:
                        if key not in seen_keys:
                            all_cves.append(item)
                            seen_keys.add(key)
                    else:
                        all_cves.append(item)

        if all_cves:
            logger.info(f"endpoint_based_cves: {len(all_cves)} CVEs de {len(candidates)} endpoints")
        return all_cves

    def synthesize_endpoint_assessments(self) -> dict:
        """
        Genera entradas de sec-conf y sys-conf a partir del inventario de endpoints.
        Se activa como fallback cuando ASM assessments no están disponibles.
        Detecta: agentes desconectados, OS sin soporte, protección desactivada,
        endpoints aislados, agentes desactualizados.
        """
        endpoints = getattr(self, "_endpoint_cache", None) or []
        sec: List[dict] = []
        sys_: List[dict] = []
        if not endpoints:
            return {"sec_conf": sec, "sys_conf": sys_}

        EOL_OS = {
            "windows xp": True, "windows vista": True, "windows 7": True,
            "windows 8": True, "windows 8.1": True,
            "windows server 2003": True, "windows server 2008": True,
            "windows server 2012": True,
            "red hat enterprise linux 6": True, "rhel 6": True,
            "centos 6": True, "centos 7": True,
            "ubuntu 16": True, "ubuntu 18": True,
            "debian 8": True, "debian 9": True,
        }

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        for ep in endpoints:
            name    = ep.get("displayName") or ep.get("hostName") or ep.get("name") or "Unknown"
            ip_list = ep.get("ipv4Addresses") or []
            ip      = ", ".join(ip_list) if isinstance(ip_list, list) else str(ep.get("ip",""))
            os_name = ep.get("osName","") or ep.get("osDescription","")
            os_ver  = ep.get("osVersion","")
            conn    = (ep.get("connectionStatus","") or ep.get("agentStatus","")).lower()
            last_c  = ep.get("lastConnectedDateTime","") or ep.get("lastSeen","")
            prot    = (ep.get("protectionStatus","") or ep.get("agentProtectionStatus","")).lower()
            isol    = (ep.get("isolationStatus","") or "").lower()
            agent_v = ep.get("agentVersion","") or ep.get("version","")
            risk    = ep.get("riskLevel","") or ep.get("riskScore","")

            sev     = "High" if risk and str(risk).lower() in ("critical","high","4","5") else "Medium"
            det     = _fmt(last_c) or now_str
            base    = {
                "Status": "Active",
                "Data source / processor": "Trend Vision One — Endpoint Security",
                "Asset": name,
                "Identity type": "",
                "Detected": det,
                "Case": ep.get("agentGuid","") or ep.get("endpointId",""),
                "Remediation": "",
                "Suggested actions": "",
                "Detail info": f"ip: {ip} | os: {os_name} {os_ver} | agent: {agent_v} | last_seen: {last_c[:10] if last_c else '-'}",
            }

            # Agente desconectado → sec-conf
            if conn in ("disconnected", "offline", "inactive"):
                sec.append({**base,
                    "Risk event": "Agente de seguridad desconectado",
                    "Event risk level": "High",
                    "Remediation": "Verificar conectividad del equipo y reinstalar el agente si es necesario.",
                    "Suggested actions": "Check endpoint connectivity and reinstall Trend agent",
                })

            # Protección desactivada → sec-conf
            if prot in ("error", "disabled", "warning", "not_running", "inactive"):
                sec.append({**base,
                    "Risk event": "Protección del agente degradada o desactivada",
                    "Event risk level": "High",
                    "Remediation": "Verificar el estado de la protección y reactivar los módulos afectados.",
                    "Suggested actions": "Enable endpoint protection modules in Trend Vision One console",
                })

            # Endpoint aislado → sys-conf (estado excepcional)
            if isol in ("isolated", "isolating"):
                sys_.append({**base,
                    "Risk event": "Endpoint en aislamiento de red activo",
                    "Event risk level": "High",
                    "Remediation": "Investigar el motivo del aislamiento. Levantar cuando el equipo esté limpio.",
                    "Suggested actions": "Investigate isolated endpoint and release when clean",
                })

            # OS sin soporte / EOL → sys-conf
            os_key = f"{os_name} {os_ver}".lower().strip()
            for eol_pattern in EOL_OS:
                if eol_pattern in os_key:
                    sys_.append({**base,
                        "Risk event": f"Sistema operativo sin soporte detectado: {os_name} {os_ver}",
                        "Event risk level": "High",
                        "Remediation": "Planificar actualización o migración del sistema operativo.",
                        "Suggested actions": f"Upgrade OS from {os_name} {os_ver} to a supported version",
                    })
                    break

        if sec or sys_:
            logger.info(f"synthesize_endpoint_assessments: {len(sec)} sec-conf, {len(sys_)} sys-conf")
        return {"sec_conf": sec, "sys_conf": sys_}

    def get_endpoint_cve_assets_from_inventory(self) -> List[dict]:
        """
        Genera cve-assets a partir de los campos riskScore/cveScore del inventario
        cuando la API de CVE específica no está disponible o devuelve pocos datos.
        """
        endpoints = getattr(self, "_endpoint_cache", None) or []
        results: List[dict] = []
        for ep in endpoints:
            risk_score = (ep.get("cveRiskScore") or ep.get("cveScore") or
                          ep.get("riskScore") or ep.get("cvssScore") or "")
            vuln_count = (ep.get("vulnerabilityCount") or ep.get("cveCount") or
                          ep.get("criticalVulnerabilityCount") or "")
            if not risk_score and not vuln_count:
                continue
            name   = ep.get("displayName") or ep.get("hostName") or ep.get("name","")
            ip_list= ep.get("ipv4Addresses") or []
            ip     = ", ".join(ip_list) if isinstance(ip_list, list) else str(ep.get("ip",""))
            os_app = f"{ep.get('osName','')} {ep.get('osVersion','')}".strip()
            last_c = ep.get("lastConnectedDateTime","")
            results.append({
                "Status":          "Active",
                "Device name":     name,
                "Operating system":os_app,
                "IP address":      ip,
                "Last user":       ep.get("lastLogonUser","") or ep.get("lastUser",""),
                "CVE event risk score": str(risk_score),
                "Total CVEs":      str(vuln_count or "?"),
                "Average Unpatched Time (AUT)": "",
                "Asset groups":    ep.get("policyName","") or ep.get("groupName",""),
                "Last detected":   _fmt(last_c),
            })
        if results:
            logger.info(f"endpoint_cve_assets_from_inventory: {len(results)} activos con score")
        return results

    def get_eiqs_data(self) -> List[dict]:
        """
        EIQS (Endpoint Intelligence Query Service) — datos de seguridad adicionales.
        Prueba múltiples variantes de endpoint y parámetros.
        """
        if not self.modules.get("endpoint_eiqs"): return []
        paths = [
            ("/v3.0/eiqs/endpoints", [{"top": 50}, {"limit": 50}, {}]),
            ("/v3.0/endpointSecurity/eiqs/endpoints", [{"top": 50}, {}]),
        ]
        for path, param_list in paths:
            for params in param_list:
                try:
                    resp = self._req("GET", path, params if params else None)
                    items = resp.get("items", resp.get("data", resp.get("endpoints", [])))
                    if items:
                        logger.info(f"eiqs ({path}): {len(items)} items")
                        return items
                except TrendAIError as e:
                    if e.status == 404:
                        break  # path incorrecto, probar el siguiente
                    logger.debug(f"eiqs {path} params={params}: HTTP {e.status}")
                except Exception as e:
                    logger.debug(f"eiqs {path}: {e}")
        return []

    def get_asm_vulnerabilities(self, start: datetime, end: datetime) -> List[dict]:
        """
        Obtiene TODOS los CVEs activos del tenant.

        Estrategias en orden de preferencia:
        1. CREM/ASRM:          /v3.0/asrm/vulnerableDevices      (si módulo contratado)
        2. Endpoint aggregate: /v3.0/endpointSecurity/vulnerabilities (si disponible)
        3. Per-endpoint:       /v3.0/endpointSecurity/endpoints/{guid}/vulnerabilities

        cveDetectionStatus=any es obligatorio: por defecto la API solo devuelve
        dispositivos ya afectados, omitiendo el resto del inventario evaluado.
        """
        # ── Estrategia 1: CREM/ASRM vulnerableDevices ───────────────────────
        if self.modules.get("asm_vuln"):
            try:
                items = self._pages(
                    "/v3.0/asrm/vulnerableDevices",
                    {"top": 200, "cveDetectionStatus": "any"},
                    max_items=8000,
                    tmv1_filter=self.discovered_by_filter,
                )
                logger.info(f"asm_vuln (vulnerableDevices): {len(items)} CVEs")
                if items:
                    return items
            except TrendAIError as e:
                logger.warning(f"asm_vuln: HTTP {e.status} — {e.body[:120]}")
            except Exception as e:
                logger.warning(f"asm_vuln: {e}")

        # ── Estrategia 2: aggregate endpoint CVE endpoint ───────────────────
        if self.modules.get("endpoint_vuln_agg"):
            for params in [{"top": 200}, {}]:
                try:
                    items = self._pages("/v3.0/endpointSecurity/vulnerabilities", params, max_items=8000)
                    if items:
                        logger.info(f"endpoint_vuln_agg: {len(items)} CVEs")
                        return items
                except TrendAIError as e:
                    logger.warning(f"endpoint_vuln_agg: HTTP {e.status}")
                except Exception as e:
                    logger.warning(f"endpoint_vuln_agg: {e}")

        # ── Estrategia 3: per-endpoint CVE extraction ───────────────────────
        if self.modules.get("endpoint_inventory") or self.modules.get("endpoint_vuln_detail"):
            result = self._get_endpoint_based_cves()
            if result:
                return result

        return []

    def get_asm_assessments(self) -> List[dict]:
        """
        /v3.0/asrm/securityPosture — Obtiene TODOS los assessments de postura
        activos (sin filtro de fecha, no toma segmento de ID). El portal
        muestra el estado actual de la postura, no solo el mes.
        """
        if not self.modules.get("asm_assessments"): return []
        try:
            items = self._pages("/v3.0/asrm/securityPosture", {"top": 200}, max_items=3000)
            logger.info(f"asm_assessments (securityPosture): {len(items)} items")
            return items
        except TrendAIError as e:
            logger.warning(f"asm_assessments: HTTP {e.status} — {e.body[:120]}")
        except Exception as e:
            logger.warning(f"asm_assessments: {e}")
        return []

    def get_asm_endpoints(self) -> List[dict]:
        """
        /v3.0/asrm/attackSurfaceDevices — Lista de activos con su CVE risk
        score agregado. Usado para enriquecer cve-assets.csv con datos de
        riesgo por activo.
        """
        if not self.modules.get("asm_endpoints"): return []
        try:
            items = self._pages(
                "/v3.0/asrm/attackSurfaceDevices", {"top": 200}, max_items=2000,
                tmv1_filter=self.discovered_by_filter,
            )
            logger.info(f"asm_endpoints (attackSurfaceDevices): {len(items)} activos")
            return items
        except TrendAIError as e:
            logger.warning(f"asm_endpoints: HTTP {e.status} — {e.body[:80]}")
        except Exception as e:
            logger.warning(f"asm_endpoints: {e}")
        return []

    def get_cloud_apps(self, start: datetime, end: datetime) -> List[dict]:
        if not self.modules.get("cloud_access"): return []
        s = start.strftime("%Y-%m-%dT%H:%M:%SZ")
        e = end.strftime("%Y-%m-%dT%H:%M:%SZ")
        for params in [
            {"top": 200, "startDateTime": s, "endDateTime": e},
            {"top": 200},
            {},
        ]:
            try:
                items = self._pages("/v3.0/cloudAccess/riskAccessEvents", params, max_items=2000)
                if items:
                    return items
            except TrendAIError as ex:
                logger.warning(f"cloud_access: HTTP {ex.status} — {ex.body[:80]}")
            except Exception as ex:
                logger.warning(f"cloud_access: {ex}")
        return []

    def get_suspicious_objects(self) -> List[dict]:
        """
        Suspicious Objects (IPs, dominios, hashes, URLs maliciosas).
        Traemos hasta 1000 — Vision One mantiene lista activa de IOCs.
        """
        if not self.modules.get("suspicious_objects"): return []
        try:
            # top=200 funciona aquí
            return self._pages("/v3.0/threatintel/suspiciousObjects",
                               {"top": 200}, max_items=1000)
        except Exception as e:
            logger.warning(f"suspicious_objects: {e}")
            return []

    def get_sandbox_submissions(self, start: datetime, end: datetime) -> List[dict]:
        if not self.modules.get("sandbox"): return []
        s = start.strftime("%Y-%m-%dT%H:%M:%SZ")
        e = end.strftime("%Y-%m-%dT%H:%M:%SZ")
        # /v3.0/sandbox/tasks es la ruta correcta (submissionList devuelve 404)
        for path in ["/v3.0/sandbox/tasks", "/v3.0/sandbox/submissionList"]:
            for params in [
                {"startDateTime": s, "endDateTime": e, "top": 200},
                {"top": 200},
                {},
            ]:
                try:
                    items = self._pages(path, params, max_items=500)
                    if items:
                        logger.info(f"sandbox: {len(items)} submissions ({path})")
                        return items
                except TrendAIError as ex:
                    if ex.status == 404:
                        break
                    logger.warning(f"sandbox ({path}) params={list(params)}: HTTP {ex.status}")
                except Exception as ex:
                    logger.warning(f"sandbox ({path}): {ex}")
        return []

    def get_risk_score(self) -> dict:
        for mod, path in [("asm_risk","/v3.0/asm/riskScore"),
                          ("risk_insights","/v3.0/riskInsights/riskScore")]:
            if self.modules.get(mod):
                try: return self._req("GET", path)
                except Exception as e: logger.warning(f"{mod} ({path}): {e}")
        return {}

    def get_intel_reports(self) -> List[dict]:
        """
        Intelligence Reports — /v3.0/threatintel/intelligenceReports
        IMPORTANTE: funciona SIN params.
        """
        if not self.modules.get("intel_reports"): return []
        try:
            resp = self._req("GET", "/v3.0/threatintel/intelligenceReports")
            return resp.get("items", resp.get("data", []))[:200]
        except Exception as e:
            logger.warning(f"intel_reports: {e}")
            return []

    def get_search_detections(self, start: datetime, end: datetime,
                               query="*", max_items=2000) -> List[dict]:
        if not self.modules.get("search"): return []
        return self._search(query, start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                            end.strftime("%Y-%m-%dT%H:%M:%SZ"), max_items=max_items)

    def get_email_security_alerts(self, start: datetime, end: datetime) -> List[dict]:
        """Email Security — phishing, malware en email, BEC"""
        if not self.modules.get("cloud_email"): return []
        try:
            return self._pages("/v3.0/emailSecurity/alerts", {
                "startDateTime": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "endDateTime":   end.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "top": 200,
            }, max_items=2000)
        except Exception as e:
            logger.warning(f"cloud_email: {e}")
            return []

    def get_identity_risk(self) -> List[dict]:
        """Identity risk accounts — cuentas con riesgo elevado"""
        all_items, seen = [], set()
        for mod, path in [
            ("identity_risk",     "/v3.0/iam/accountsRiskInsight"),
            ("identity_accounts", "/v3.0/iam/accounts"),
        ]:
            if not self.modules.get(mod): continue
            for params in [{"top": 100}, {"top": 50}, {"pageSize": 100}, {}]:
                try:
                    items = self._pages(path, params, max_items=1000)
                    for it in items:
                        uid = it.get("accountId") or it.get("id") or it.get("userPrincipalName")
                        if uid:
                            if uid not in seen:
                                all_items.append(it)
                                seen.add(uid)
                        else:
                            all_items.append(it)  # sin ID: incluir siempre, no deduplicar
                    if items: break
                except TrendAIError as e:
                    logger.warning(f"identity {mod}: HTTP {e.status}")
                except Exception as e:
                    logger.warning(f"identity {mod}: {e}")
        return all_items

    def get_endpoint_agent_health(self) -> List[dict]:
        """Endpoints con problemas de agente — desconectados, sin actualizar"""
        if not self.modules.get("endpoint_health"): return []
        try:
            return self._pages("/v3.0/endpointSecurity/agentHealth", {"top":200}, max_items=1000)
        except Exception as e:
            logger.warning(f"endpoint_health: {e}")
            return []

    def get_audit_logs(self, start: datetime, end: datetime) -> List[dict]:
        """Audit logs — cambios de configuración, accesos admin"""
        if not self.modules.get("audit_logs"): return []
        s = start.strftime("%Y-%m-%dT%H:%M:%SZ")
        e_s = end.strftime("%Y-%m-%dT%H:%M:%SZ")
        # /v3.0/audit/logs es la ruta correcta (no /v3.0/auditLogs — devuelve 404)
        for path in ["/v3.0/audit/logs", "/v3.0/auditLogs"]:
            for params in [
                {"startDateTime": s, "endDateTime": e_s, "top": 200},
                {"startDateTime": s, "endDateTime": e_s},
                {"top": 200},
                {},
            ]:
                try:
                    items = self._pages(path, params, max_items=500)
                    if items:
                        logger.info(f"audit_logs: {len(items)} logs ({path})")
                        return items
                    # 200 con 0 items es válido (no hay logs en el periodo)
                    return []
                except TrendAIError as e_:
                    if e_.status == 404:
                        break  # probar siguiente path
                    if e_.status == 400:
                        continue  # probar siguientes params
                    logger.warning(f"audit_logs ({path}): HTTP {e_.status}")
                except Exception as e_:
                    logger.warning(f"audit_logs ({path}): {e_}")
        return []

    def get_response_tasks(self, start: datetime, end: datetime) -> List[dict]:
        """
        Response Tasks — /v3.0/response/tasks
        IMPORTANTE: funciona SIN params de fecha/top.
        Luego filtramos por fecha en Python.
        """
        if not self.modules.get("response_tasks"): return []
        try:
            items = self._pages("/v3.0/response/tasks", {"top": 200}, max_items=2000)
            # Filtrar por mes si hay fecha
            start_str = start.strftime("%Y-%m-%d")
            end_str   = end.strftime("%Y-%m-%d")
            filtered = [t for t in items if
                start_str <= (t.get("createdDateTime","") or t.get("lastActionDateTime",""))[:10] <= end_str
            ] if items else items
            return filtered if filtered else items  # si no hay del mes, devolver todos
        except Exception as e:
            logger.warning(f"response_tasks: {e}")
            return []

    def get_asm_attack_paths(self) -> List[dict]:
        """ASM Attack Paths — rutas de ataque simuladas (predictivo)"""
        if not self.modules.get("asm_attack_paths"): return []
        try:
            return self._pages("/v3.0/asm/attackPaths", {"top":50}, max_items=100)
        except Exception as e:
            logger.warning(f"asm_attack_paths: {e}")
            return []

    def get_network_events(self, start: datetime, end: datetime) -> List[dict]:
        """Network security events via Search API"""
        if not self.modules.get("search"): return []
        return self._search(
            'product:*network* OR eventSubType:NETWORK_DETECTION OR product:*IPS* OR product:*DPI*',
            start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            max_items=500
        )

    def get_endpoint_tasks(self) -> List[dict]:
        """Endpoint Security Tasks — tareas de respuesta en endpoints (aislamiento, scan, etc.)"""
        if not self.modules.get("endpoint_tasks"): return []
        for params in [{"top": 200}, {}]:
            try:
                items = self._pages("/v3.0/endpointSecurity/tasks", params, max_items=1000)
                if items or params == {}:
                    return items
            except TrendAIError as e:
                logger.warning(f"endpoint_tasks: HTTP {e.status}")
            except Exception as e:
                logger.warning(f"endpoint_tasks: {e}")
        return []

    def get_endpoint_isolation(self) -> List[dict]:
        """Endpoints actualmente aislados (cuarentena de red)"""
        if not self.modules.get("endpoint_isolation"): return []
        for params in [{"top": 200}, {}]:
            try:
                items = self._pages("/v3.0/endpointSecurity/isolatedEndpoints", params, max_items=500)
                if items or params == {}:
                    return items
            except TrendAIError as e:
                logger.warning(f"endpoint_isolation: HTTP {e.status}")
            except Exception as e:
                logger.warning(f"endpoint_isolation: {e}")
        return []

    def get_cloud_file_security(self, start: datetime, end: datetime) -> List[dict]:
        """Cloud File Security — archivos maliciosos detectados en almacenamiento cloud"""
        if not self.modules.get("cloud_file_security"): return []
        s = start.strftime("%Y-%m-%dT%H:%M:%SZ")
        e = end.strftime("%Y-%m-%dT%H:%M:%SZ")
        for params in [
            {"startDateTime": s, "endDateTime": e, "top": 200},
            {"top": 200},
        ]:
            try:
                items = self._pages("/v3.0/cloudFileSecurity/events", params, max_items=2000)
                if items:
                    return items
            except TrendAIError as ex:
                logger.warning(f"cloud_file_security params={list(params)}: HTTP {ex.status}")
            except Exception as ex:
                logger.warning(f"cloud_file_security: {ex}")
        return []

    def get_container_security_alerts(self, start: datetime, end: datetime) -> List[dict]:
        """Container Security — alertas de contenedores Kubernetes/Docker"""
        if not self.modules.get("container_security"): return []
        s = start.strftime("%Y-%m-%dT%H:%M:%SZ")
        e = end.strftime("%Y-%m-%dT%H:%M:%SZ")
        for params in [
            {"startDateTime": s, "endDateTime": e, "top": 200},
            {"top": 200},
        ]:
            try:
                items = self._pages("/v3.0/containerSecurity/alerts", params, max_items=2000)
                if items:
                    return items
            except TrendAIError as ex:
                logger.warning(f"container_security params={list(params)}: HTTP {ex.status}")
            except Exception as ex:
                logger.warning(f"container_security: {ex}")
        return []

    def get_asm_internet_facing_assets(self) -> List[dict]:
        """
        /v3.0/asrm/attackSurfacePublicIpAddresses — activos expuestos
        directamente a internet (IPs públicas).
        """
        if not self.modules.get("asm_internet_facing"): return []
        try:
            items = self._pages(
                "/v3.0/asrm/attackSurfacePublicIpAddresses", {"top": 200}, max_items=2000,
                tmv1_filter=self.discovered_by_filter,
            )
            logger.info(f"asm_internet_facing (attackSurfacePublicIpAddresses): {len(items)} activos expuestos")
            return items
        except TrendAIError as e:
            logger.warning(f"asm_internet_facing: HTTP {e.status}")
        except Exception as e:
            logger.warning(f"asm_internet_facing: {e}")
        return []

    def get_asrm_high_risk_devices(self) -> List[dict]:
        """/v3.0/asrm/highRiskDevices — dispositivos con mayor exposición de riesgo."""
        if not self.modules.get("asrm_high_risk"): return []
        try:
            items = self._pages(
                "/v3.0/asrm/highRiskDevices", {"top": 200}, max_items=2000,
                tmv1_filter=self.discovered_by_filter,
            )
            logger.info(f"asrm_high_risk (highRiskDevices): {len(items)} activos")
            return items
        except TrendAIError as e:
            logger.warning(f"asrm_high_risk: HTTP {e.status}")
        except Exception as e:
            logger.warning(f"asrm_high_risk: {e}")
        return []

    def get_asrm_asset_groups(self) -> List[dict]:
        """/v3.0/asrm/assetGroups — grupos de activos definidos en CREM (no toma segmento de ID)."""
        if not self.modules.get("asrm_asset_groups"): return []
        try:
            items = self._pages("/v3.0/asrm/assetGroups", {"top": 200}, max_items=1000)
            logger.info(f"asrm_asset_groups (assetGroups): {len(items)} grupos")
            return items
        except TrendAIError as e:
            logger.warning(f"asrm_asset_groups: HTTP {e.status}")
        except Exception as e:
            logger.warning(f"asrm_asset_groups: {e}")
        return []

    def get_email_quarantine(self, start: datetime, end: datetime) -> List[dict]:
        """Email quarantine — mensajes en cuarentena por política o amenaza"""
        if not self.modules.get("email_quarantine"): return []
        s = start.strftime("%Y-%m-%dT%H:%M:%SZ")
        e = end.strftime("%Y-%m-%dT%H:%M:%SZ")
        for params in [
            {"startDateTime": s, "endDateTime": e, "top": 200},
            {"top": 200},
        ]:
            try:
                items = self._pages("/v3.0/emailSecurity/quarantineMessages", params, max_items=1000)
                if items:
                    return items
            except TrendAIError as ex:
                logger.warning(f"email_quarantine: HTTP {ex.status}")
            except Exception as ex:
                logger.warning(f"email_quarantine: {ex}")
        return []

    def get_cloud_posture(self) -> List[dict]:
        """Cloud Posture (Conformity) — resumen de evaluaciones de seguridad cloud"""
        if not self.modules.get("cloud_posture"): return []
        for path in ["/v3.0/cloudPosture/assessmentSummaries",
                     "/v3.0/cloudPosture/checks",
                     "/v3.0/cloudPosture/rules"]:
            for params in [{"top": 200}, {}]:
                try:
                    items = self._pages(path, params, max_items=1000)
                    if items:
                        logger.info(f"cloud_posture ({path}): {len(items)} items")
                        return items
                except TrendAIError as e:
                    if e.status == 404:
                        break  # probar siguiente path
                    logger.warning(f"cloud_posture {path}: HTTP {e.status}")
                except Exception as e:
                    logger.warning(f"cloud_posture: {e}")
        return []

    def get_stix_sweeping_results(self) -> List[dict]:
        """STIX Sweeping Tasks + resultados — búsqueda proactiva de IOCs"""
        if not self.modules.get("intel_tasks"): return []
        try:
            tasks = self._pages("/v3.0/threatintel/stixSweepingTasks", {"top": 50}, max_items=100)
        except Exception as e:
            logger.warning(f"intel_tasks: {e}")
            return []
        results = []
        for t in tasks[:10]:  # limitar enriquecimiento a las 10 más recientes
            tid = t.get("id") or t.get("taskId")
            if not tid:
                results.append(t)
                continue
            try:
                r = self._req("GET", f"/v3.0/threatintel/stixSweepingTasks/{tid}/results")
                hits = r.get("items", r.get("data", []))
                results.append({**t, "_hits": hits, "_hit_count": len(hits)})
            except Exception:
                results.append(t)
        return results

    def get_xdr_impacted_entities(self, start: datetime, end: datetime) -> List[dict]:
        """XDR Impacted Entities — entidades afectadas por alertas XDR"""
        if not self.modules.get("xdr_entities") and not self.modules.get("workbench"):
            return []
        s = start.strftime("%Y-%m-%dT%H:%M:%SZ")
        e = end.strftime("%Y-%m-%dT%H:%M:%SZ")
        for path in ["/v3.0/xdr/impactedEntities", "/v3.0/workbench/impactedEntities"]:
            for params in [
                {"startDateTime": s, "endDateTime": e, "top": 200},
                {"top": 200},
            ]:
                try:
                    items = self._pages(path, params, max_items=1000)
                    if items:
                        logger.info(f"xdr_entities ({path}): {len(items)}")
                        return items
                except TrendAIError as ex:
                    if ex.status == 404:
                        break
                    logger.warning(f"xdr_entities {path}: HTTP {ex.status}")
                except Exception as ex:
                    logger.warning(f"xdr_entities: {ex}")
        return []

    def get_network_sensors(self) -> List[dict]:
        """Network Security Sensors — inventario de sensores de red desplegados"""
        if not self.modules.get("network_sensor"): return []
        for params in [{"top": 200}, {}]:
            try:
                items = self._pages("/v3.0/networkSecurity/sensors", params, max_items=500)
                if items or params == {}:
                    logger.info(f"network_sensors: {len(items)} sensores")
                    return items
            except TrendAIError as e:
                logger.warning(f"network_sensors: HTTP {e.status}")
            except Exception as e:
                logger.warning(f"network_sensors: {e}")
        return []

    def get_network_policies(self) -> List[dict]:
        """Network Security Policies — políticas de firewall de red activas"""
        if not self.modules.get("network_policy"): return []
        for params in [{"top": 200}, {}]:
            try:
                items = self._pages("/v3.0/networkSecurity/policies", params, max_items=500)
                if items or params == {}:
                    logger.info(f"network_policies: {len(items)} políticas")
                    return items
            except TrendAIError as e:
                logger.warning(f"network_policies: HTTP {e.status}")
            except Exception as e:
                logger.warning(f"network_policies: {e}")
        return []

    # ── NORMALIZERS ──────────────────────────────────────────────────────────

    def _build_detail(self, indicators: list, extra: dict = None) -> str:
        """Construye Detail info completo desde indicadores + datos extra."""
        parts = []
        type_labels = {
            "file_sha256":"fileHash","file_sha1":"fileHash","file_md5":"fileHash",
            "process":"process","url":"url","domain":"domain","ip":"ip",
            "hostname":"host","email":"email","registryKey":"registry",
            "command":"command","filePath":"filePath","username":"user",
        }
        seen = set()
        for ind in indicators[:10]:
            t = str(ind.get("type","")).lower()
            v = str(ind.get("value", ind.get("field", ind.get("objectValue","")))).strip()
            if not v or v in ("None","null",""): continue
            label = type_labels.get(t, t) if t else "value"
            # Defang URLs/domains
            if t in ("url","domain") or "http" in v: v = _defang(v)
            entry = f"{label}: {v}"
            if entry not in seen:
                seen.add(entry)
                parts.append(entry)
        if extra:
            for k, v in extra.items():
                if v: parts.append(f"{k}: {_defang(str(v))}" if "url" in k.lower() or "http" in str(v) else f"{k}: {v}")
        return " | ".join(parts)

    def _classify_alert(self, model: str, provider: str, entities: list) -> str:
        """Clasifica una alerta en threat / anomaly / account."""
        m = model.lower(); p = provider.lower()
        # Cuenta comprometida
        if any(k in m for k in ("credential","brute force","phishing","identity","impossible travel",
                                 "account takeover","password spray","mfa","sign-in","suspicious login")):
            return "account"
        if any(k in m for k in ("anomalous","unusual","abnormal","baseline deviation","rare")):
            return "anomaly"
        # Entidades — si solo hay accounts → anomaly
        has_host = any(e.get("entityType","") in ("host","endpoint","server") for e in entities)
        has_acct = any(e.get("entityType","") in ("account","user") for e in entities)
        if has_acct and not has_host and not any(k in m for k in ("malware","ransomware","exploit","c2")):
            return "anomaly"
        return "threat"

    def normalize_alerts(self, alerts: list) -> dict:
        threats, anomaly, accounts = [], [], []
        for a in alerts:
            model    = a.get("model","") or a.get("alertModel","") or ""
            provider = a.get("alertProvider","") or ""
            severity = _sev(a.get("severity","medium"))
            created  = _fmt(a.get("createdDateTime",""))
            updated  = _fmt(a.get("updatedDateTime",""))
            wb_id    = a.get("id","")
            wb_link  = a.get("workbenchLink","")
            status   = a.get("investigationStatus","Open")
            score    = a.get("score",0)
            desc     = a.get("description", model)

            # Impact scope — estructura real Vision One
            scope    = a.get("impactScope",{})
            entities = scope.get("entities",[])
            assets, users, ips = [], [], []
            for e in entities:
                ev = e.get("entityValue",{})
                et = str(e.get("entityType","")).lower()
                if isinstance(ev, dict):
                    name = (ev.get("name","") or ev.get("displayName","") or
                            ev.get("endpointName","") or ev.get("accountName",""))
                    if name:
                        if et in ("account","user"): users.append(name)
                        else: assets.append(name)
                    for ip in (ev.get("ips") or []):
                        if ip: ips.append(ip)
                elif isinstance(ev, str) and ev:
                    # entityValue es string directamente (ej: "BCNSCODDC01$")
                    if et in ("account","user"): users.append(ev)
                    else: assets.append(ev)
            asset_str  = ", ".join(dict.fromkeys(a for a in assets if a))
            user_str   = ", ".join(dict.fromkeys(u for u in users if u))
            impact_str = user_str or asset_str or \
                f"{scope.get('desktopCount',0)}pc/{scope.get('serverCount',0)}srv"

            # Detail info
            indicators = a.get("indicators",[])
            extra = {"workbenchId":wb_id, "score":score}
            if wb_link: extra["link"] = wb_link
            if ips:     extra["ips"]  = ",".join(ips[:3])
            detail = self._build_detail(indicators, extra)

            # Suggested actions from alert
            suggested = a.get("suggestedActions","") or \
                "; ".join(str(x) for x in a.get("responseActions",[])[:3]) if a.get("responseActions") else ""

            cat = self._classify_alert(model, provider, entities)
            row = {
                "Status":                   status,
                "Risk event":               desc or model,
                "Data source / processor":  f"Trend Vision One — {provider}",
                "Asset":                    asset_str,
                "Identity type":            "User Account" if cat in ("account","anomaly") and user_str else "",
                "Event risk level":         severity,
                "Detected":                 created,
                "Updated":                  updated,
                "Case":                     wb_id,
                "Remediation":              "",
                "Suggested actions":        suggested,
                "Detail info":              detail,
            }
            if cat == "account":
                row["Impact scope"] = impact_str
            (accounts if cat=="account" else anomaly if cat=="anomaly" else threats).append(row)
        return {"threats":threats,"anomaly":anomaly,"accounts":accounts}

    def normalize_oat(self, oat: list) -> list:
        """OAT → sys-conf rows (config/technique detections)"""
        rows = []
        for o in oat:
            filters  = o.get("filters",[])
            tactics  = ", ".join(f.get("mitreTactic","") for f in filters if f.get("mitreTactic"))
            techs    = ", ".join(f.get("mitreTechnique","") for f in filters if f.get("mitreTechnique"))
            endpoint = o.get("endpoint",{})
            asset    = endpoint.get("name","") or endpoint.get("ip","")
            detail_parts = []
            if tactics: detail_parts.append(f"tactics: {tactics}")
            if techs:   detail_parts.append(f"techniques: {techs}")
            detail_parts.append(f"uuid: {o.get('uuid','')}")
            rows.append({
                "Status":                   "Active",
                "Risk event":               o.get("filterName","") or o.get("name","Observed Attack Technique"),
                "Data source / processor":  "Trend Vision One — Observed Attack Techniques",
                "Asset":                    asset,
                "Identity type":            "",
                "Event risk level":         _sev(o.get("severity","medium")),
                "Detected":                 _fmt(o.get("detectedDateTime","") or o.get("eventTime","")),
                "Case":                     "",
                "Remediation":              "",
                "Suggested actions":        "",
                "Detail info":              " | ".join(detail_parts),
            })
        return rows

    def normalize_vulnerabilities(self, vulns: list, endpoints: list) -> dict:
        # Build endpoint map for enrichment
        ep_map = {}
        for ep in endpoints:
            for k in ["endpointName","hostname","displayName","name"]:
                n = ep.get(k,"")
                if n: ep_map[n.lower()] = ep

        events_map, assets_map = {}, {}
        for v in vulns:
            # Cubrir variaciones de field names entre ASM, endpoint aggregate y per-endpoint APIs
            cve_id   = (v.get("cveId","") or v.get("vulnerabilityId","") or
                        v.get("id","") or v.get("cve",""))
            device   = (v.get("deviceName","") or v.get("endpointHostname","") or
                        v.get("assetName","") or v.get("hostName","") or
                        v.get("endpointName","") or v.get("name","")).strip()
            score    = str(v.get("cvssScore","") or v.get("riskScore","") or
                          v.get("cvssV3Score","") or v.get("score",""))
            severity = _sev(v.get("severity","") or v.get("riskLevel","") or
                           v.get("risk_level",""))
            os_app   = (v.get("productName","") or v.get("application","") or
                        v.get("affectedProduct","") or v.get("osName","") or
                        v.get("component",""))
            detected = _fmt(v.get("lastDetectedDateTime","") or v.get("detectedDateTime","") or
                           v.get("lastSeen","") or v.get("updatedDateTime",""))
            published= str(v.get("publishedDate","") or v.get("publishDate","") or "")[:10]
            exploit  = (v.get("exploitPotential","") or v.get("globalExploitPotential","") or
                        v.get("exploitability",""))
            if isinstance(exploit, bool): exploit = "Actively Exploited" if exploit else "Low"
            attempts = str(v.get("exploitAttempts",0) or 0)
            ip       = v.get("ipAddress","") or v.get("ip","") or v.get("endpointIp","")

            # Enrich from endpoint inventory
            ep = ep_map.get(device.lower())
            if ep:
                if not ip:      ip      = (ep.get("ipAddresses",[""])[0] if isinstance(ep.get("ipAddresses"), list) else ep.get("ip",""))
                if not os_app:  os_app  = f"{ep.get('osName','')} {ep.get('osVersion','')}".strip()

            if cve_id:
                if cve_id not in events_map:
                    events_map[cve_id] = {
                        "Status":"Active","Vulnerability ID":cve_id,
                        "CVE impact score":score,"Global exploit potential":exploit,
                        "OS/Application":os_app,"Impact scope":device,
                        "Prevention rule":v.get("preventionRule","None"),
                        "Exploit attempts":attempts,
                        "First seen time":detected,"Publish date":published,
                    }
                else:
                    ex = events_map[cve_id]
                    if device and device not in ex["Impact scope"]:
                        ex["Impact scope"] += "," + device
                    try:
                        if float(score or 0) > float(ex["CVE impact score"] or 0):
                            ex["CVE impact score"] = score
                    except Exception: pass

            if device:
                if device not in assets_map:
                    assets_map[device] = {
                        "Status":"Active","Device name":device,
                        "Operating system":os_app,"IP address":ip,
                        "Last user":v.get("lastUser","") or v.get("logonUser",""),
                        "CVE event risk score":str(v.get("riskScore","") or score),
                        "Total CVEs":1,
                        "Average Unpatched Time (AUT)":str(v.get("avgUnpatchedDays","") or ""),
                        "Asset groups":v.get("assetGroup",""),
                        "Last detected":detected,
                    }
                else:
                    assets_map[device]["Total CVEs"] += 1
                    try:
                        cur = float(assets_map[device]["CVE event risk score"] or 0)
                        new = float(v.get("riskScore","") or score or 0)
                        if new > cur: assets_map[device]["CVE event risk score"] = str(new)
                    except Exception: pass

        for d in assets_map.values():
            d["Total CVEs"] = str(d["Total CVEs"])

        return {"cve_events":list(events_map.values()),"cve_assets":list(assets_map.values())}

    def normalize_assessments(self, assessments: list) -> dict:
        """
        Clasifica assessments en security-conf vs sys-conf usando el mapa real
        de categorías que devuelve Vision One + fallback por palabras del título.
        """
        sec, sys_ = [], []

        # Categorías reales de Vision One → sec-conf
        SEC_EXACT = {
            "endpoint_detection_and_response", "endpoint_security", "edr",
            "antivirus", "anti-malware", "firewall", "dlp", "data_loss_prevention",
            "email_security", "cloud_app_security", "web_security", "intrusion_prevention",
            "endpoint_protection", "behavior_monitoring", "ransomware_protection",
            "endpoint_sensor", "patch_management", "device_control",
            "application_control", "exploit_prevention", "privilege_escalation",
            "identity_and_access", "identity_security", "mfa", "zero_trust",
            "cloud_security", "network_security", "encryption",
        }
        # Categorías reales → sys-conf
        SYS_EXACT = {
            "system_configuration", "os_configuration", "hardware",
            "network_configuration", "registry", "software_vulnerability",
            "vulnerability_management", "end_of_life", "deprecated",
            "unsupported_os", "legacy_software", "system_update",
            "certificate", "password_policy", "audit_policy",
            "user_account_control", "remote_access",
        }
        # Prefijos de categoria Vision One → clasificación
        SEC_PREFIXES = ("security","protection","antivirus","edr","firewall","dlp","email",
                        "patch","encrypt","mfa","identity","cloud_sec","web_sec","ips",
                        "endpoint_sec","endpoint_det","behavior","ransomware","device_ctrl",
                        "app_ctrl","exploit","privilege","zero_trust","network_sec")
        SYS_PREFIXES = ("system","os_","hardware","network_conf","registry","software_vuln",
                        "vuln","end_of","deprecated","legacy","unsupported","cert","password",
                        "audit_policy","user_acct","remote_access","update","config")
        # Palabras clave del título → sec
        SEC_TITLE_KW = ("antivirus","edr","firewall","dlp","email filter","protection enabled",
                        "sensor","agent","real-time","scan","exploit","ransomware","malware",
                        "encryption","mfa","multi-factor","identity","zero trust","web filter",
                        "intrusion","ips","endpoint security","behavior","patch")
        # Palabras clave del título → sys
        SYS_TITLE_KW = ("os version","operating system","end-of-life","end of support","eol",
                        "legacy","deprecated","unsupported","registry","audit log","password policy",
                        "certificate","ssl","update","vulnerability","cve","smb","rdp","telnet",
                        "open port","service","configuration","remote desktop","uac","unsigned",
                        "autorun","network share","default credential")

        def _classify_cat(cat: str, title: str, source: str = "") -> str:
            c = cat.lower().replace(" ","_").replace("-","_")
            t = title.lower()
            if c in SEC_EXACT:  return "sec"
            if c in SYS_EXACT:  return "sys"
            if any(c.startswith(p) for p in SEC_PREFIXES): return "sec"
            if any(c.startswith(p) for p in SYS_PREFIXES): return "sys"
            # fallback: título
            if any(k in t for k in SEC_TITLE_KW): return "sec"
            if any(k in t for k in SYS_TITLE_KW): return "sys"
            # OAT y unknown → sys (config de sistema/técnica de ataque)
            if source == "OAT": return "sys"
            return "sys"

        for a in assessments:
            cat   = str(a.get("category","") or a.get("type","") or "").lower()
            title = (a.get("title","") or a.get("checkName","") or a.get("filterName","")
                     or a.get("riskEvent","") or a.get("name","") or "Assessment")
            asset = (a.get("assetName","") or a.get("deviceName","") or
                     a.get("endpointName","") or
                     (a.get("endpoint") or {}).get("name","") or
                     a.get("affectedAsset","") or a.get("asset",""))
            risk  = _sev(a.get("riskLevel","") or a.get("severity","") or
                         a.get("risk_level",""))
            det   = _fmt(a.get("detectedDateTime","") or a.get("lastDetectedDateTime","")
                         or a.get("eventTime","") or a.get("createdDateTime",""))
            parts = []
            for k in ["recommendation","description","setting","value","osName","osVersion",
                      "affectedVersions","patchAvailable","cveCount",
                      "tactics","techniques","mitreTactic","mitreTechnique",
                      "category","ruleId","filterName","uuid"]:
                v = a.get(k,"")
                if v: parts.append(f"{k}: {v}")
            detail = " | ".join(parts[:10])
            source = a.get("_source","Posture")
            row = {
                "Status":                  a.get("status","Active"),
                "Risk event":              title,
                "Data source / processor": f"Trend Vision One — {source}",
                "Asset":                   asset,
                "Identity type":           "",
                "Event risk level":        risk,
                "Detected":                det,
                "Case":                    a.get("ruleId","") or a.get("uuid","") or a.get("id",""),
                "Remediation":             a.get("remediation","") or a.get("recommendation",""),
                "Suggested actions":       a.get("suggestedActions",""),
                "Detail info":             detail,
            }
            bucket = _classify_cat(cat, title, a.get("_source", ""))
            (sec if bucket == "sec" else sys_).append(row)

        return {"sec_conf": sec, "sys_conf": sys_}

    def normalize_cloud_apps(self, apps: list) -> list:
        rows = []
        for a in apps:
            app_name = (a.get("appName","") or a.get("application","") or
                        a.get("service","") or a.get("risk event","Unsanctioned App"))
            asset    = (a.get("endpointName","") or a.get("user","") or
                        a.get("sourceUser","") or a.get("sourceIp",""))
            risk     = _sev(a.get("riskLevel","") or a.get("severity",""))
            det      = _fmt(a.get("eventTime","") or a.get("detectedDateTime","") or a.get("timestamp",""))
            parts = []
            for k,v in a.items():
                if k.startswith("_"): continue
                if k in ("appName","riskLevel","eventTime","detectedDateTime"): continue
                if v and str(v) not in ("None","","null"):
                    val = _defang(str(v)) if any(x in k.lower() for x in ("url","link","host")) else str(v)
                    parts.append(f"{k}: {val}")
            rows.append({
                "Status":"Active",
                "Risk event":f"Cloud App de Riesgo: {app_name}",
                "Data source / processor":"Trend Vision One — Cloud App Security",
                "Asset":asset,"Identity type":"",
                "Event risk level":risk,"Detected":det,
                "Case":"","Remediation":"","Suggested actions":"",
                "Detail info":" | ".join(parts[:8]),
                "_app":app_name,
            })
        return rows

    def normalize_email_alerts(self, alerts: list) -> list:
        """Email Security alerts → threat-detections"""
        rows = []
        for a in alerts:
            risk  = _sev(a.get("severity","") or a.get("riskLevel",""))
            det   = _fmt(a.get("detectedDateTime","") or a.get("createdDateTime",""))
            sender  = a.get("sender","") or a.get("from","")
            subject = a.get("subject","") or a.get("mailSubject","")
            recip   = a.get("recipients","") or a.get("to","")
            detail_parts = []
            if sender:  detail_parts.append(f"from: {_defang(str(sender))}")
            if subject: detail_parts.append(f"subject: {subject[:80]}")
            if recip:   detail_parts.append(f"to: {str(recip)[:80]}")
            for k in ["threatType","malwareFamily","spamScore","phishingScore","url","sha256"]:
                v = a.get(k,"")
                if v: detail_parts.append(f"{k}: {_defang(str(v))}")
            rows.append({
                "Status":                  "Active",
                "Risk event":              a.get("subject","Email Security Alert")[:80] or "Email Security Alert",
                "Data source / processor": "Trend Vision One — Email Security",
                "Asset":                   str(recip)[:80],
                "Identity type":           "Email",
                "Event risk level":        risk,
                "Detected":                det,
                "Case":                    a.get("messageId","") or a.get("id",""),
                "Remediation":             "",
                "Suggested actions":       "Quarantine message and investigate sender",
                "Detail info":             " | ".join(detail_parts[:8]),
            })
        return rows

    def normalize_identity_risk(self, accounts: list) -> list:
        """Identity risk → account-compromise rows"""
        rows = []
        for a in accounts:
            risk_score = a.get("riskScore",0) or a.get("score",0)
            if risk_score < 30: continue  # solo cuentas con riesgo significativo
            name  = a.get("displayName","") or a.get("accountName","") or a.get("userPrincipalName","")
            upn   = a.get("userPrincipalName","") or name
            risk  = _sev("high" if risk_score >= 70 else "medium")
            parts = [f"riskScore: {risk_score}", f"upn: {upn}"]
            for k in ["riskFactors","lastRiskyActivity","location","mfaEnabled","isAdmin","lastLogin"]:
                v = a.get(k,"")
                if v: parts.append(f"{k}: {v}")
            rows.append({
                "Status":                  "Active",
                "Risk event":              f"Identity Risk: {name}",
                "Data source / processor": "Trend Vision One — Identity & Access",
                "Impact scope":            upn,
                "Event risk level":        risk,
                "Detected":                _fmt(a.get("lastRiskyActivity","") or a.get("detectedDateTime","")),
                "Case":                    a.get("accountId","") or a.get("id",""),
                "Remediation":             "",
                "Suggested actions":       "Review account activity and enforce MFA",
                "Detail info":             " | ".join(parts[:8]),
            })
        return rows

    def normalize_agent_health(self, agents: list) -> list:
        """Endpoint agent health issues → sys-conf rows"""
        rows = []
        for a in agents:
            status = a.get("agentStatus","") or a.get("status","")
            if status.lower() in ("active","normal","healthy"): continue
            name  = a.get("endpointName","") or a.get("displayName","") or a.get("name","")
            issue = a.get("agentStatusReason","") or a.get("statusReason","") or status
            parts = [f"status: {status}", f"issue: {issue}"]
            for k in ["lastConnected","agentVersion","osName","policyName","componentStatus"]:
                v = a.get(k,"")
                if v: parts.append(f"{k}: {v}")
            rows.append({
                "Status":                  "Active",
                "Risk event":              f"Agente sin protección: {issue}",
                "Data source / processor": "Trend Vision One — Endpoint Security",
                "Asset":                   name,
                "Identity type":           "",
                "Event risk level":        _sev(a.get("severity","medium")),
                "Detected":                _fmt(a.get("lastConnected","") or a.get("detectedDateTime","")),
                "Case":                    a.get("agentGuid","") or a.get("id",""),
                "Remediation":             "Reconnect and update agent",
                "Suggested actions":       "Verify endpoint connectivity and reinstall agent if needed",
                "Detail info":             " | ".join(parts[:8]),
                "_source": "agent_health",
            })
        return rows

    def normalize_audit_logs(self, logs: list) -> list:
        """Audit logs — cambios de config relevantes → sys-conf"""
        rows = []
        # Solo los cambios de config sensibles
        AUDIT_KEYWORDS = ("disable","delete","remove","modify","permission","password",
                          "policy","admin","api key","role","user","login","logout")
        for log in logs:
            action  = str(log.get("action","") or log.get("activity","") or "").lower()
            if not any(k in action for k in AUDIT_KEYWORDS): continue
            user    = log.get("user","") or log.get("account","") or log.get("loggedInAccount","")
            target  = log.get("target","") or log.get("object","") or log.get("resource","")
            det     = _fmt(log.get("loggedDateTime","") or log.get("createdDateTime","") or log.get("timestamp",""))
            parts   = [f"action: {log.get('action','')}", f"user: {user}", f"target: {target}"]
            for k in ["result","detail","ipAddress","source","category"]:
                v = log.get(k,"")
                if v: parts.append(f"{k}: {v}")
            rows.append({
                "Status":                  "Active",
                "Risk event":              f"Cambio de configuración: {log.get('action','Audit event')[:80]}",
                "Data source / processor": "Trend Vision One — Audit Logs",
                "Asset":                   str(target)[:100],
                "Identity type":           "User Account" if user else "",
                "Event risk level":        "Medium",
                "Detected":                det,
                "Case":                    log.get("id","") or log.get("logId",""),
                "Remediation":             "",
                "Suggested actions":       "Review and verify this configuration change",
                "Detail info":             " | ".join(parts[:8]),
                "_source": "audit",
            })
        return rows

    def normalize_intel_reports(self, reports: list) -> list:
        """
        Intelligence Reports → sys-conf rows.
        Son informes de amenazas activas relevantes para el sector.
        """
        rows = []
        for r in reports[:30]:  # top 30 más recientes
            name    = r.get("name","") or r.get("title","")
            updated = _fmt(r.get("updatedDateTime","") or r.get("createdDateTime",""))
            rep_id  = r.get("id","")
            rows.append({
                "Status":                   "Active",
                "Risk event":               f"Threat Intel: {name[:100]}",
                "Data source / processor":  "Trend Vision One — Threat Intelligence",
                "Asset":                    "",
                "Identity type":            "",
                "Event risk level":         "Medium",
                "Detected":                 updated,
                "Case":                     rep_id,
                "Remediation":              "",
                "Suggested actions":        "Review report and apply mitigations",
                "Detail info":              f"reportId: {rep_id} | updated: {updated} | name: {name[:120]}",
            })
        return rows

    def normalize_response_tasks(self, tasks: list) -> list:
        """Response tasks → complementa el Detail info de amenazas"""
        rows = []
        for t in tasks:
            action  = t.get("action","") or t.get("taskType","")
            status  = t.get("status","")
            target  = t.get("targetEndpoint","") or t.get("endpointName","") or t.get("target","")
            parts   = [f"action: {action}", f"status: {status}", f"target: {target}"]
            for k in ["taskId","triggeredBy","completedDateTime","reason","result"]:
                v = t.get(k,"")
                if v: parts.append(f"{k}: {v}")
            rows.append({
                "Status":                  "Resolved" if status.lower() in ("success","completed") else "Active",
                "Risk event":              f"Acción de respuesta: {action}",
                "Data source / processor": "Trend Vision One — Response Management",
                "Asset":                   target,
                "Identity type":           "",
                "Event risk level":        "Medium",
                "Detected":                _fmt(t.get("createdDateTime","") or t.get("triggeredDateTime","")),
                "Case":                    t.get("taskId","") or t.get("id",""),
                "Remediation":             f"Task {status}",
                "Suggested actions":       "",
                "Detail info":             " | ".join(parts[:8]),
                "_source": "response",
            })
        return rows

    def normalize_attack_paths(self, paths: list) -> list:
        """ASM Attack Paths → predictive-analytics"""
        rows = []
        for p in paths:
            score  = p.get("riskScore","") or p.get("score","")
            entry  = str(p.get("entryPoints",[]) or p.get("sourceAssets",[]))[:100]
            target = str(p.get("targetAssets",[]) or p.get("targets",[]))[:100]
            steps  = p.get("steps",[])
            parts  = [f"steps: {len(steps)}", f"riskScore: {score}"]
            for s in steps[:3]:
                if isinstance(s, dict): parts.append(f"step: {s.get('technique',s.get('description',''))[:50]}")
            rows.append({
                "Status":                  "Active",
                "Risk event":              p.get("name","") or f"Attack Path (score: {score})",
                "Data source / processor": "Trend Vision One — ASM Attack Paths",
                "Entry assets":            entry,
                "Target assets":           target,
                "Attack path risk score":  str(score),
                "Detected":                _fmt(p.get("detectedDateTime","") or p.get("createdDateTime","")),
                "Case":                    p.get("id",""),
                "Remediation":             p.get("remediation",""),
                "Suggested actions":       p.get("suggestedActions",""),
                "Detail info":             " | ".join(parts[:8]),
            })
        return rows

    def normalize_network_events(self, events: list) -> list:
        """Network security detections → threat-detections"""
        rows = []
        for e in events:
            src_ip  = e.get("sourceIp","") or e.get("src","") or e.get("objectIp","")
            dst_ip  = e.get("destinationIp","") or e.get("dst","") or e.get("targetIp","")
            asset   = e.get("endpointHostName","") or e.get("hostname","") or src_ip
            parts   = []
            if src_ip: parts.append(f"srcIP: {src_ip}")
            if dst_ip: parts.append(f"dstIP: {dst_ip}")
            for k in ["protocol","port","ruleName","action","threatType","sha256","url"]:
                v = e.get(k,"")
                if v: parts.append(f"{k}: {_defang(str(v))}")
            rows.append({
                "Status":                  "Active",
                "Risk event":              e.get("eventSubType","") or e.get("type","Network Event"),
                "Data source / processor": "Trend Vision One — Network Security",
                "Asset":                   asset,
                "Identity type":           "",
                "Event risk level":        _sev(e.get("severity","medium")),
                "Detected":                _fmt(e.get("eventTime","") or e.get("detectedDateTime","")),
                "Case":                    e.get("uuid","") or e.get("id",""),
                "Remediation":             "",
                "Suggested actions":       "",
                "Detail info":             " | ".join(parts[:10]),
                "_source": "network",
            })
        return rows

    def normalize_suspicious_objects(self, objects: list) -> list:
        """
        Suspicious Objects → sys-conf rows.
        Tipos reales: ip, domain, url, fileSha256, fileSha1
        Estructura real: {ip/domain/url/fileSha256: valor, type, description,
                          scanAction, riskLevel, inExceptionList,
                          lastModifiedDateTime, expiredDateTime}
        """
        rows = []
        TYPE_LABELS = {
            "ip":         ("🔴 IP maliciosa",       "IP bloqueada por Threat Intelligence"),
            "domain":     ("🌐 Dominio malicioso",  "Dominio bloqueado por Threat Intelligence"),
            "url":        ("🔗 URL maliciosa",       "URL bloqueada por Threat Intelligence"),
            "fileSha256": ("🦠 Hash malicioso",      "Archivo bloqueado (SHA256)"),
            "fileSha1":   ("🦠 Hash malicioso",      "Archivo bloqueado (SHA1)"),
        }
        for o in objects:
            otype = o.get("type","")
            # El valor está en el campo con el mismo nombre que el tipo
            value = o.get(otype,"") or o.get("objectValue","") or o.get("value","")
            if not value: continue  # skip si no hay valor
            risk    = _sev(o.get("riskLevel","high"))
            det     = _fmt(o.get("lastModifiedDateTime","") or o.get("expiredDateTime",""))
            action  = o.get("scanAction","block")
            desc    = o.get("description","")
            expired = o.get("expiredDateTime","")
            label, event_desc = TYPE_LABELS.get(otype, (f"Suspicious {otype}", "Objeto sospechoso"))
            rows.append({
                "Status":                  "Active",
                "Risk event":              f"{label}: {str(value)[:80]}",
                "Data source / processor": "Trend Vision One — Threat Intelligence",
                "Asset":                   "",
                "Identity type":           "",
                "Event risk level":        risk,
                "Detected":                det,
                "Case":                    "",
                "Remediation":             f"Action: {action}",
                "Suggested actions":       f"Block {otype} in firewall/DNS/proxy",
                "Detail info":             (
                    f"type: {otype} | value: {_defang(str(value))} | "
                    f"action: {action} | risk: {risk} | "
                    f"description: {desc[:80]} | expires: {expired[:10]}"
                ),
            })
        return rows

    def normalize_container_alerts(self, alerts: list) -> list:
        """Container Security alerts → threat-detections"""
        rows = []
        for a in alerts:
            cluster  = a.get("clusterName","") or a.get("cluster","")
            ns       = a.get("namespace","") or a.get("namespaceName","")
            asset    = f"{cluster}/{ns}" if cluster and ns else cluster or ns or a.get("id","")
            sev      = _sev(a.get("severity","") or a.get("riskLevel","medium"))
            rule     = a.get("ruleName","") or a.get("title","") or a.get("name","Container Alert")
            detail   = " | ".join(filter(None, [
                f"cluster: {cluster}" if cluster else "",
                f"namespace: {ns}" if ns else "",
                f"image: {a.get('imageName','')}" if a.get('imageName') else "",
                f"pod: {a.get('podName','')}" if a.get('podName') else "",
                f"description: {a.get('description','')[:80]}" if a.get('description') else "",
            ]))
            rows.append({
                "Status":                  "Active",
                "Risk event":              rule,
                "Data source / processor": "Trend Vision One — Container Security",
                "Asset":                   asset,
                "Identity type":           "Container",
                "Event risk level":        sev,
                "Detected":                _fmt(a.get("detectedDateTime","") or a.get("createdDateTime","")),
                "Case":                    a.get("id",""),
                "Remediation":             a.get("mitigationSuggestion","") or a.get("remediation",""),
                "Suggested actions":       a.get("suggestion",""),
                "Detail info":             detail,
                "_source":                 "container",
            })
        return rows

    def normalize_cloud_file_security(self, events: list) -> list:
        """Cloud File Security events → threat-detections"""
        rows = []
        for e in events:
            fname  = e.get("fileName","") or e.get("objectName","")
            svc    = e.get("cloudService","") or e.get("service","") or e.get("provider","")
            user   = e.get("userEmail","") or e.get("userId","") or e.get("accountEmail","")
            sev    = _sev(e.get("riskLevel","") or e.get("severity","medium"))
            detail = " | ".join(filter(None, [
                f"file: {fname[:60]}" if fname else "",
                f"service: {svc}" if svc else "",
                f"user: {user}" if user else "",
                f"sha256: {e.get('sha256','')}" if e.get('sha256') else "",
                f"detection: {e.get('detectionName','')[:60]}" if e.get('detectionName') else "",
                f"action: {e.get('action','')}" if e.get('action') else "",
            ]))
            rows.append({
                "Status":                  "Active",
                "Risk event":              e.get("detectionName","") or e.get("type","Cloud File Threat"),
                "Data source / processor": f"Trend Vision One — Cloud File Security ({svc})",
                "Asset":                   fname[:80],
                "Identity type":           "Cloud User",
                "Event risk level":        sev,
                "Detected":                _fmt(e.get("eventTime","") or e.get("detectedDateTime","")),
                "Case":                    e.get("id",""),
                "Remediation":             "",
                "Suggested actions":       "Review file and user activity",
                "Detail info":             detail,
                "_source":                 "cloud_file",
            })
        return rows

    def normalize_email_quarantine(self, messages: list) -> list:
        """Email quarantine messages → threat-detections (como amenazas bloqueadas)"""
        rows = []
        for m in messages:
            sender  = m.get("sender","") or m.get("from","")
            subject = m.get("subject","")
            reason  = m.get("quarantineReason","") or m.get("reason","") or m.get("threatType","Quarantined")
            recip   = m.get("recipientEmailAddress","") or m.get("recipient","")
            rows.append({
                "Status":                  "Active",
                "Risk event":              f"Email quarantined: {reason[:60]}",
                "Data source / processor": "Trend Vision One — Email Security (Quarantine)",
                "Asset":                   recip,
                "Identity type":           "Email",
                "Event risk level":        _sev(m.get("riskLevel","") or "medium"),
                "Detected":                _fmt(m.get("receivedDateTime","") or m.get("detectedDateTime","")),
                "Case":                    m.get("messageId","") or m.get("id",""),
                "Remediation":             "Message quarantined",
                "Suggested actions":       "Review sender and release or delete",
                "Detail info":             f"from: {sender} | subject: {subject[:80]} | reason: {reason}",
                "_source":                 "email_quarantine",
            })
        return rows

    def normalize_cloud_posture(self, checks: list) -> list:
        """Cloud Posture (Conformity) → sys-conf rows"""
        rows = []
        for c in checks:
            rule    = c.get("ruleName","") or c.get("checkName","") or c.get("title","Cloud Posture Check")
            svc     = c.get("service","") or c.get("cloudService","") or c.get("provider","")
            region  = c.get("region","") or c.get("cloudRegion","")
            acct    = c.get("accountId","") or c.get("cloudAccountId","")
            status  = c.get("status","") or c.get("result","")
            if status.lower() in ("pass","passed","ok"): continue  # solo failures
            sev     = _sev(c.get("riskLevel","") or c.get("severity","medium"))
            detail  = " | ".join(filter(None, [
                f"service: {svc}" if svc else "",
                f"region: {region}" if region else "",
                f"account: {acct}" if acct else "",
                f"status: {status}" if status else "",
                f"resource: {c.get('resource','')[:60]}" if c.get('resource') else "",
            ]))
            rows.append({
                "Status":                  "Active",
                "Risk event":              rule,
                "Data source / processor": f"Trend Vision One — Cloud Posture ({svc})",
                "Asset":                   acct or svc,
                "Identity type":           "Cloud",
                "Event risk level":        sev,
                "Detected":                _fmt(c.get("lastUpdatedDateTime","") or c.get("createdDateTime","")),
                "Case":                    c.get("id","") or c.get("checkId",""),
                "Remediation":             c.get("remediation","") or c.get("resolution",""),
                "Suggested actions":       c.get("description","")[:120],
                "Detail info":             detail,
                "_source":                 "cloud_posture",
            })
        return rows

    def normalize_endpoint_isolation(self, endpoints: list) -> list:
        """Isolated endpoints → sys-conf (situación de cuarentena activa)"""
        rows = []
        for ep in endpoints:
            name   = ep.get("endpointName","") or ep.get("hostname","") or ep.get("id","")
            reason = ep.get("isolationReason","") or ep.get("reason","") or "Isolated"
            rows.append({
                "Status":                  "Active",
                "Risk event":              f"Endpoint isolated: {reason[:80]}",
                "Data source / processor": "Trend Vision One — Endpoint Security (Isolation)",
                "Asset":                   name,
                "Identity type":           "",
                "Event risk level":        "High",
                "Detected":                _fmt(ep.get("isolatedDateTime","") or ep.get("lastUpdatedDateTime","")),
                "Case":                    ep.get("id","") or ep.get("agentGuid",""),
                "Remediation":             "Investigate and lift isolation when safe",
                "Suggested actions":       "",
                "Detail info":             f"ip: {ep.get('ip','')} | os: {ep.get('os','')} | reason: {reason}",
                "_source":                 "endpoint_isolation",
            })
        return rows

    def normalize_network_sensors(self, sensors: list) -> list:
        """Network sensors con estado anómalo → sys-conf rows"""
        rows = []
        for s in sensors:
            status  = (s.get("status","") or s.get("agentStatus","")).lower()
            if status in ("active","running","online","healthy","connected"): continue
            name    = s.get("sensorName","") or s.get("name","") or s.get("id","")
            ip      = s.get("ipAddress","") or s.get("managementIp","")
            version = s.get("version","") or s.get("sensorVersion","")
            rows.append({
                "Status":                  "Active",
                "Risk event":              f"Sensor de red con estado anómalo: {status or 'unknown'}",
                "Data source / processor": "Trend Vision One — Network Security",
                "Asset":                   name,
                "Identity type":           "Network Sensor",
                "Event risk level":        "Medium",
                "Detected":                _fmt(s.get("lastUpdatedDateTime","") or s.get("lastSeen","")),
                "Case":                    s.get("id",""),
                "Remediation":             "Check sensor connectivity and update if needed",
                "Suggested actions":       "",
                "Detail info":             f"ip: {ip} | version: {version} | status: {status}",
                "_source":                 "network_sensor",
            })
        return rows

    def normalize_endpoint_tasks(self, tasks: list) -> list:
        """Endpoint tasks fallidas o pendientes → sys-conf rows"""
        rows = []
        for t in tasks:
            status  = (t.get("status","") or t.get("taskStatus","")).lower()
            if status in ("success","completed","successful","done"): continue
            action  = t.get("action","") or t.get("taskType","") or t.get("type","Task")
            target  = (t.get("targetEndpoint","") or t.get("endpointName","") or t.get("target",""))
            task_id = t.get("taskId","") or t.get("id","")
            sev     = "High" if status in ("failed","error","timeout") else "Medium"
            parts   = [f"action: {action}", f"status: {status}"]
            if target:  parts.append(f"target: {target}")
            for k in ["reason","result","triggeredBy","progress"]:
                v = t.get(k,"")
                if v: parts.append(f"{k}: {v}")
            rows.append({
                "Status":                  "Active",
                "Risk event":              f"Tarea endpoint: {action} [{status}]",
                "Data source / processor": "Trend Vision One — Endpoint Response",
                "Asset":                   target,
                "Identity type":           "",
                "Event risk level":        sev,
                "Detected":                _fmt(t.get("createdDateTime","") or t.get("triggeredDateTime","")),
                "Case":                    task_id,
                "Remediation":             f"Review and retry task {task_id}: {action}",
                "Suggested actions":       "Check endpoint and retry task if needed",
                "Detail info":             " | ".join(parts[:8]),
                "_source":                 "endpoint_task",
            })
        return rows

    def normalize_xdr_entities(self, entities: list) -> dict:
        """XDR Impacted Entities → threats (hosts) y accounts (usuarios) deduplicados"""
        threats, accounts = [], []
        seen: set = set()
        for ent in entities:
            etype   = (ent.get("entityType","") or ent.get("type","")).lower()
            eid     = ent.get("entityId","") or ent.get("id","")
            ename   = ent.get("entityValue","") or ent.get("name","") or str(eid)
            if isinstance(ename, dict):
                ename = (ename.get("name","") or ename.get("accountName","") or
                         ename.get("displayName","") or str(eid))
            wb_id   = ent.get("workbenchId","") or ent.get("alertId","")
            risk    = _sev(ent.get("riskLevel","") or ent.get("severity","medium"))
            det     = _fmt(ent.get("lastDetectedDateTime","") or ent.get("detectedDateTime",""))
            uid     = f"{etype}:{eid or ename}"
            if uid in seen: continue
            seen.add(uid)
            detail  = f"entityType: {etype} | entityId: {eid} | workbenchId: {wb_id}"
            base = {
                "Status":                  "Active",
                "Data source / processor": "Trend Vision One — XDR Workbench",
                "Event risk level":        risk,
                "Detected":                det,
                "Case":                    wb_id or str(eid),
                "Remediation":             "",
                "Suggested actions":       "Investigate entity in Workbench",
                "Detail info":             detail,
                "_source":                 "xdr_entity",
            }
            if etype in ("account","user","email"):
                accounts.append({**base,
                    "Risk event":   f"Entidad XDR comprometida: {str(ename)[:80]}",
                    "Impact scope": str(ename)[:100],
                })
            elif etype in ("host","endpoint","server","container","network"):
                threats.append({**base,
                    "Risk event":    f"Endpoint XDR impactado: {str(ename)[:80]}",
                    "Asset":         str(ename)[:100],
                    "Identity type": "",
                })
        if threats or accounts:
            logger.info(f"xdr_entities: {len(threats)} threats, {len(accounts)} accounts")
        return {"threats": threats, "accounts": accounts}

    def normalize_eiqs(self, eiqs_data: list) -> list:
        """EIQS Endpoint Intelligence → cve-assets enrichment (endpoints con score de riesgo)"""
        results = []
        for ep in eiqs_data:
            name  = ep.get("displayName","") or ep.get("hostName","") or ep.get("name","")
            risk  = ep.get("riskScore","") or ep.get("cveScore","") or ep.get("cvssScore","")
            vuln  = ep.get("vulnerabilityCount","") or ep.get("cveCount","")
            if not risk and not vuln: continue
            os_   = f"{ep.get('osName','')} {ep.get('osVersion','')}".strip()
            ips   = ep.get("ipv4Addresses",[]) or []
            ip    = ", ".join(ips) if isinstance(ips, list) else str(ep.get("ip",""))
            results.append({
                "Status":                       "Active",
                "Device name":                  name,
                "Operating system":             os_,
                "IP address":                   ip,
                "Last user":                    ep.get("lastLogonUser",""),
                "CVE event risk score":         str(risk),
                "Total CVEs":                   str(vuln or "?"),
                "Average Unpatched Time (AUT)": "",
                "Asset groups":                 ep.get("policyName","") or ep.get("groupName",""),
                "Last detected":                _fmt(ep.get("lastConnectedDateTime","") or ep.get("lastSeen","")),
                "_source":                      "eiqs",
            })
        if results:
            logger.info(f"eiqs_normalize: {len(results)} endpoints con riesgo")
        return results

    # ── MAIN FETCH ────────────────────────────────────────────────────────────
    def fetch_all(self, mes_es: str, csv_dir: str, progress_cb=None) -> dict:
        """
        Descubre módulos, extrae TODO lo disponible, guarda CSVs.
        Se adapta automáticamente a los módulos que tenga cada cliente.
        """
        try: import pandas as pd
        except ImportError: raise RuntimeError("pandas no instalado: pip install pandas")

        out_path = Path(csv_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        start, end = _month_range(mes_es)
        s_str = start.strftime("%Y-%m-%dT%H:%M:%SZ")
        e_str = end.strftime("%Y-%m-%dT%H:%M:%SZ")

        steps_total = 27
        step_n = [0]
        def prog(msg):
            step_n[0] += 1
            if progress_cb: progress_cb(step_n[0], steps_total, msg)
            else: print(f"  [{step_n[0]:2d}/{steps_total}] {msg}")

        raw, src_stats = {}, {}

        # 1. Discover
        prog("Descubriendo módulos disponibles…")
        self.discover_modules()
        active_mods = sum(1 for v in self.modules.values() if v)
        # Log diagnóstico: status HTTP real de cada módulo
        _statuses_list = getattr(self, "module_status", {})
        for _m, _st in sorted(_statuses_list.items()):
            _ok = self.modules.get(_m, False)
            logger.info(f"  módulo {_m:30s} HTTP {_st:3d}  {'✓' if _ok else '✗'}")
        logger.info(f"discover_modules: {active_mods}/{len(self.modules)} activos")
        if active_mods == 0 and _statuses_list:
            _uniq_codes = set(_statuses_list.values())
            if _uniq_codes <= {403}:
                logger.error("DIAGNÓSTICO: Todos los endpoints devuelven 403. "
                             "La API key no tiene permisos suficientes. "
                             "Ve a Vision One → Administration → API Keys y asigna rol 'Master Administrator' o los roles necesarios.")
            elif _uniq_codes <= {401}:
                logger.error("DIAGNÓSTICO: Todos los endpoints devuelven 401. API key inválida o expirada.")
            elif _uniq_codes <= {0}:
                logger.error("DIAGNÓSTICO: Sin conexión con la API. Verifica la región configurada y la conectividad de red.")
            elif _uniq_codes <= {404}:
                logger.error("DIAGNÓSTICO: Todos los endpoints devuelven 404. Posible API key de región incorrecta o versión de API no soportada.")
            else:
                _code_summary = ", ".join(f"HTTP {c}: {sum(1 for v in _statuses_list.values() if v==c)}" for c in sorted(_uniq_codes))
                logger.error(f"DIAGNÓSTICO: Ningún módulo disponible. Distribución de errores: {_code_summary}")

        # 2. Workbench Alerts — SIEMPRE
        prog("Alertas Workbench (amenazas, anomalías, cuentas)…")
        raw["alerts"] = self.get_workbench_alerts(start, end)
        src_stats["workbench_alerts"] = len(raw["alerts"])

        # 3. OAT — si disponible
        prog("Técnicas de ataque observadas (MITRE ATT&CK)…")
        raw["oat"] = self.get_oat_events(start, end)
        src_stats["oat_events"] = len(raw["oat"])

        # 4. Endpoint Inventory
        prog("Inventario de endpoints…")
        raw["endpoints"] = self.get_endpoint_inventory()
        src_stats["endpoints"] = len(raw["endpoints"])
        logger.info(f"endpoints loaded: {len(raw['endpoints'])}")

        # 5. Endpoint Agent Health
        prog("Estado de agentes endpoint…")
        raw["agent_health"] = self.get_endpoint_agent_health()
        src_stats["agent_health"] = len(raw["agent_health"])

        # 6. ASM Vulnerabilities (TODOS los activos, sin filtro de fecha)
        prog("Vulnerabilidades CVE (ASM) — todos los activos…")
        raw["vulns_asm"] = self.get_asm_vulnerabilities(start, end)
        src_stats["asm_vulnerabilities"] = len(raw["vulns_asm"])
        logger.info(f"asm_vulns loaded: {len(raw['vulns_asm'])}")

        # 6b. ASM Endpoints para enriquecer risk scores por activo
        raw["asm_endpoints"] = self.get_asm_endpoints()
        src_stats["asm_endpoints"] = len(raw["asm_endpoints"])

        # 7. Search: CVEs adicionales si ASM no disponible
        prog("CVEs adicionales via Search API…")
        raw["search_cve"] = []
        if not raw["vulns_asm"] and self.modules.get("search"):
            raw["search_cve"] = self.get_search_detections(
                start, end,
                query='eventSubType:VULNERABILITY_DETECTION OR ruleName:*CVE* OR objectName:*CVE*',
                max_items=1000
            )
        src_stats["search_cve"] = len(raw["search_cve"])

        # 8. ASM Assessments + Attack Paths (sin restricción de fecha)
        prog("Evaluaciones de postura (ASM) — estado actual…")
        raw["assessments"] = self.get_asm_assessments()
        raw["attack_paths"] = self.get_asm_attack_paths()
        src_stats["asm_assessments"] = len(raw["assessments"])
        src_stats["asm_attack_paths"] = len(raw["attack_paths"])
        logger.info(f"assessments loaded: {len(raw['assessments'])}")

        # 9. Cloud Apps
        prog("Eventos cloud y SaaS…")
        raw["cloud"] = self.get_cloud_apps(start, end)
        src_stats["cloud_apps"] = len(raw["cloud"])

        # 10. Email Security
        prog("Alertas de seguridad de email…")
        raw["email"] = self.get_email_security_alerts(start, end)
        src_stats["email_alerts"] = len(raw["email"])

        # 11. Identity Risk
        prog("Riesgo de identidades y cuentas…")
        raw["identity"] = self.get_identity_risk()
        src_stats["identity_risk"] = len(raw["identity"])

        # 12. Suspicious Objects (Threat Intel)
        prog("Objetos sospechosos (Threat Intelligence)…")
        raw["suspicious"] = self.get_suspicious_objects()
        src_stats["suspicious_objects"] = len(raw["suspicious"])

        # 12b. Intel Reports — informes de amenazas activas
        raw["intel_reports"] = self.get_intel_reports()
        src_stats["intel_reports"] = len(raw["intel_reports"])

        # 13. Sandbox
        prog("Envíos a Sandbox…")
        raw["sandbox"] = self.get_sandbox_submissions(start, end)
        src_stats["sandbox"] = len(raw["sandbox"])

        # 14. Audit Logs
        prog("Logs de auditoría (cambios de config)…")
        raw["audit"] = self.get_audit_logs(start, end)
        src_stats["audit_logs"] = len(raw["audit"])

        # Guardar response tasks en raw
        raw["response_tasks"] = self.get_response_tasks(start, end)
        src_stats["response_tasks_fetched"] = len(raw["response_tasks"])

        # 15. Network Events via Search
        prog("Eventos de red (Network Security)…")
        raw["network"] = self.get_network_events(start, end)
        src_stats["network_events"] = len(raw["network"])

        # 16. Endpoint Tasks + Isolation + EIQS
        prog("Tareas y aislamientos de endpoints…")
        raw["endpoint_tasks"]     = self.get_endpoint_tasks()
        raw["endpoint_isolation"] = self.get_endpoint_isolation()
        raw["eiqs"]               = self.get_eiqs_data()
        src_stats["endpoint_tasks"]     = len(raw["endpoint_tasks"])
        src_stats["endpoint_isolation"] = len(raw["endpoint_isolation"])
        src_stats["eiqs"]               = len(raw["eiqs"])

        # 16b. Network Sensors + Policies
        prog("Sensores y políticas de red (Network Security)…")
        raw["network_sensors"]  = self.get_network_sensors()
        raw["network_policies"] = self.get_network_policies()
        src_stats["network_sensors"]  = len(raw["network_sensors"])
        src_stats["network_policies"] = len(raw["network_policies"])

        # 17. Cloud File Security
        prog("Seguridad de archivos en cloud…")
        raw["cloud_file"] = self.get_cloud_file_security(start, end)
        src_stats["cloud_file_security"] = len(raw["cloud_file"])

        # 18. Container Security
        prog("Alertas de seguridad de contenedores…")
        raw["container"] = self.get_container_security_alerts(start, end)
        src_stats["container_security"] = len(raw["container"])

        # 19. ASM Internet-Facing Assets
        prog("Activos expuestos a internet (ASM)…")
        raw["inet_facing"] = self.get_asm_internet_facing_assets()
        src_stats["asm_internet_facing"] = len(raw["inet_facing"])

        # 19b. CREM/ASRM: dispositivos de alto riesgo + grupos de activos
        raw["asrm_high_risk"]    = self.get_asrm_high_risk_devices()
        raw["asrm_asset_groups"] = self.get_asrm_asset_groups()
        src_stats["asrm_high_risk"]    = len(raw["asrm_high_risk"])
        src_stats["asrm_asset_groups"] = len(raw["asrm_asset_groups"])

        # 20. Email Quarantine
        prog("Mensajes en cuarentena (Email Security)…")
        raw["email_quarantine"] = self.get_email_quarantine(start, end)
        src_stats["email_quarantine"] = len(raw["email_quarantine"])

        # 21. Cloud Posture (Conformity)
        prog("Postura de seguridad cloud (Conformity)…")
        raw["cloud_posture"] = self.get_cloud_posture()
        src_stats["cloud_posture"] = len(raw["cloud_posture"])

        # 22. STIX Sweeping results
        prog("STIX Sweeping (búsqueda proactiva de IOCs)…")
        raw["stix_tasks"] = self.get_stix_sweeping_results()
        src_stats["stix_tasks"] = len(raw["stix_tasks"])

        # 23. XDR Impacted Entities
        prog("Entidades afectadas por alertas XDR…")
        raw["xdr_entities"] = self.get_xdr_impacted_entities(start, end)
        src_stats["xdr_entities"] = len(raw["xdr_entities"])

        # 24. Normalize, merge, save

        prog("Normalizando, combinando y guardando CSVs…")

        # Classify workbench alerts
        classified = self.normalize_alerts(raw["alerts"])

        # Email alerts → threats
        email_threats = self.normalize_email_alerts(raw["email"])
        classified["threats"].extend(email_threats)

        # Sandbox → threats
        for s in raw["sandbox"]:
            verdict = s.get("verdict","") or s.get("analysis",{}).get("verdict","")
            if verdict.lower() not in ("malicious","highly suspicious","suspicious"): continue
            fname_ = s.get("fileName","") or s.get("name","")
            classified["threats"].append({
                "Status":"Active",
                "Risk event":f"Sandbox: {verdict} — {fname_[:60]}",
                "Data source / processor":"Trend Vision One — Sandbox Analysis",
                "Asset":s.get("submittedBy","") or s.get("endpointName",""),
                "Identity type":"","Event risk level":"High",
                "Detected":_fmt(s.get("submittedDateTime","") or s.get("createdDateTime","")),
                "Case":s.get("id",""),"Remediation":"",
                "Suggested actions":"Quarantine file and investigate",
                "Detail info":f"verdict: {verdict} | sha256: {s.get('sha256','')} | type: {s.get('fileType','')} | file: {_defang(fname_[:50])}",
            })

        # Network events → threats
        classified["threats"].extend(self.normalize_network_events(raw["network"]))

        # Identity risk → account-compromise
        identity_rows = self.normalize_identity_risk(raw["identity"])
        classified["accounts"].extend(identity_rows)

        # Vulnerabilities — enriquecer endpoints con asm_endpoints risk scores
        all_endpoints = raw["endpoints"] + raw.get("asm_endpoints", [])
        vuln_raw  = raw["vulns_asm"] or raw["search_cve"]
        vuln_data = self.normalize_vulnerabilities(vuln_raw, all_endpoints)

        # Fallback CVE assets: desde riskScores del inventario si no hay datos CVE explícitos
        if not vuln_data.get("cve_assets") and raw["endpoints"]:
            inv_assets = self.get_endpoint_cve_assets_from_inventory()
            if inv_assets:
                vuln_data.setdefault("cve_assets", []).extend(inv_assets)
                src_stats["endpoint_cve_assets_inv"] = len(inv_assets)

        # EIQS enrichment: añadir endpoints EIQS a cve-assets si no están ya presentes
        if raw.get("eiqs"):
            eiqs_rows = self.normalize_eiqs(raw["eiqs"])
            if eiqs_rows:
                existing_names = {
                    str(r.get("Device name","")).lower()
                    for r in vuln_data.get("cve_assets", [])
                }
                new_rows = [
                    r for r in eiqs_rows
                    if str(r.get("Device name","")).lower() not in existing_names
                ]
                if new_rows:
                    vuln_data.setdefault("cve_assets", []).extend(new_rows)
                    src_stats["eiqs_cve_assets"] = len(new_rows)

        # Posture: assessments + OAT (tagged)
        oat_tagged = [{**o, "_source":"OAT"} for o in raw["oat"]]
        posture_data = self.normalize_assessments(raw["assessments"] + oat_tagged)

        # Fallback assessments: sintetizar desde inventario de endpoints cuando ASM no disponible
        if not raw["assessments"] and raw["endpoints"]:
            synth = self.synthesize_endpoint_assessments()
            posture_data["sec_conf"].extend(synth["sec_conf"])
            posture_data["sys_conf"].extend(synth["sys_conf"])
            src_stats["endpoint_synth_sec"] = len(synth["sec_conf"])
            src_stats["endpoint_synth_sys"] = len(synth["sys_conf"])

        # Agent health → sys-conf
        posture_data["sys_conf"].extend(self.normalize_agent_health(raw["agent_health"]))

        # Audit logs → sys-conf (config changes)
        posture_data["sys_conf"].extend(self.normalize_audit_logs(raw["audit"]))

        # Suspicious objects → sys-conf (IPs/dominios/hashes maliciosos activos)
        posture_data["sys_conf"].extend(self.normalize_suspicious_objects(raw["suspicious"])[:30])

        # Intel reports → sys-conf (amenazas del sector relevantes)
        posture_data["sys_conf"].extend(self.normalize_intel_reports(raw.get("intel_reports",[])))

        # Response tasks → añadir contexto a amenazas ya clasificadas
        # (enriquecemos el Detail info de threats con las acciones tomadas)
        resp_tasks = self.normalize_response_tasks(raw.get("response_tasks",raw.get("resp_tasks",[])))
        if resp_tasks:
            classified["threats"].extend(resp_tasks)

        # Cloud: try module, fallback to workbench cloud-model alerts
        cloud_rows = self.normalize_cloud_apps(raw["cloud"])
        if not cloud_rows:
            cloud_wb = [a for a in raw["alerts"] if any(
                k in str(a.get("model","")).lower()
                for k in ("cloud","saas","dropbox","onedrive","sharepoint","google","teams",
                           "o365","microsoft 365","box.com","wetransfer","mega.nz")
            )]
            cloud_rows = self.normalize_cloud_apps(cloud_wb)

        # Cloud File Security → threats
        classified["threats"].extend(self.normalize_cloud_file_security(raw.get("cloud_file",[])))

        # Email quarantine → threats (mensajes bloqueados)
        classified["threats"].extend(self.normalize_email_quarantine(raw.get("email_quarantine",[])))

        # Container security → threats
        classified["threats"].extend(self.normalize_container_alerts(raw.get("container",[])))

        # XDR Impacted Entities → threats (hosts) + accounts (usuarios), deduplicados
        xdr_ent = self.normalize_xdr_entities(raw.get("xdr_entities",[]))
        classified["threats"].extend(xdr_ent["threats"])
        classified["accounts"].extend(xdr_ent["accounts"])
        src_stats["xdr_entity_threats"]  = len(xdr_ent["threats"])
        src_stats["xdr_entity_accounts"] = len(xdr_ent["accounts"])

        # Endpoint isolation → sys-conf
        posture_data["sys_conf"].extend(self.normalize_endpoint_isolation(raw.get("endpoint_isolation",[])))

        # Cloud Posture (Conformity) → sys-conf
        posture_data["sys_conf"].extend(self.normalize_cloud_posture(raw.get("cloud_posture",[])))

        # Network sensors con estado anómalo → sys-conf
        posture_data["sys_conf"].extend(self.normalize_network_sensors(raw.get("network_sensors",[])))

        # Endpoint tasks fallidas o pendientes → sys-conf
        posture_data["sys_conf"].extend(self.normalize_endpoint_tasks(raw.get("endpoint_tasks",[])))

        # STIX hits → sys-conf (IOCs encontrados)
        for task in raw.get("stix_tasks", []):
            hits = task.get("_hits", [])
            if hits:
                for h in hits[:10]:
                    posture_data["sys_conf"].append({
                        "Status": "Active",
                        "Risk event": f"STIX IOC match: {task.get('name','')[:60]}",
                        "Data source / processor": "Trend Vision One — STIX Sweeping",
                        "Asset": str(h.get("endpointHostName","") or h.get("asset","")),
                        "Identity type": "",
                        "Event risk level": "High",
                        "Detected": _fmt(task.get("lastUpdatedDateTime","") or task.get("createdDateTime","")),
                        "Case": task.get("id",""),
                        "Remediation": "",
                        "Suggested actions": "Investigate matched IOC on affected endpoints",
                        "Detail info": f"hits: {task.get('_hit_count',0)} | pattern: {task.get('stixPattern','')[:80]}",
                        "_source": "stix",
                    })

        # Attack paths → predictive-analytics
        predict_rows = self.normalize_attack_paths(raw["attack_paths"])

        # Enriquecer vuln_data con internet-facing assets
        if raw.get("inet_facing"):
            inet_names = {
                str(a.get("hostname","") or a.get("endpointName","")).lower()
                for a in raw["inet_facing"]
            }
            inet_ips = {
                str(a.get("ipAddress","") or a.get("publicIp",""))
                for a in raw["inet_facing"]
            } - {""}
            for row in vuln_data.get("cve_assets", []):
                dn = str(row.get("Device name","")).lower()
                ip = str(row.get("IP address",""))
                if dn in inet_names or ip in inet_ips:
                    row["Asset groups"] = (row.get("Asset groups","") + " | Internet-Facing").lstrip(" | ")

        # Enriquecer vuln_data con dispositivos de alto riesgo (ASRM)
        if raw.get("asrm_high_risk"):
            high_risk_names = {
                str(a.get("hostname","") or a.get("deviceName","") or a.get("endpointName","")).lower()
                for a in raw["asrm_high_risk"]
            } - {""}
            for row in vuln_data.get("cve_assets", []):
                dn = str(row.get("Device name","")).lower()
                if dn in high_risk_names:
                    row["Asset groups"] = (row.get("Asset groups","") + " | High-Risk (ASRM)").lstrip(" | ")

        # Enriquecer vuln_data con grupos de activos (ASRM assetGroups)
        if raw.get("asrm_asset_groups"):
            group_by_device: Dict[str, List[str]] = {}
            for g in raw["asrm_asset_groups"]:
                gname = g.get("name","") or g.get("groupName","")
                if not gname: continue
                for member in (g.get("devices") or g.get("members") or g.get("assets") or []):
                    mname = str(member.get("hostname","") or member.get("deviceName","")
                                if isinstance(member, dict) else member).lower()
                    if mname:
                        group_by_device.setdefault(mname, []).append(gname)
            if group_by_device:
                for row in vuln_data.get("cve_assets", []):
                    dn = str(row.get("Device name","")).lower()
                    groups = group_by_device.get(dn)
                    if groups:
                        existing = row.get("Asset groups","")
                        row["Asset groups"] = (existing + " | " + ", ".join(groups)).lstrip(" | ")

        # ── Save CSVs ──────────────────────────────────────────────────────
        CSV_COLS = {
            "threat-detections.csv":    ["Status","Risk event","Data source / processor","Asset","Identity type","Event risk level","Detected","Case","Remediation","Suggested actions","Detail info"],
            "anomaly-detections.csv":   ["Status","Risk event","Data source / processor","Asset","Identity type","Event risk level","Detected","Case","Remediation","Suggested actions","Detail info"],
            "account-compromise.csv":   ["Status","Risk event","Data source / processor","Impact scope","Event risk level","Detected","Case","Remediation","Suggested actions","Detail info"],
            "cve-events.csv":           ["Status","Vulnerability ID","CVE impact score","Global exploit potential","OS/Application","Impact scope","Prevention rule","Exploit attempts","First seen time","Publish date"],
            "cve-assets.csv":           ["Status","Device name","Operating system","IP address","Last user","CVE event risk score","Total CVEs","Average Unpatched Time (AUT)","Asset groups","Last detected"],
            "security-conf.csv":        ["Status","Risk event","Data source / processor","Asset","Identity type","Event risk level","Detected","Case","Remediation","Suggested actions","Detail info"],
            "sys-conf.csv":             ["Status","Risk event","Data source / processor","Asset","Identity type","Event risk level","Detected","Case","Remediation","Suggested actions","Detail info"],
            "cloud-app.csv":            ["Status","Risk event","Data source / processor","Asset","Identity type","Event risk level","Detected","Case","Remediation","Suggested actions","Detail info"],
            "predictive-analytics.csv": ["Status","Risk event","Data source / processor","Entry assets","Target assets","Attack path risk score","Detected","Case","Remediation","Suggested actions","Detail info"],
        }
        CSV_DATA = {
            "threat-detections.csv":    classified["threats"],
            "anomaly-detections.csv":   classified["anomaly"],
            "account-compromise.csv":   classified["accounts"],
            "cve-events.csv":           vuln_data["cve_events"],
            "cve-assets.csv":           vuln_data["cve_assets"],
            "security-conf.csv":        posture_data["sec_conf"],
            "sys-conf.csv":             posture_data["sys_conf"],
            "cloud-app.csv":            cloud_rows,
            "predictive-analytics.csv": predict_rows,
        }

        row_counts = {}
        for fname, rows in CSV_DATA.items():
            cols = CSV_COLS[fname]
            df   = pd.DataFrame(rows) if rows else pd.DataFrame(columns=cols)
            for c in cols:
                if c not in df.columns: df[c] = ""
            keep = [c for c in cols if c in df.columns] +                    [c for c in df.columns if c not in cols and not c.startswith("_")]
            df = df[keep]
            df.to_csv(out_path / fname, index=False, encoding="utf-8-sig")
            row_counts[fname] = len(df)

        # Response tasks in meta (not CSV) — reusa lo ya extraído (sin re-llamar API)
        response_count = len(raw.get("response_tasks", []))

        # Resumen de extracción
        zero_csvs = [k for k, v in row_counts.items() if v == 0]
        if zero_csvs:
            prog(f"⚠ CSVs vacíos: {', '.join(zero_csvs)}")
        prog(f"✓ Total filas extraídas: {sum(row_counts.values()):,} en {len(row_counts)} CSVs")

        # Risk score from API (asm/riskScore or riskInsights)
        _risk_api = {}
        try:
            _risk_api = self.get_risk_score()
        except Exception:
            pass
        _risk_score_val = (_risk_api.get("riskScore") or _risk_api.get("score")
                           or _risk_api.get("data",{}).get("riskScore") or 0)

        # Internet-exposed asset count from ASM endpoints (hasPublicIP or exposure type)
        _inet_exposed = 0
        for ep in raw.get("asm_endpoints", []):
            pub = ep.get("publicIpAddresses") or ep.get("exposureStatus") or ep.get("publicIp")
            if pub:
                _inet_exposed += 1
        # Fallback: cve_assets with non-RFC1918 IP
        if _inet_exposed == 0:
            for row in vuln_data.get("cve_assets", []):
                ip = str(row.get("IP address", "")).strip()
                try:
                    if not ipaddress.ip_address(ip).is_private:
                        _inet_exposed += 1
                except Exception:
                    pass

        # Save metadata
        meta = {
            "empresa":           str(out_path.parent.name),
            "mes":               mes_es,
            "extracted_at":      datetime.now().isoformat(),
            "region":            self.base_url,
            "modules":           self.modules,
            "module_status":     getattr(self, "module_status", {}),
            "src_stats":         {**src_stats, "response_tasks": response_count},
            "rows":              row_counts,
            "total_rows":        sum(row_counts.values()),
            "warnings":          zero_csvs,
            "risk_score_api":    _risk_score_val,
            "internet_exposed":  _inet_exposed,
        }
        (out_path / ".api_meta.json").write_text(
            json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8"
        )

        return {"rows": row_counts, "modules": self.modules,
                "src_stats": {**src_stats, "response_tasks": response_count}}



# ══════════════════════════════════════════════════════════════════════════════
# RICH OUTPUT
# ══════════════════════════════════════════════════════════════════════════════

def _print_results(empresa: str, mes: str, result: dict, elapsed: float):
    """Output visual completo de la extracción — módulos, fuentes y CSVs."""
    rows      = result.get("rows", {})
    modules   = result.get("modules", {})
    statuses  = result.get("module_status", {})
    src_stats = result.get("src_stats", {})
    total     = sum(rows.values())

    # ── MODULE GROUPS ─────────────────────────────────────────────────────────
    MODULE_GROUPS = {
        "Core XDR": [
            ("workbench",          "Workbench Alerts",              "Alertas correlacionadas XDR"),
            ("oat",                "Observed Attack Techniques",     "Técnicas MITRE ATT&CK"),
            ("search",             "Search API",                     "Búsqueda en logs históricos"),
        ],
        "Endpoint Security": [
            ("endpoint_inventory",   "Inventario Endpoints",         "Lista y estado de todos los endpoints"),
            ("endpoint_eiqs",        "Endpoint Intel (EIQS)",        "Inventario vía EIQS"),
            ("endpoint_health",      "Agent Health",                 "Estado de agentes de protección"),
            ("endpoint_tasks",       "Endpoint Tasks",               "Tareas pendientes en endpoints"),
            ("endpoint_vuln_agg",    "CVE Agregado",                 "CVEs vía Endpoint Security (aggregate)"),
            ("endpoint_vuln_detail", "CVE por Endpoint",             "CVEs vía per-endpoint API"),
            ("endpoint_isolation",   "Endpoints Aislados",           "Endpoints en aislamiento de red"),
        ],
        "CREM (ASRM / Cyber Risk)": [
            ("asm_vuln",           "Vulnerabilidades CVE",           "vulnerableDevices"),
            ("asm_assessments",    "Evaluaciones de postura",        "securityPosture"),
            ("asm_endpoints",      "Endpoints (attack surface)",     "attackSurfaceDevices"),
            ("asm_internet_facing","IPs públicas expuestas",         "attackSurfacePublicIpAddresses"),
            ("asrm_high_risk",     "Dispositivos alto riesgo",       "highRiskDevices"),
            ("asrm_asset_groups",  "Grupos de activos",              "assetGroups"),
            ("asm_attack_paths",   "Rutas de ataque",                "Simulación de ataques (predictivo)"),
            ("asm_risk",           "Risk Score",                     "Puntuación de riesgo global"),
        ],
        "Cloud & Email": [
            ("cloud_access",       "Cloud App Access",               "Apps SaaS de riesgo"),
            ("cloud_email",        "Email Security",                 "Phishing, malware, BEC"),
            ("cloud_file_security","File Security",                  "Análisis de archivos en cloud"),
        ],
        "Threat Intelligence": [
            ("sandbox",            "Sandbox Analysis",               "Análisis dinámico de malware"),
            ("suspicious_objects", "Suspicious Objects",             "IOCs activos en la red"),
            ("intel_reports",      "Intel Reports",                  "Informes de inteligencia"),
            ("intel_tasks",        "STIX Sweeping",                  "Búsqueda proactiva de IOCs"),
        ],
        "Identity & Network": [
            ("identity_accounts",  "Cuentas (IAM)",                  "Inventario de cuentas"),
            ("identity_risk",      "Identity Risk",                  "Cuentas con riesgo elevado"),
            ("network_sensor",     "Network Sensors",                "Sensores de red desplegados"),
            ("audit_logs",         "Audit Logs",                     "Cambios de configuración"),
            ("response_tasks",     "Response Tasks",                 "Acciones de respuesta ejecutadas"),
        ],
        "Risk & Compliance": [
            ("risk_insights",      "Risk Insights",                  "Dashboard de riesgo ejecutivo"),
        ],
    }

    CSV_LABELS = {
        "threat-detections.csv":    ("🚨", "Amenazas activas",         "Malware, ransomware, C2, exploits"),
        "anomaly-detections.csv":   ("📡", "Anomalías detectadas",     "Comportamiento inusual"),
        "account-compromise.csv":   ("👤", "Compromiso de cuentas",    "Credential stuffing, brute force"),
        "cve-events.csv":           ("🔓", "CVE Vulnerabilidades",     "Fallos de seguridad sin parchear"),
        "cve-assets.csv":           ("💻", "Activos vulnerables",      "Equipos con CVEs pendientes"),
        "security-conf.csv":        ("🔒", "Config. Seguridad",        "Herramientas de seguridad mal config."),
        "sys-conf.csv":             ("⚙️", "Config. Sistema",          "OS, software, configuraciones"),
        "cloud-app.csv":            ("☁️", "Cloud Apps de riesgo",     "Apps SaaS no autorizadas"),
        "predictive-analytics.csv": ("🎯", "Analítica predictiva",     "Rutas de ataque simuladas"),
    }

    SOURCE_LABELS = {
        "workbench_alerts":         "Workbench Alerts",
        "oat_events":               "Técnicas de Ataque (OAT)",
        "endpoints":                "Inventario Endpoints",
        "agent_health":             "Estado de Agentes",
        "asm_vulnerabilities":      "CVEs (ASM)",
        "search_cve":               "CVEs (Search API)",
        "asm_assessments":          "Evaluaciones (ASM)",
        "asm_attack_paths":         "Rutas de Ataque",
        "cloud_apps":               "Cloud Apps",
        "email_alerts":             "Email Security",
        "identity_risk":            "Identity Risk",
        "suspicious_objects":       "Suspicious Objects",
        "sandbox":                  "Sandbox",
        "audit_logs":               "Audit Logs",
        "network_events":           "Network Events",
        "response_tasks":           "Response Tasks",
        "eiqs":                     "EIQS (Endpoint Intel)",
        "endpoint_cve_assets_inv":  "CVE Assets (Inventario)",
        "endpoint_synth_sec":       "Sec-Conf (Sintetizado)",
        "endpoint_synth_sys":       "Sys-Conf (Sintetizado)",
        "network_sensors":          "Network Sensors",
        "network_policies":         "Network Policies",
        "eiqs_cve_assets":          "CVE Assets (EIQS)",
        "xdr_entity_threats":       "XDR Entities (Threats)",
        "xdr_entity_accounts":      "XDR Entities (Accounts)",
        "asrm_high_risk":           "Dispositivos alto riesgo (ASRM)",
        "asrm_asset_groups":        "Grupos de activos (ASRM)",
    }

    try:
        from rich.console import Console
        from rich.table   import Table
        from rich.panel   import Panel
        from rich.rule    import Rule
        from rich         import box
        console = Console()
        RICH = True
    except ImportError:
        RICH = False

    # ── PLAIN FALLBACK ────────────────────────────────────────────────────────
    if not RICH:
        w = 64
        print(f"\n{'═'*w}")
        print(f"  CREM — Extracción Vision One")
        print(f"  {empresa}  ·  {mes}  ·  {elapsed:.1f}s")
        print(f"{'═'*w}")
        print("\n  MÓDULOS DETECTADOS:")
        for grp, items in MODULE_GROUPS.items():
            any_active = any(modules.get(k) for k,_,_ in items)
            grp_status = "✓" if any_active else "○"
            print(f"    {grp_status}  [{grp}]")
            for k, label, desc in items:
                st = "  ✓" if modules.get(k) else "  ✗"
                print(f"      {st}  {label}")
        print("\n  DATOS EXTRAÍDOS:")
        for k, n in src_stats.items():
            label = SOURCE_LABELS.get(k, k)
            print(f"    {'✓' if n else '○'}  {label:30s} {n:>5,}")
        print("\n  CSVs GENERADOS:")
        for fname, n in rows.items():
            ico, label, _ = CSV_LABELS.get(fname, ("·", fname, ""))
            print(f"    {'✓' if n else '○'}  {ico} {label:28s} {n:>5,}")
        print(f"\n  Total: {total:,} filas  ·  {elapsed:.1f}s")
        return

    # ── RICH VERSION ──────────────────────────────────────────────────────────
    console.print()
    console.print(Rule(
        f"[bold]  CREM — TrendAI Vision One  ·  {empresa}  ·  {mes}  ",
        style="bold dim"
    ))
    console.print()

    # ── Tabla de módulos por grupo ────────────────────────────────────────────
    mod_table = Table(
        box=box.ROUNDED, border_style="dim",
        title="[bold]  Módulos disponibles[/]", title_style="bold",
        title_justify="left", expand=False,
        show_header=True, header_style="dim bold",
        min_width=56
    )
    mod_table.add_column("Grupo",   style="dim",   min_width=18, no_wrap=True)
    mod_table.add_column("Módulo",                 min_width=24, no_wrap=True)
    mod_table.add_column("Estado",  justify="center", min_width=14)
    mod_table.add_column("HTTP",    justify="center", min_width=6)

    _HTTP_REASON = {0:"red-error", 200:"OK", 400:"bad-params", 401:"unauth",
                    403:"forbidden", 404:"not-found", 405:"method-err", 429:"rate-limit"}
    for grp, items in MODULE_GROUPS.items():
        for i, (k, label, desc) in enumerate(items):
            ok  = modules.get(k, False)
            st  = statuses.get(k, 0)
            grp_cell = f"[dim]{grp}[/]" if i == 0 else ""
            http_cell = f"[green]{st}[/]" if ok else (
                f"[yellow]{st}[/]" if st in (400, 405) else
                f"[red]{st}[/]" if st in (401, 403) else
                f"[dim]{st}[/]"
            )
            if ok:
                mod_table.add_row(grp_cell, f"[bold]{label}[/]", "[green]✓  Activo[/]", http_cell)
            else:
                reason = _HTTP_REASON.get(st, "")
                state_cell = f"[dim]✗  {reason}[/]" if reason else "[dim]✗  N/D[/]"
                mod_table.add_row(grp_cell, f"[dim]{label}[/]", state_cell, http_cell)

    # ── Tabla de fuentes ──────────────────────────────────────────────────────
    src_table = Table(
        box=box.ROUNDED, border_style="dim",
        title="[bold]  Datos por fuente[/]", title_style="bold",
        title_justify="left", expand=False,
        show_header=True, header_style="dim bold",
        min_width=40
    )
    src_table.add_column("Fuente",    min_width=26, no_wrap=True)
    src_table.add_column("Registros", justify="right", min_width=10)

    sorted_srcs = sorted(src_stats.items(), key=lambda x: -x[1])
    for k, n in sorted_srcs:
        label = SOURCE_LABELS.get(k, k.replace("_"," ").title())
        if n > 0:
            src_table.add_row(f"[bold]{label}[/]", f"[bold green]{n:,}[/]")
        else:
            src_table.add_row(f"[dim]{label}[/]", "[dim]—[/]")

    # Print side by side if terminal is wide enough, else stacked
    import shutil
    term_w = shutil.get_terminal_size((100,40)).columns
    if term_w >= 110:
        from rich.columns import Columns
        console.print(Columns([mod_table, src_table], padding=(0,2)))
    else:
        console.print(mod_table)
        console.print()
        console.print(src_table)
    console.print()

    # ── Tabla de CSVs ─────────────────────────────────────────────────────────
    csv_table = Table(
        box=box.SIMPLE_HEAD, border_style="dim",
        title="[bold]  Archivos generados[/]", title_style="bold",
        title_justify="left", expand=True,
        show_header=True, header_style="dim bold"
    )
    csv_table.add_column("CSV",         style="dim",   min_width=26, no_wrap=True)
    csv_table.add_column("Módulo",                     min_width=24, no_wrap=True)
    csv_table.add_column("Descripción",                min_width=32)
    csv_table.add_column("Filas",       justify="right", min_width=7)
    csv_table.add_column("",            min_width=14)  # bar

    max_n = max((v for v in rows.values()), default=1)
    for fname, n in rows.items():
        ico, label, desc = CSV_LABELS.get(fname, ("·", fname, ""))
        bar_len = round((n / max_n) * 12) if n > 0 else 0
        bar = "█" * bar_len

        if n > 0:
            csv_table.add_row(
                f"{ico}  {fname.replace('.csv','')}",
                f"[bold]{label}[/]",
                f"[dim]{desc}[/]",
                f"[bold green]{n:,}[/]",
                f"[green]{bar}[/]"
            )
        else:
            csv_table.add_row(
                f"[dim]{ico}  {fname.replace('.csv','')}[/]",
                f"[dim]{label}[/]",
                f"[dim]{desc}[/]",
                "[dim]—[/]",
                "[dim]Sin datos[/]"
            )

    console.print(csv_table)
    console.print()

    # ── Panel resumen ─────────────────────────────────────────────────────────
    active_count = sum(1 for v in modules.values() if v)
    total_mods   = len(modules)
    coverage_pct = round(active_count / total_mods * 100) if total_mods else 0
    csvs_with_data = sum(1 for v in rows.values() if v > 0)

    summary = (
        f"[bold green]{total:,} filas totales[/]  ·  "
        f"[bold]{csvs_with_data}/{len(rows)}[/] CSVs con datos  ·  "
        f"[bold]{active_count}/{total_mods}[/] módulos activos ({coverage_pct}%)  ·  "
        f"[dim]{elapsed:.1f}s[/]"
    )
    console.print(Panel(summary, border_style="green", expand=False, padding=(0,1)))
    console.print()


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import argparse
    # Portabilidad: resolver rutas (CLIENTES/, .env, CSV/) junto a este script,
    # no respecto al directorio desde el que se invoque. Así funciona igual en
    # cualquier equipo aunque la carpeta compartida cambie de ruta absoluta.
    os.chdir(Path(__file__).resolve().parent)

    parser = argparse.ArgumentParser(
        description="CREM — Extracción de datos TrendAI Vision One API",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python trendai_api.py --empresa ACME --mes "Mayo 2026" --test
  python trendai_api.py --empresa ACME --mes "Mayo 2026"
  python trendai_api.py --empresa ACME --mes "Mayo 2026" --discover
        """
    )
    parser.add_argument("--empresa",   required=True, help='Nombre empresa (carpeta donde está el .env y CSV/)')
    parser.add_argument("--mes",       default="", help='Período: "Mayo 2026"')
    parser.add_argument("--env-file",  help=".env path (default: [EMPRESA]/.env)")
    parser.add_argument("--test",      action="store_true", help="Solo probar conexión")
    parser.add_argument("--discover",  action="store_true", help="Solo descubrir módulos disponibles")
    parser.add_argument("--only-risk", action="store_true", help="Solo obtener el Cyber Risk Index desde la API")
    parser.add_argument("--verbose",   action="store_true", help="Log detallado")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s"
    )

    _cli_base = Path("CLIENTES")
    env_file = args.env_file or (
        str(_cli_base / args.empresa / ".env") if _cli_base.is_dir()
        else f"{args.empresa}/.env"
    )
    try:
        client = TrendAIClient.from_env(env_file)
    except Exception as e:
        print(f"\n  ✗ Error cargando .env: {e}")
        print(f"  → Asegúrate de que existe {env_file} con TRENDAI_API_KEY=...")
        sys.exit(1)

    # ── Only Risk mode
    if args.only_risk:
        print(f"\n  Obteniendo Cyber Risk Index para {args.empresa}…")
        risk_res = client.get_cyber_risk_index()
        if risk_res.get("ok"):
            print(f"  ✓ Cyber Risk Index: {risk_res['score']} ({risk_res['level']}) — Endpoint: {risk_res['endpoint']}\n")
            sys.exit(0)
        else:
            print(f"  ✗ Error: {risk_res.get('message')}\n")
            sys.exit(1)

    # ── Test mode
    if args.test:

        result = client.test_connection()
        icon = "✓" if result["ok"] else "✗"
        print(f"\n  {icon} {result['message']}\n")
        sys.exit(0 if result["ok"] else 1)

    # ── Discover mode
    if args.discover:
        print(f"\n  Descubriendo módulos para {args.empresa}…\n")
        mods = client.discover_modules()
        active = [k for k,v in mods.items() if v]
        inactive = [k for k,v in mods.items() if not v]
        print(f"  Activos ({len(active)}):")
        for m in sorted(active): print(f"    ✓  {m}")
        print(f"\n  No disponibles ({len(inactive)}):")
        for m in sorted(inactive): print(f"    ○  {m}")
        print()
        sys.exit(0)

    # ── Full fetch
    csv_dir = (
        str(_cli_base / args.empresa / "CSV") if _cli_base.is_dir()
        else f"{args.empresa}/CSV"
    )
    t0 = time.monotonic()

    try:
        from rich.console import Console
        Console().print(f"\n  [bold]Extrayendo datos:[/] {args.empresa} — {args.mes}")
        Console().print(f"  [dim]Región: {client.base_url}[/]\n")
    except ImportError:
        print(f"\n  Extrayendo datos: {args.empresa} — {args.mes}")
        print(f"  Región: {client.base_url}\n")

    try:
        result = client.fetch_all(args.mes, csv_dir)
        elapsed = round(time.monotonic() - t0, 1)
        _print_results(args.empresa, args.mes, result, elapsed)
    except Exception as e:
        if args.verbose:
            import traceback; traceback.print_exc()
        else:
            print(f"\n  ✗ Error: {e}\n  (usa --verbose para más detalle)")
        sys.exit(1)
