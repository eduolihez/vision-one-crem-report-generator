# CREM — Cybersecurity Risk, Exposure & Management Review

![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-uso%20interno%20real-orange)

Sistema automatizado de generación de informes de seguridad mensual basado en **Trend Micro Vision One**. Extrae, normaliza y presenta todos los eventos de seguridad del tenant en informes HTML interactivos (responsive), Word y PDF.

Los datos pueden venir de **dos fuentes**, ambas soportadas:

- **API de Vision One** — descarga automática (requiere API key con permisos de Reports)
- **CSVs exportados a mano** desde el portal — se arrastran al dashboard y se renombran/normalizan solos

**De un vistazo:**

- 🔌 Cliente propio de la API Vision One (`trendai_api.py`, ~3.100 líneas, solo `urllib` de la stdlib) que cubre **32 endpoints** en 10 categorías, con auto-descubrimiento de módulos contratados y fallback automático cuando un módulo no está disponible.
- 📊 Generador de informes (`informe_crem.py`, ~6.800 líneas) que produce **Word, HTML técnico, HTML ejecutivo y PDF** a partir de los mismos datos — diff de CVEs mes a mes, detección de activos reincidentes, tendencia histórica y un cálculo de riesgo propio (**Riesgo CREM**, 0–100).
- 🛡️ Enriquecimiento automático de **cada CVE** contra NVD, CISA KEV y EPSS, con caché en disco para poder regenerar informes 100% offline.
- 🖥️ Dashboard de escritorio (`crem_dashboard.py`, Flask + PyQt6) con generación de informes, histórico, gestión multi-cliente y subida de CSVs por arrastrar-y-soltar.
- 🗂️ Multi-cliente desde el primer día: cada empresa tiene su propia configuración, inventario de activos, SLAs e histórico, aislados entre sí.

Es una herramienta que uso en producción para generar informes mensuales reales de clientes — no es una demo ni un prototipo. Este repositorio es una versión sanitizada: nombres de cliente, inventarios de infraestructura real y credenciales se han sustituido por ejemplos genéricos antes de publicarla (ver [Aviso](#aviso) al final).

---

## Índice

1. [Requisitos e instalación](#1-requisitos-e-instalación)
2. [Estructura de carpetas](#2-estructura-de-carpetas)
3. [Puesta en marcha rápida](#3-puesta-en-marcha-rápida)
4. [Configuración inicial](#4-configuración-inicial)
5. [`main.py` — punto de entrada único](#5-mainpy--punto-de-entrada-único)
6. [Fuentes de datos: API vs. CSVs manuales](#6-fuentes-de-datos-api-vs-csvs-manuales)
7. [Referencia de configuraciones (`config.json`)](#7-referencia-de-configuraciones-configjson)
8. [Flags de línea de comandos de cada script](#8-flags-de-línea-de-comandos-de-cada-script)
9. [Módulos del sistema](#9-módulos-del-sistema)
10. [API Vision One — Endpoints cubiertos](#10-api-vision-one--endpoints-cubiertos)
11. [CSVs y archivado histórico](#11-csvs-y-archivado-histórico)
12. [Enriquecimiento de CVEs (NVD · KEV · EPSS)](#12-enriquecimiento-de-cves-nvd--kev--epss)
13. [Archivos que genera el informe](#13-archivos-que-genera-el-informe)
14. [Informe HTML](#14-informe-html)
15. [Riesgo CREM — cálculo automático vs. manual](#15-riesgo-crem--cálculo-automático-vs-manual)
16. [Dashboard de escritorio (`crem_dashboard.py`)](#16-dashboard-de-escritorio-crem_dashboardpy)
17. [Test de API (`herramientas/test_api.py`)](#17-test-de-api-herramientastest_apipy)
18. [Solución de problemas](#18-solución-de-problemas)
19. [Desarrollo: pruebas y cambios en el código](#19-desarrollo-pruebas-y-cambios-en-el-código)
20. [Notas técnicas](#notas-técnicas)
21. [Aviso](#aviso)
22. [Licencia](#licencia)

---

## 1. Requisitos e instalación

```
Python 3.12+
```

> Los f-strings del generador de HTML usan sintaxis (PEP 701) que solo el parser de Python 3.12+ acepta — en 3.10/3.11 `informe_crem.py` falla al importar con un `SyntaxError`.

Todas las dependencias están en `requirements.txt`:

```bash
pip install -r requirements.txt
```

| Paquete | Uso |
|---|---|
| `pandas` | Procesado de CSVs / dataframes |
| `python-docx`, `lxml` | Generación del informe Word |
| `openpyxl` | Excels de revisión (`--excels`) |
| `rich` | Interfaz de consola (menús, tablas, progreso) |
| `reportlab` | Exportación a PDF |
| `flask` | Backend del dashboard |
| `PyQt6` + `PyQt6-WebEngine` | Ventana nativa de escritorio del dashboard (recomendado en Windows) |
| `pywebview` *(opcional, comentado en requirements.txt)* | Alternativa ligera a PyQt6 si no quieres instalarlo |

No se requieren librerías de terceros para la extracción de la API ni para el enriquecimiento de CVEs — `trendai_api.py` y `cve_enrich.py` usan únicamente `urllib` de la stdlib. Tanto `informe_crem.py` como `trendai_api.py` auto-instalan sus dependencias mínimas al arrancar si detectan que faltan.

---

## 2. Estructura de carpetas

```
Generador Informes/
│
├── main.py                  # ★ Punto de entrada único (menú dashboard/terminal)
├── crem_dashboard.py        # Dashboard de escritorio (Flask + ventana nativa) — v4.1
├── informe_crem.py          # Generador de informes (Word + HTML técnico/ejecutivo + PDF) — v4.0
├── trendai_api.py           # Cliente Vision One API
├── cve_enrich.py            # Motor de enriquecimiento de CVEs (NVD, KEV, EPSS)
├── requirements.txt         # Listado de dependencias de Python
├── .env                     # (opcional) .env global del proyecto — p.ej. NVD_API_KEY
├── .env.template            # Plantilla comentada del .env de empresa
│
├── CLIENTES/                # Configuración e informes históricos de clientes
│   ├── ACME/
│   │   ├── .env             # API key + región de ESTE cliente
│   │   ├── config.json      # Inventario, SLAs y contacto
│   │   ├── CSV/             # CSVs del mes en curso (se vacía al archivar)
│   │   ├── INFORMES/        # Informes definitivos + histórico de CSVs
│   │   └── PRUEBAS/         # Informes en modo prueba (no tocan el histórico)
│   ├── CONTOSO/
│   └── NORTHWIND/
│
├── cve_cache/               # Caché de enriquecimiento de CVEs
│   ├── cve_cache.json       # Datos NVD/EPSS ya descargados (permite trabajar offline)
│   └── kev_catalog.json     # Catálogo CISA KEV (se refresca cada 24 h)
│
├── herramientas/            # Utilidades de diagnóstico, depuración y guías de mapeo
│   ├── test_api.py          # Test de conectividad y cobertura de la API
│   ├── debug_api.py         # Depuración de llamadas a la API
│   ├── debug_params.py      # Depuración de fechas y parámetros
│   ├── security_frameworks.py # Mapeo de hallazgos a frameworks (CIS, NIST, ENS…)
│   ├── opciones_config.txt  # Explicación de las opciones en config.json
│   └── mapeo_csv.txt        # Mapeo de nombres de ficheros CSV originales
│
└── plantilla/
    ├── Revisión_CREM_MES_AÑO.docx   # Plantilla Word base del informe técnico
    └── plantilla csv sin datos/     # CSVs vacíos con las cabeceras correctas
```

---

## 3. Puesta en marcha rápida

```bash
pip install -r requirements.txt
python main.py            # → opción 1 (Dashboard)
```

En el dashboard:

1. **Empresa** → selecciona el cliente (o créalo escribiendo el nombre y pulsando *Crear*).
2. **Fuente de datos** →
   - *API Vision One*: configura antes la key en **Conexión API**.
   - *CSVs descargados*: ve a **Estado CSVs**, elige la empresa y arrastra los CSV exportados del portal — se renombran y normalizan solos.
3. **Plantilla** → `Ambas` (técnica + ejecutiva).
4. **Período** → mes del informe.
5. **Generar informe** → los archivos aparecen en `CLIENTES/[EMPRESA]/INFORMES/Mes_Año/`.

---

## 4. Configuración inicial

*(Solo necesario si vas a usar la fuente de datos por API. Con CSVs manuales puedes saltarte 4.1 y 4.2.)*

### 4.1 Crear la API key en Vision One

1. Entra en **Vision One Portal** → `Administration` → `User Roles` → **+ Add role**
   - `Can be assigned to API keys` = **Yes**
   - Permisos: `Dashboards & Reports → Reports → Configure and download + View`
     (cubre attack-surface devices, vulnerable devices, high-risk devices, IPs públicas y asset groups)
   - Añade también `Third-party auditing (API only)` — necesario para el endpoint `securityPosture`
   - `Data and app assets`: define el scope de activos necesario
2. `Administration` → `API Keys` → crea la clave con ese rol y comprueba que el toggle **Status** esté activado
3. Copia el token (solo visible una vez)

> El rol **Operator** *no* incluye permiso de Reports y devuelve 403 en los módulos CREM. Si prefieres no crear rol, `Master Administrator` da cobertura total.

**Permisos mínimos por módulo:**

| Módulo Vision One | Permiso API Key |
|---|---|
| Workbench / XDR Alerts | Threat Investigation |
| CVEs / ASM | Attack Surface Risk Management |
| Endpoint Security | Endpoint Security |
| Email Security | Cloud Email Gateway |
| Cloud Apps | Cloud Access Security |
| Identity / IAM | Identity & Access Management |
| Audit Logs | Audit Log Management |
| Response Tasks | Response Management |
| Container Security | Container Security |
| Cloud Posture (Conformity) | Cloud Posture Management |

### 4.2 Crear el archivo `.env`

Copia `.env.template` a `CLIENTES/[empresa]/.env` y rellénalo (o hazlo desde el dashboard en **Conexión API**, que lo escribe por ti):

```bash
# CLIENTES/[empresa]/.env

TRENDAI_API_KEY=eyJ0eXAi...       # token Vision One
TRENDAI_REGION=EU                  # EU | US | AU | IN | SG | JP
TRENDAI_DISCOVERED_BY_FILTER=      # (opcional) filtro TMV1 para acotar el origen de datos
```

**Regiones disponibles:**

| Código | Servidor | Ubicación |
|--------|----------|-----------|
| `EU` | `api.eu.xdr.trendmicro.com` | Europa |
| `US` | `api.xdr.trendmicro.com` | Estados Unidos |
| `AU` | `api.au.xdr.trendmicro.com` | Australia |
| `IN` | `api.in.xdr.trendmicro.com` | India |
| `SG` | `api.sg.xdr.trendmicro.com` | Singapur |
| `JP` | `api.jp.xdr.trendmicro.com` | Japón |

### 4.3 `.env` global del proyecto (opcional)

El `.env` de la raíz sirve para valores comunes a todos los clientes — hoy en día, la clave de NVD:

```bash
NVD_API_KEY=xxxxxxxx-xxxx-...   # gratuita, sube el rate-limit de 5 a 50 req/30s
```

Ver [sección 12](#12-enriquecimiento-de-cves-nvd--kev--epss).

### 4.4 Crear el `config.json`

Se crea automáticamente con valores por defecto la primera vez que se ejecuta `informe_crem.py` sobre una empresa nueva (o al pulsar *Crear* en el dashboard), pero puedes crearlo/editarlo a mano — ver el detalle completo en la [sección 7](#7-referencia-de-configuraciones-configjson).

```json
{
  "empresa": "ACME",
  "contacto_tecnico": "admin@empresa.com",
  "sla_critico_dias": 1,
  "sla_alto_dias": 3,
  "sla_medio_dias": 7,
  "meses_reincidente": 2,
  "abrir_html_al_terminar": false,
  "inventario_activos": {
    "_comentario": "Criticidad: MUY CRITICO | CRITICO | NO CRITICO | (vacío = sin catalogar)",
    "servidor-ERP": {
      "descripcion": "ERP Principal",
      "criticidad": "MUY CRITICO"
    },
    "PC-Recepcion": {
      "descripcion": "PC Recepción",
      "criticidad": "NO CRITICO"
    }
  }
}
```

---

## 5. `main.py` — punto de entrada único

`main.py` (v2.0) centraliza el acceso a la herramienta con un menú Rich en consola. Es la forma recomendada de arrancar; los scripts individuales siguen funcionando de forma independiente para uso avanzado/scripted (cron, CI, etc.).

```bash
python main.py
```

```
  TREND AI   Generador de Informes CREM
  v2.0 · punto de entrada centralizado

  1  📊  Dashboard (Principal)   → crem_dashboard.py
  2  🖥️  Versión Terminal        → informe_crem.py
  0      Salir
```

- **Dashboard** (opción por defecto, Enter) — interfaz gráfica completa; ver [sección 16](#16-dashboard-de-escritorio-crem_dashboardpy).
- **Versión Terminal** — lanza `informe_crem.py` en modo interactivo: pregunta período, empresa, alertas XDR manuales y Riesgo CREM por consola.

Atajos para saltarse el menú:

```bash
python main.py --dashboard   # va directo al dashboard
python main.py --terminal    # va directo a la versión de consola
```

---

## 6. Fuentes de datos: API vs. CSVs manuales

El generador no depende de la API: funciona igual de bien con los CSV exportados a mano desde el portal. En el dashboard se elige en la tarjeta **Fuente de datos**.

### 6.1 Fuente *API Vision One*

Descarga los datos del mes con `trendai_api.py` y los deja en `CLIENTES/[empresa]/CSV/` justo antes de generar. Requiere `.env` con API key ([sección 4](#4-configuración-inicial)).

### 6.2 Fuente *CSVs descargados* — exportación manual desde el portal

En el portal del cliente: **Cyber Risk Exposure Management → Continuous Risk Management → Threat and Exposure Management**. Para cada módulo:

1. Fija `Status` = **NEW** (viene así por defecto) y `Event Risk Level` = **ALL**
2. Pulsa **Export** (lateral derecho) y espera a que termine la descarga

En **Vulnerabilities** no hay `Event Risk Level` sino `Group By` — de ahí se descargan **dos** CSV: uno con `Group By = CVE Event` y otro con `Group By = Asset`.

**Mapeo de exportaciones a nombre estándar:**

| # | Módulo del portal | Filtro | Nombre estándar |
|---|---|---|---|
| 1 | Highly Exploitable CVE's – Internal Assets | Group By = **CVE Event** | `cve-events.csv` |
| 2 | Highly Exploitable CVE's – Internal Assets | Group By = **Asset** | `cve-assets.csv` |
| 3 | Account Compromise Indicators | ALL | `account-compromise.csv` |
| 4 | Anomaly Detections | ALL | `anomaly-detections.csv` |
| 5 | Cloud App Activity Risk Events | ALL | `cloud-app.csv` |
| 6 | System Configuration Risk Events | ALL | `sys-conf.csv` |
| 7 | *XDR* | — | **No se puede exportar** — se introduce a mano en el paso interactivo |
| 8 | Threat Detections | ALL | `threat-detections.csv` |
| 9 | Security Configuration Risk Events | ALL | `security-conf.csv` |
| 10 | Predictive Analytics | ALL | `predictive-analytics.csv` *(opcional)* |

**No hace falta renombrarlos a mano.** Al subirlos por el dashboard (**Estado CSVs** → zona de arrastrar), `normalizar_csvs()` detecta el tipo por el nombre en bruto (`Account Compromise Indicators_20260723095557.csv`) y, cuando el nombre no basta —los dos CSV de vulnerabilidades se llaman igual—, por las cabeceras del archivo:

- cabecera con `Vulnerability ID` / `CVE impact score` → `cve-events.csv`
- cabecera con `Device name` / `Total CVEs` → `cve-assets.csv`

Si subes dos veces el mismo tipo, gana el archivo más reciente. Después de subirlos, revisa la lista de **Estado CSVs**: los 8 requeridos deben aparecer con badge `OK`.

> Si un módulo no tiene datos ese mes o el portal no deja exportarlo, copia el CSV vacío equivalente desde `plantilla/plantilla csv sin datos/` a la carpeta `CSV/` de la empresa — tiene las cabeceras correctas y el informe simplemente mostrará esa sección a cero.

---

## 7. Referencia de configuraciones (`config.json`)

Archivo por empresa en `CLIENTES/[empresa]/config.json`. Todas las claves son opcionales — si faltan se usan los valores por defecto indicados. Editable desde el dashboard (**Empresa**, **Inventario activos**, **SLAs y módulos**).

| Clave | Tipo | Por defecto | Efecto |
|---|---|---|---|
| `empresa` | string | `""` (nombre de la carpeta) | Nombre mostrado en cabeceras del informe |
| `contacto_tecnico` | string | `""` | Contacto mostrado en el informe ejecutivo |
| `sla_critico_dias` | int | `1` | Días de SLA objetivo para hallazgos Críticos (columna SLA del Plan de Actuación ejecutivo) |
| `sla_alto_dias` | int | `3` | Días de SLA objetivo para hallazgos Altos |
| `sla_medio_dias` | int | `7` | Días de SLA objetivo para el resto |
| `meses_reincidente` | int | `2` | Nº de meses consecutivos que un CVE debe seguir sin resolver para marcarse como "reincidente" |
| `notas_adicionales` | string | `""` | Texto libre incluido en el informe ejecutivo |
| `abrir_html_al_terminar` | bool | `false` | Si es `true`, abre automáticamente el HTML generado al finalizar |
| `modulos_ignorar` | list[string] | `[]` | Reservado para excluir módulos del informe (campo de esquema; no filtra activamente todavía) |
| `nvd_api_key` | string | `""` | Clave NVD por empresa (compatibilidad — se prefiere el `.env`) |
| `inventario_activos` | dict | `{}` | Mapa `{nombre_o_patrón: {descripcion, criticidad}}` — ver detalle abajo |

### `inventario_activos`

Cada clave es un nombre (o fragmento de nombre — el match es por subcadena, insensible a mayúsculas) de dispositivo/activo tal como aparece en los CSVs de Vision One (`Device name`, `Asset`, etc.). El valor es:

```json
"NombreOFragmento": {
  "descripcion": "Texto libre — para qué sirve el activo",
  "criticidad": "MUY CRITICO"
}
```

`criticidad` acepta exactamente uno de estos 4 valores (usados en badges, filtros, ranking de Vista CREM y en el resumen de exposición):

| Valor | Icono | Significado |
|---|---|---|
| `MUY CRITICO` | 💀 | Activo de máximo impacto para el negocio (ERP, BBDD producción, controladores de dominio…) |
| `CRITICO` | 🔴 | Activo importante pero no de máximo impacto |
| `NO CRITICO` | 🟢 | Activo de bajo impacto (PCs de usuario, equipos de pruebas…) |
| `""` (vacío) o clave ausente | ⬜ | Sin catalogar — se muestra explícitamente como tal en el informe |

Este inventario alimenta tanto los badges de criticidad en las tablas como el **ranking de Vista CREM** y la **fila-resumen de exposición por criticidad** (ver secciones 14 y 15).

---

## 8. Flags de línea de comandos de cada script

Todos los scripts se pueden invocar directamente (sin pasar por `main.py`) para uso avanzado, cron, CI, etc.

### `informe_crem.py`

```bash
python informe_crem.py [opciones]
```

| Flag | Tipo | Descripción |
|---|---|---|
| `--mes "MES_ANO"` | string | Período del informe, ej. `"Mayo 2026"`. Si se omite, pregunta por consola (o usa el mes anterior con `--no-input`) |
| `--empresa NOMBRE` | string | Nombre de la carpeta de empresa en `CLIENTES/`. Si se omite, muestra un menú de selección |
| `--template {tecnico,ejecutivo,ambos}` | choice | Tipo de informe. `tecnico` = Word + HTML completo; `ejecutivo` = HTML ligero; **por defecto `ambos`** |
| `--no-input` | flag | Modo no interactivo (cron/scheduler, y lo que usa el dashboard). Omite todos los prompts |
| `--riesgo-crem SCORE` | float | Fija manualmente el **Riesgo CREM** (0-100, admite decimales) en vez del calculado — ver [sección 15](#15-riesgo-crem--cálculo-automático-vs-manual) |
| `--api-riesgo` | flag | Consulta el **Cyber Risk Index** real a la API de Vision One y lo usa como Riesgo CREM |
| `--solo-word` | flag | Regenera Word/HTML reutilizando la caché `.pkl` sin releer los CSVs (rápido para iterar sobre plantilla/estilos) |
| `--excels` | flag | Genera además un Excel de revisión por módulo |
| `--conservar-csv` | flag | Copia los CSV al histórico en vez de moverlos (la carpeta `CSV/` no se vacía) |
| `--prueba` | flag | Genera en `[EMPRESA]/PRUEBAS/` sin archivar CSVs, sin persistir el Riesgo CREM ni tocar el histórico |
| `--enriquecer-cve` | flag | *(Obsoleto)* El enriquecimiento de CVEs se hace siempre; se mantiene por compatibilidad |

### `trendai_api.py`

```bash
python trendai_api.py --empresa NOMBRE --mes "MES_ANO" [opciones]
```

| Flag | Tipo | Descripción |
|---|---|---|
| `--empresa NOMBRE` | string, **requerido** | Carpeta de empresa donde está el `.env` y se guardará `CSV/` |
| `--mes "MES_ANO"` | string | Período a extraer, ej. `"Mayo 2026"` |
| `--env-file RUTA` | string | Ruta explícita a un `.env` (por defecto `CLIENTES/[empresa]/.env`) |
| `--test` | flag | Solo probar la conexión con la API, sin extraer datos |
| `--discover` | flag | Solo descubrir qué módulos tiene contratados el tenant, sin descargar datos |
| `--only-risk` | flag | Solo obtener el Cyber Risk Index desde la API |
| `--verbose` | flag | Log detallado de cada petición HTTP |

### `herramientas/test_api.py`

```bash
python herramientas/test_api.py [opciones]
```

| Flag | Tipo | Descripción |
|---|---|---|
| `--empresa NOMBRE` | string | Por defecto `ACME`. Busca `CLIENTES/[empresa]/.env` |
| `--env RUTA` | string | Ruta explícita al `.env`, alternativa a `--empresa` |
| `--mes "MES_ANO"` | string | Por defecto el mes actual |
| `--quick` | flag | Solo descubrimiento + test de conexión, sin descargar datos de muestra |
| `--probe-cve` | flag | Prueba exhaustiva de rutas CVE alternativas (diagnóstico fino de ASM) |
| `--probe-all` | flag | Prueba rutas alternativas para todos los módulos que fallan |
| `--dump-endpoint` | flag | Vuelca todos los campos del primer registro de cada endpoint |
| `--json RUTA` | string | Guarda los resultados del diagnóstico en un JSON |

### `main.py`

| Flag | Descripción |
|---|---|
| `--dashboard` | Lanza directamente el dashboard |
| `--terminal` | Lanza directamente `informe_crem.py` en modo interactivo |

---

## 9. Módulos del sistema

### `trendai_api.py` — Cliente API

- **Descubrimiento automático de módulos**: detecta qué módulos tiene contratados el cliente (paralelo, 6 workers)
- **Extracción máxima**: múltiples fuentes de datos con estrategias de fallback
- **Normalización**: transforma respuestas crudas de API en filas de CSV homogéneas
- **Deduplicación**: por ID de alerta/CVE/activo
- **Guardado**: CSVs + `.api_meta.json` con estadísticas de la extracción

### `informe_crem.py` — Generador de informes (v4.0)

- Lee los CSVs de `CLIENTES/[empresa]/CSV/` (normalizando antes los nombres en bruto)
- **Enriquece todos los CVEs** con NVD + CISA KEV + EPSS ([sección 12](#12-enriquecimiento-de-cves-nvd--kev--epss))
- Calcula el **Riesgo CREM** (0–100), con opción de override manual o vía API ([sección 15](#15-riesgo-crem--cálculo-automático-vs-manual))
- Identifica **TOP 3 incidentes críticos** (Acciones Prioritarias)
- Construye los **5 paneles de Vista CREM** (Devices, Internet, Accounts, Applications, Cloud), rankeados por score + criticidad de inventario
- Calcula **diff de CVEs** (nuevos / resueltos / persistentes vs. mes anterior)
- Detecta **CVEs reincidentes** (sin resolver N meses, según `meses_reincidente`)
- Calcula **tendencia histórica** leyendo los meses archivados
- Genera **HTML técnico y/o ejecutivo**, **Word** y **PDF**
- **Archiva automáticamente** los CSV del mes en el histórico de la empresa ([sección 11](#11-csvs-y-archivado-histórico))

### `cve_enrich.py` — Enriquecimiento de CVEs

Consulta NVD 2.0, CISA KEV y EPSS con caché a disco. Ver [sección 12](#12-enriquecimiento-de-cves-nvd--kev--epss).

### `crem_dashboard.py` — Dashboard de escritorio (v4.1)

Interfaz Flask servida en un puerto local libre, mostrada en una **ventana nativa** — ver [sección 16](#16-dashboard-de-escritorio-crem_dashboardpy).

### `herramientas/test_api.py` — Test de API

Diagnostica la conectividad y cobertura de datos de la API key, diferenciando:
- `[OK]` — módulo accesible con datos
- `[403]` — módulo existe pero la API key no tiene permiso
- `[404]` — módulo no contratado en el tenant

---

## 10. API Vision One — Endpoints cubiertos

El sistema cubre **32 endpoints** organizados en 10 categorías:

### Core XDR
| Endpoint | Descripción | CSV destino |
|----------|-------------|-------------|
| `GET /v3.0/workbench/alerts` | Alertas XDR correlacionadas (amenazas, anomalías, cuentas) | threat / anomaly / account |
| `GET /v3.0/workbench/detections` | Técnicas ATT&CK observadas (OAT) | sys-conf |
| `POST /v3.0/search/detections` | Búsqueda en logs históricos | CVEs (fallback) / network |
| `GET /v3.0/xdr/impactedEntities` | Entidades afectadas por alertas XDR | threat |

### Endpoint Security
| Endpoint | Descripción | CSV destino |
|----------|-------------|-------------|
| `GET /v3.0/endpointSecurity/endpoints` | Inventario completo de endpoints | enriquecimiento CVEs |
| `GET /v3.0/eiqs/endpoints` | Inventario EIQS (alternativo) | enriquecimiento CVEs |
| `GET /v3.0/endpointSecurity/agentHealth` | Agentes desconectados / desactualizados | sys-conf |
| `GET /v3.0/endpointSecurity/tasks` | Tareas pendientes en endpoints | sys-conf |
| `GET /v3.0/endpointSecurity/isolatedEndpoints` | Endpoints actualmente en cuarentena | sys-conf |

### CREM / ASRM — Attack Surface Risk Management
| Endpoint | Descripción | CSV destino |
|----------|-------------|-------------|
| `GET /v3.0/asrm/vulnerableDevices` | Todos los CVEs activos (`cveDetectionStatus=any` obligatorio) | cve-events / cve-assets |
| `GET /v3.0/asrm/attackSurfaceDevices` | Activos con risk score agregado | enriquecimiento |
| `GET /v3.0/asrm/securityPosture` | Evaluaciones de postura de seguridad | security-conf / sys-conf |
| `GET /v3.0/asrm/highRiskDevices` | Dispositivos con mayor exposición de riesgo | enriquecimiento cve-assets |
| `GET /v3.0/asrm/attackSurfacePublicIpAddresses` | Activos expuestos directamente a internet (IPs públicas) | enriquecimiento cve-assets |
| `GET /v3.0/asrm/assetGroups` | Grupos de activos definidos en CREM | enriquecimiento cve-assets |
| `GET /v3.0/asm/riskScore` | Puntuación de riesgo global del tenant (score real del portal) | meta / risk gauge |
| `GET /v3.0/asm/attackPaths` | Rutas de ataque simuladas (predictivo) | predictive-analytics |

### Cloud & Email
| Endpoint | Descripción | CSV destino |
|----------|-------------|-------------|
| `GET /v3.0/cloudAccess/riskAccessEvents` | Accesos cloud de riesgo (SaaS) | cloud-app |
| `GET /v3.0/emailSecurity/alerts` | Phishing, malware, BEC detectados | threat |
| `GET /v3.0/emailSecurity/quarantineMessages` | Mensajes bloqueados en cuarentena | threat |
| `GET /v3.0/cloudFileSecurity/events` | Archivos maliciosos en almacenamiento cloud | threat |
| `GET /v3.0/cloudPosture/assessmentSummaries` | Evaluaciones Cloud Posture (Conformity) | sys-conf |

### Threat Intelligence
| Endpoint | Descripción | CSV destino |
|----------|-------------|-------------|
| `GET /v3.0/sandbox/submissionList` | Análisis de malware en Sandbox | threat |
| `GET /v3.0/threatintel/suspiciousObjects` | IOCs activos (IP, dominio, URL, hash) | sys-conf |
| `GET /v3.0/threatintel/intelligenceReports` | Informes de inteligencia de amenazas | sys-conf |
| `GET /v3.0/threatintel/stixSweepingTasks` | Búsqueda proactiva de IOCs STIX | sys-conf |

### Identity & IAM
| Endpoint | Descripción | CSV destino |
|----------|-------------|-------------|
| `GET /v3.0/iam/accountsRiskInsight` | Cuentas con riesgo elevado | account-compromise |
| `GET /v3.0/iam/accounts` | Inventario de cuentas IAM | account-compromise |
| `GET /v3.0/riskInsights/riskScore` | Risk score global por identidad | meta |

### Network Security
| Endpoint | Descripción | CSV destino |
|----------|-------------|-------------|
| `GET /v3.0/networkSecurity/sensors` | Sensores de red desplegados | meta (discovery) |
| `GET /v3.0/networkSecurity/policies` | Políticas de seguridad de red | meta (discovery) |

### Container Security
| Endpoint | Descripción | CSV destino |
|----------|-------------|-------------|
| `GET /v3.0/containerSecurity/alerts` | Alertas de contenedores Kubernetes/Docker | threat |

### Audit & Response
| Endpoint | Descripción | CSV destino |
|----------|-------------|-------------|
| `GET /v3.0/auditLogs` | Cambios de configuración y accesos admin | sys-conf |
| `GET /v3.0/response/tasks` | Tareas de respuesta ejecutadas | threat |

---

## 11. CSVs y archivado histórico

Vengan de la API o de una exportación manual, todos se guardan en `CLIENTES/[empresa]/CSV/`:

| Archivo | Contenido | Columnas clave | Requerido |
|---------|-----------|----------------|:---:|
| `threat-detections.csv` | Amenazas activas: malware, ataques, BEC, sandbox, red, container, cloud file | Risk event, Asset, Event risk level | ✔ |
| `anomaly-detections.csv` | Comportamientos anómalos detectados por ML | Risk event, Asset, Event risk level | ✔ |
| `account-compromise.csv` | Cuentas comprometidas o en riesgo | Risk event, Impact scope, Event risk level | ✔ |
| `cve-events.csv` | CVEs individuales con CVSS score y exploit | Vulnerability ID, CVE impact score, Global exploit potential | ✔ |
| `cve-assets.csv` | Activos con CVEs — resumen por dispositivo | Device name, CVE event risk score, Total CVEs | ✔ |
| `security-conf.csv` | Problemas de configuración de seguridad | Risk event, Asset, Event risk level | ✔ |
| `sys-conf.csv` | Problemas de sistema, IOCs, audit, agentes, cloud posture | Risk event, Asset, Event risk level | ✔ |
| `cloud-app.csv` | Eventos de apps cloud en riesgo | Risk event, Asset, Event risk level, Detail info | ✔ |
| `predictive-analytics.csv` | Rutas de ataque simuladas (ASM) | Entry assets, Target assets, Attack path risk score | — |

### `.api_meta.json`

Solo se genera en extracciones por API:

```json
{
  "empresa": "ACME",
  "mes": "Junio 2026",
  "extracted_at": "2026-06-11T10:00:00",
  "region": "https://api.eu.xdr.trendmicro.com",
  "modules": { "workbench": true, "asm_vuln": false },
  "module_status": { "workbench": 403, "asm_vuln": 404 },
  "src_stats": { "workbench_alerts": 45, "endpoints": 100 },
  "rows": { "threat-detections.csv": 23, "cve-events.csv": 156 },
  "total_rows": 412,
  "risk_score_api": 67,
  "internet_exposed": 3,
  "warnings": []
}
```

### Archivado automático al histórico

Al terminar de generar el informe, `informe_crem.py` **mueve** los CSV (y el `.api_meta.json`) de `CLIENTES/[empresa]/CSV/` a `CLIENTES/[empresa]/INFORMES/CSV/csv-{mes}-{año}/`, dejando `CSV/` vacía y lista para el mes siguiente. Es el comportamiento esperado: **no es un error que la carpeta `CSV/` quede vacía después de generar.**

- Con `--conservar-csv` se copian en vez de moverse.
- Con `--prueba` no se archiva nada.
- Esa carpeta histórica es la que alimenta el **diff de CVEs**, la **tendencia mensual** y los **CVEs reincidentes** de los meses siguientes.
- Junto a los CSVs se guarda `risk_score.json` con el Riesgo CREM final del mes; si regeneras el mismo mes, los CSVs no se duplican pero el `risk_score.json` sí se actualiza.

---

## 12. Enriquecimiento de CVEs (NVD · KEV · EPSS)

Cada CVE del informe se enriquece **siempre** (no hay que activar nada) con tres fuentes gratuitas:

| Fuente | Qué aporta |
|---|---|
| **NVD 2.0** (NIST) | Versión que corrige el fallo, CVSS, CWE, enlaces al parche → texto de *solución* en español |
| **CISA KEV** | Si el CVE se está explotando activamente + fecha límite de remediación |
| **EPSS** (FIRST.org) | Probabilidad de explotación en los próximos 30 días (0–1) |

- **Caché en `cve_cache/`**: los CVE no cambian, así que solo se descargan los que faltan. Con la caché caliente el informe se regenera **offline**.
- **Rate-limit de NVD**: 5 peticiones/30 s sin clave (≈6,5 s por CVE nuevo) o 50/30 s con clave gratuita (≈0,7 s). Si el cliente tiene muchos CVEs nuevos, el primer informe puede tardar bastante — es normal.
- La clave NVD se resuelve en este orden: variable de entorno `NVD_API_KEY` → `.env` global del proyecto → `.env` de la empresa → `nvd_api_key` en `config.json`.
- El catálogo KEV se refresca cada 24 h en una sola descarga.

---

## 13. Archivos que genera el informe

En `CLIENTES/[EMPRESA]/INFORMES/Mes_Año/` (o `PRUEBAS/Mes_Año/` con `--prueba`):

| Archivo | Plantilla | Contenido |
|---|---|---|
| `Revisión_CREM_Mes_Año.docx` | técnica / ambas | Informe Word a partir de `plantilla/Revisión_CREM_MES_AÑO.docx` |
| `Revisión_CREM_Mes_Año.html` | técnica / ambas | Informe interactivo completo (tema oscuro) |
| `Revisión_CREM_Mes_Año_ejecutivo.html` | ejecutiva / ambas | Informe ejecutivo (tema claro, lenguaje de negocio) |
| `Revisión_CREM_Mes_Año*.pdf` | — | Conversión del HTML (botón *Exportar PDF* del histórico) |
| `log_Mes_Año_AAAAMMDD_HHMMSS.txt` | siempre | Log de la ejecución — útil para diagnosticar |
| `excels/*.xlsx` | con `--excels` | Un Excel de revisión por módulo |

El HTML técnico es un único archivo autocontenido (los gráficos son SVG en línea), así que puede pesar decenas de MB pero se puede enviar tal cual al cliente.

---

## 14. Informe HTML

El informe interactivo (plantillas `tecnico` y `ejecutivo`) es **responsive**: en escritorio muestra sidebar de navegación fija; en tablet/móvil (< 900px) el sidebar pasa a ser un panel deslizante (drawer) accesible con el botón ☰ de la cabecera, y las tablas anchas scrollean horizontalmente dentro de su propio contenedor sin romper el layout de la página.

### Header
- **Risk Gauge (Riesgo CREM)**: puntuación 0–100 (o el valor manual fijado, con 1 decimal si aplica) con nivel (Crítico / Alto / Medio / Bajo) y tendencia vs. mes anterior
- KPIs: total eventos, CVEs nuevos, CVEs resueltos, activos en riesgo, alertas XDR, CVEs reincidentes

### Vista CREM (5 dimensiones)

Cada panel muestra el TOP 3 de activos/eventos de mayor riesgo de esa dimensión. Encima de los 5 paneles hay una **fila-resumen** con el número de activos con CVE Alto/Crítico agrupados por criticidad de inventario (💀 Muy Crítico · 🔴 Crítico · 🟢 No Crítico · ⬜ Sin catalogar), para tener contexto de exposición antes de entrar al detalle.

| Dimensión | TOP 3 muestra | Criterio de ranking |
|-----------|---------------|---------------------|
| Dispositivos | Activos con mayor CVE risk score | Score numérico + bonus por criticidad de inventario (Muy Crítico +15, Crítico +8) — el score mostrado es siempre el real, el bonus solo afecta el orden |
| Internet / Expuesto | Activos con IP pública o marcados como internet-facing | Igual que Dispositivos: score + bonus de criticidad |
| Cuentas | Cuentas con riesgo más alto | Nivel de evento (Critical > High) |
| Aplicaciones | OS/Apps con más CVEs críticos | Max CVSS score |
| Cloud Assets | Apps cloud con mayor riesgo | Nivel de evento |

Cada elemento de los paneles Dispositivos/Internet muestra su chip de criticidad — si el activo no está en el `inventario_activos` de `config.json`, se muestra explícitamente como **⬜ Sin catalogar** en vez de ocultarse.

### Resumen Ejecutivo
- **Acciones Prioritarias**: TOP 3 incidentes Critical/High de Workbench con link directo al portal
- Diff de CVEs (nuevos / resueltos / persistentes vs. mes anterior)
- Gráficos: distribución de severidad (donut) + eventos por módulo (barras)
- Tabla de módulos con totales

### Secciones detalladas
CVE Eventos · CVE Activos · Config. Sistema · Config. Seguridad · Amenazas · Anomalías · Cloud Apps · Cuentas · XDR · Reincidentes · Tendencia histórica · Plan de Actuación

### Funcionalidades
- Búsqueda en tiempo real en todos los datos
- Filtros por severidad e inventario de criticidad
- Exportación CSV por sección
- Detalle ampliado por activo (popup con todos sus CVEs, incluida la solución enriquecida)
- Sidebar de navegación con contadores en tiempo real (drawer deslizante en móvil)

---

## 15. Riesgo CREM — cálculo automático vs. manual

El **Riesgo CREM** que se muestra en el pill de cabecera del informe técnico es, por defecto, una **heurística propia** (`calcular_risk_score`) calculada a partir de: CVEs críticos/altos, amenazas activas, cuentas comprometidas, activos reincidentes y problemas de configuración — **no** es el mismo cálculo que el "Cyber Risk Index / ASM Risk Score" que muestra el portal Vision One, por lo que puede no coincidir (por ejemplo, la heurística puede dar 17 mientras el portal muestra 36.2).

Tres formas de fijar el valor real:

- **Automática desde la API** — `--api-riesgo` (es lo que usa el dashboard cuando dejas el campo manual vacío y hay API key): consulta el Cyber Risk Index real del tenant.
- **Manual en consola**: si no usas `--no-input`, al generar el informe se te pregunta:
  ```
  Riesgo CREM
  Score calculado automáticamente: 17
  Si el portal Vision One muestra un valor distinto, introdúcelo aquí (ej: 36.2).
  Enter = mantener el valor automático.
  → 36.2
  ```
- **Manual por flag / dashboard**: `--riesgo-crem 36.2`, o el campo numérico **Riesgo CREM manual** del dashboard (con el botón *Obtener de API* al lado, que lo rellena consultando Vision One).

El valor final se muestra con 1 decimal cuando no es entero y se persiste en `risk_score.json` dentro de la carpeta histórica del mes. Los meses siguientes usan ese valor real (en vez de una aproximación) para calcular la tendencia (`▲`/`▼`).

---

## 16. Dashboard de escritorio (`crem_dashboard.py`)

```bash
python crem_dashboard.py
# o: python main.py --dashboard
```

El dashboard **no** es un servidor web en un puerto fijo: al arrancar busca un puerto local libre, levanta Flask en un hilo en segundo plano y abre una **ventana nativa de escritorio** apuntando a ese servidor:

1. **PyQt6 + PyQt6-WebEngine** (recomendado, mejor integración en Windows) — si está instalado
2. Si no, intenta **pywebview** como alternativa más ligera
3. Si ninguno está disponible, cae a abrir la URL en el **navegador del sistema**

**Pantallas (sidebar):**

| Sección | Pantalla | Para qué sirve |
|---|---|---|
| Generación | **Generar informe** | Empresa · plantilla (Técnica / Ejecutiva / Ambas) · fuente de datos (API o CSVs) · período · opciones · Riesgo CREM manual. Progreso en vivo por Server-Sent Events |
| Generación | **Histórico** | Todos los informes generados: abrir HTML/Word, exportar a PDF, abrir la carpeta |
| Configuración | **Empresa** | Editar `config.json` completo |
| Configuración | **Inventario activos** | Alta/baja de activos y su criticidad, en tabla |
| Configuración | **SLAs y módulos** | SLAs por severidad y meses de reincidencia |
| Diagnóstico | **Estado CSVs** | Zona de arrastrar y soltar para subir los CSV en bruto (se renombran y normalizan solos) + listado de qué CSVs hay, con filas y tamaño, y aviso de cuáles faltan |
| Diagnóstico | **Conexión API** | API key + región, probar conexión, ver módulos disponibles y lanzar la descarga de datos del mes |
| Diagnóstico | **Acerca de** | Rutas del script y estructura de carpetas |

**Botones de generación** (pie de página):

- **Generar informe** — flujo normal: escribe en `INFORMES/`, archiva los CSVs y actualiza el histórico.
- **Generar prueba** — pensado para escribir en `PRUEBAS/` sin tocar el histórico. ⚠️ Actualmente el dashboard **no** pasa el flag `--prueba` al subproceso, así que genera en `INFORMES/` y luego no encuentra los archivos donde los busca. Hasta que se corrija, para modo prueba usa la terminal: `python informe_crem.py --empresa X --mes "Junio 2026" --prueba`.

---

## 17. Test de API (`herramientas/test_api.py`)

Diagnóstico completo de la API key y cobertura de datos:

```bash
# Modo rápido — solo verifica conexión y descubre módulos (sin descargar datos)
python herramientas/test_api.py --empresa ACME --quick

# Modo completo — descarga muestra de cada módulo disponible
python herramientas/test_api.py --empresa ACME --mes "Junio 2026"

# Guardar resultados en JSON
python herramientas/test_api.py --empresa ACME --json diagnostico.json

# Otra empresa / .env explícito
python herramientas/test_api.py --empresa ACME
python herramientas/test_api.py --env /ruta/al/.env
```

**Interpretación de resultados:**

| Estado | Código | Significado |
|--------|--------|-------------|
| `[OK]` | 200 | Módulo accesible y con datos |
| `[WARN]` | — | Accesible pero respuesta inesperada |
| `[403]` | 403 | Módulo contratado — API key sin permiso |
| `[404]` | 404 | Módulo no contratado en este tenant |
| `[NET]` | 0 | Error de red — revisar región y conectividad |

> Si ves módulos con `[403]`: revisa el rol de la API key ([sección 4.1](#41-crear-la-api-key-en-vision-one)) — el permiso que falta casi siempre es `Dashboards & Reports → Reports`.

---

## 18. Solución de problemas

### "API key inválida" (HTTP 401)
- Verifica que la clave no haya expirado y que el toggle **Status** esté activado
- Comprueba que está copiada completa (sin espacios)

### Módulos con HTTP 403
- La API key existe pero no tiene el rol necesario
- Edita el rol en **Administration → User Roles** y añade `Dashboards & Reports → Reports` + `Third-party auditing (API only)`

### "Sin conexión" (HTTP 0)
- Verifica la región en `.env` — debe coincidir con el portal que usas
- Comprueba la conectividad de red desde el equipo

### CVEs en el portal pero `asm_vuln` como 404
- El portal puede mostrar CVEs a través de Endpoint Security sin el módulo ASM completo
- El sistema tiene fallback automático vía Search API para detectar CVEs sin módulo ASM

### La carpeta `CSV/` está vacía después de generar
- Es lo normal: los CSVs se **mueven** al histórico ([sección 11](#11-csvs-y-archivado-histórico)). Están en `INFORMES/CSV/csv-mes-año/`

### Subí los CSVs pero faltan / están mal clasificados
- Mira **Estado CSVs**: dice exactamente cuáles faltan
- Los dos CSV de vulnerabilidades se distinguen por sus cabeceras, no por el nombre — asegúrate de exportar uno con `Group By = CVE Event` y otro con `Group By = Asset`
- Si un módulo no tiene datos, copia el CSV vacío de `plantilla/plantilla csv sin datos/`

### El informe tarda muchísimo la primera vez
- Es el enriquecimiento de CVEs contra NVD ([sección 12](#12-enriquecimiento-de-cves-nvd--kev--epss)). Configura `NVD_API_KEY` en el `.env` global para ir ~9× más rápido; las siguientes ejecuciones tiran de caché

### El Riesgo CREM no coincide con el portal Vision One
- Es esperado: la heurística interna y el Cyber Risk Index del portal son cálculos distintos — usa `--api-riesgo`, `--riesgo-crem`, el prompt interactivo o el campo del dashboard ([sección 15](#15-riesgo-crem--cálculo-automático-vs-manual))

### Informe vacío o con pocos datos
- Verifica que los CSVs existen en `CLIENTES/[empresa]/CSV/`
- Si usas la API, revisa `.api_meta.json` para ver cuántas filas se extrajeron
- Revisa el `log_*.txt` de la carpeta del informe

### Caracteres raros en el informe
- El informe HTML usa UTF-8; verifica que el navegador lo detecta correctamente

### El dashboard no abre ventana nativa, solo el navegador
- Instala `PyQt6` y `PyQt6-WebEngine` (`pip install -r requirements.txt`); sin ellos cae automáticamente al navegador del sistema

### El informe salió, pero con cifras raras
- Mira el final de la ejecución: si algo se generó incompleto aparece un bloque **AVISOS DE ESTA EJECUCIÓN** con qué falló y qué se perdió. Ese mismo aviso sale dentro del HTML, arriba del todo
- Comprueba el bloque **Procedencia de los CSV de entrada** del log: filas, tamaño, fecha y hash de cada CSV que entró. Si dos ejecuciones del mismo mes dan resultados distintos, ahí se ve si los datos eran los mismos
- Si tienes una prueba de regresión propia con datos de cliente reales, ejecútala: si falla, el problema está en el código, no en los datos

---

## 19. Desarrollo: pruebas y cambios en el código

### Prueba de regresión

En uso interno, este proyecto se apoya en una prueba de regresión
(`tests/test_regresion.py`, no incluida aquí) que reproduce un mes real ya
cerrado de un cliente sobre una **copia temporal** de sus CSV archivados
—nunca toca `CLIENTES/`— y comprueba cifra a cifra el resultado: filas por
módulo, diff de CVEs, comparativa mes a mes, resumen, reincidentes, orden de
la tendencia y Riesgo CREM. Se ha omitido de esta versión pública porque sus
cifras esperadas están calculadas sobre datos reales de cliente que no se
distribuyen aquí.

Si vas a modificar el cálculo, te recomendamos montar tu propia versión de
esta prueba contra un mes tuyo ya cerrado, con las cifras esperadas escritas a
mano: los fallos de este programa no son excepciones, el proceso termina con
✓ y el informe sale con los números mal, y un error así llega al cliente sin
que nadie lo note.

### Añadir un módulo nuevo

Todo módulo (CVE, amenazas, cloud apps…) se declara en **un solo sitio**:
`MODULOS`, en `informe_crem.py`. Una entrada nueva ahí da de alta el módulo en
la carga, el resumen, el gráfico de barras y la comparativa mensual. Nunca
referencies un módulo por su etiqueta en castellano: usa su `id`.

### Cuando algo falle a medias

No uses `warn()` para un fallo que recorta el informe: usa
`degradado(ámbito, detalle, impacto)`. Así aparece en el resumen final de la
ejecución, en el log y dentro del propio HTML, en vez de perderse por la
consola.

### Versiones de las librerías

`requirements.txt` sirve para instalar de cero; `requirements.lock` fija el
entorno exacto con el que se generan los informes que se entregan. Antes de
subir cualquier versión, pasa la regresión: una subida de pandas ya provocó
una vez que los valores vacíos se imprimieran como el texto `nan` dentro del
informe del cliente.

---

## Notas técnicas

- **Sin dependencias de API externas para generar**: con los CSVs ya en disco y la caché de CVEs caliente, el generador funciona 100% offline
- **Caché histórica**: los CSVs de meses anteriores se archivan en `INFORMES/CSV/csv-mes-año/`, usados para tendencias, diff de CVEs y el Riesgo CREM histórico real
- **Caché de ejecución**: `datos/*.pkl` permite regenerar Word/HTML sin releer los CSVs (`--solo-word`)
- **Deduplicación**: las alertas Workbench se deduplican por ID para no contar la misma alerta dos veces aunque aparezca en múltiples estrategias de extracción
- **Fallback automático**: si ASM no está disponible, el sistema busca CVEs vía Search API; si cloudAccess no está, busca eventos cloud en Workbench
- **Rate limiting**: la extracción respeta el header `Retry-After` en respuestas 429 y reintenta con backoff exponencial para errores 5xx
- **Seguridad**: los `.env` contienen credenciales — no subir a git ni compartir por email (ya cubierto por el `.gitignore` del repo)

---

## Aviso

Este es un proyecto **personal e independiente**, no afiliado a, ni respaldado ni certificado por Trend Micro. "Trend Micro" y "Vision One" son marcas de sus respectivos propietarios; este repositorio solo consume su API pública documentada.

Es la versión pública de una herramienta que uso en producción. Antes de publicarla se retiraron por completo: nombres y CSVs de clientes reales, un inventario de infraestructura real que estaba hardcodeado en el código, credenciales (`.env`, API keys) y cualquier informe ya generado. Lo que queda es el motor genérico — cualquier `CLIENTES/[empresa]/` que crees tú se queda en tu máquina y nunca se sube al repo gracias al `.gitignore`.

## Licencia

[MIT](LICENSE) — úsalo, modifícalo y redistribúyelo libremente.

## Autor

Eduardo Olivares
