# CREM: Cybersecurity Risk, Exposure & Management Review

![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-uso%20interno%20real-orange)

### [Versión en Español](README.md) · **[English version](README.en.md)**

Generates the monthly security report from Trend Micro Vision One. It extracts,
normalises and presents every security event in the tenant as interactive,
responsive HTML, plus Word and PDF.

The data can come from two places, and both work equally well:

- The Vision One API, downloading automatically. It needs an API key with
  Reports permissions.
- CSVs exported by hand from the portal. You drag them onto the dashboard and
  they get renamed and normalised on their own.

At a glance:

- A custom Vision One API client (`trendai_api.py`, ~3,100 lines, only `urllib`
  from the stdlib) covering 32 endpoints across 10 categories, with
  auto-discovery of the contracted modules and automatic fallback when a module
  isn't available.
- A report generator (`informe_crem.py`, ~6,800 lines) that produces Word,
  technical HTML, executive HTML and PDF from the same data: month-to-month CVE
  diff, detection of repeat-offender assets, historical trend, and a risk
  calculation of its own, the CREM Risk score (0 to 100).
- Automatic enrichment of every CVE against NVD, CISA KEV and EPSS, with an
  on-disk cache so reports can be regenerated 100% offline.
- A desktop dashboard (`crem_dashboard.py`, Flask + PyQt6) with report
  generation, history, multi-client management and drag-and-drop CSV upload.
- Multi-client from day one: each company has its own configuration, asset
  inventory, SLAs and history, isolated from the rest.

This is a tool I use in production to generate real monthly client reports. It
is not a demo or a prototype. This repository is a sanitised version: client
names, real infrastructure inventories and credentials were replaced with
generic examples before publishing it (see [Notice](#notice) at the end).

---

## Index

1. [Requirements and installation](#1-requirements-and-installation)
2. [Folder structure](#2-folder-structure)
3. [Quick start](#3-quick-start)
4. [Initial configuration](#4-initial-configuration)
5. [`main.py`, the single entry point](#5-mainpy-the-single-entry-point)
6. [Data sources: API vs. manual CSVs](#6-data-sources-api-vs-manual-csvs)
7. [Configuration reference (`config.json`)](#7-configuration-reference-configjson)
8. [Command-line flags for each script](#8-command-line-flags-for-each-script)
9. [System modules](#9-system-modules)
10. [Vision One API endpoints covered](#10-vision-one-api-endpoints-covered)
11. [CSVs and historical archiving](#11-csvs-and-historical-archiving)
12. [CVE enrichment (NVD · KEV · EPSS)](#12-cve-enrichment-nvd--kev--epss)
13. [Files the report generates](#13-files-the-report-generates)
14. [The HTML report](#14-the-html-report)
15. [CREM Risk: automatic vs. manual](#15-crem-risk-automatic-vs-manual)
16. [Desktop dashboard (`crem_dashboard.py`)](#16-desktop-dashboard-crem_dashboardpy)
17. [API test (`herramientas/test_api.py`)](#17-api-test-herramientastest_apipy)
18. [Troubleshooting](#18-troubleshooting)
19. [Development: tests and code changes](#19-development-tests-and-code-changes)
20. [Technical notes](#technical-notes)
21. [Notice](#notice)
22. [License](#license)

---

## 1. Requirements and installation

```
Python 3.12+
```

> The HTML generator's f-strings use syntax (PEP 701) that only the Python 3.12+ parser accepts. On 3.10 and 3.11, `informe_crem.py` fails to import with a `SyntaxError`.

Every dependency is in `requirements.txt`:

```bash
pip install -r requirements.txt
```

| Package | Used for |
|---|---|
| `pandas` | CSV and dataframe processing |
| `python-docx`, `lxml` | Generating the Word report |
| `openpyxl` | Review spreadsheets (`--excels`) |
| `rich` | Console interface (menus, tables, progress) |
| `reportlab` | PDF export |
| `flask` | Dashboard backend |
| `PyQt6` + `PyQt6-WebEngine` | The dashboard's native desktop window (recommended on Windows) |
| `pywebview` *(optional, commented out in requirements.txt)* | A lighter alternative to PyQt6 if you'd rather not install it |

Neither the API extraction nor the CVE enrichment needs third-party libraries: `trendai_api.py` and `cve_enrich.py` use only `urllib` from the stdlib. Both `informe_crem.py` and `trendai_api.py` auto-install their minimum dependencies on startup if they find them missing.

---

## 2. Folder structure

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

## 3. Quick start

```bash
pip install -r requirements.txt
python main.py            # → opción 1 (Dashboard)
```

In the dashboard:

1. Company: pick the client, or create it by typing the name and pressing *Crear*.
2. Data source:
   - *API Vision One*: set the key first under **Conexión API**.
   - *CSVs descargados*: go to **Estado CSVs**, pick the company and drag in the CSVs exported from the portal. They get renamed and normalised on their own.
3. Template: `Ambas` (technical and executive).
4. Period: the report month.
5. Generate the report. The files show up in `CLIENTES/[EMPRESA]/INFORMES/Mes_Año/`.

---

## 4. Initial configuration

*(Only needed if you're going to use the API as the data source. With manual CSVs you can skip 4.1 and 4.2.)*

### 4.1 Creating the API key in Vision One

1. Go to **Vision One Portal** → `Administration` → `User Roles` → **+ Add role**
   - `Can be assigned to API keys` = **Yes**
   - Permissions: `Dashboards & Reports → Reports → Configure and download + View`
     (covers attack-surface devices, vulnerable devices, high-risk devices, public IPs and asset groups)
   - Also add `Third-party auditing (API only)`, needed for the `securityPosture` endpoint
   - `Data and app assets`: define the asset scope you need
2. `Administration` → `API Keys` → create the key with that role and check that the **Status** toggle is on
3. Copy the token (only visible once)

> The **Operator** role does *not* include the Reports permission and returns 403 on the CREM modules. If you'd rather not create a role, `Master Administrator` covers everything.

Minimum permissions per module:

| Vision One module | API key permission |
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

### 4.2 Creating the `.env` file

Copy `.env.template` to `CLIENTES/[empresa]/.env` and fill it in, or do it from the dashboard under **Conexión API**, which writes it for you:

```bash
# CLIENTES/[empresa]/.env

TRENDAI_API_KEY=eyJ0eXAi...       # token Vision One
TRENDAI_REGION=EU                  # EU | US | AU | IN | SG | JP
TRENDAI_DISCOVERED_BY_FILTER=      # (opcional) filtro TMV1 para acotar el origen de datos
```

Available regions:

| Code | Server | Location |
|--------|----------|-----------|
| `EU` | `api.eu.xdr.trendmicro.com` | Europe |
| `US` | `api.xdr.trendmicro.com` | United States |
| `AU` | `api.au.xdr.trendmicro.com` | Australia |
| `IN` | `api.in.xdr.trendmicro.com` | India |
| `SG` | `api.sg.xdr.trendmicro.com` | Singapore |
| `JP` | `api.jp.xdr.trendmicro.com` | Japan |

### 4.3 The project-wide `.env` (optional)

The `.env` at the root holds values common to every client. Right now, only the NVD key:

```bash
NVD_API_KEY=xxxxxxxx-xxxx-...   # gratuita, sube el rate-limit de 5 a 50 req/30s
```

See [section 12](#12-cve-enrichment-nvd--kev--epss).

### 4.4 Creating `config.json`

It gets created with default values the first time `informe_crem.py` runs against a new company, or when you press *Crear* in the dashboard, but you can create and edit it by hand. The full detail is in [section 7](#7-configuration-reference-configjson).

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

## 5. `main.py`, the single entry point

`main.py` (v2.0) centralises access to the tool with a Rich menu in the console. It is the recommended way to start, although the individual scripts still work on their own for advanced or scripted use (cron, CI and so on).

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

- Dashboard, the default option with Enter: the full graphical interface, described in [section 16](#16-desktop-dashboard-crem_dashboardpy).
- Terminal version: runs `informe_crem.py` interactively, asking on the console for the period, the company, the manual XDR alerts and the CREM Risk score.

Shortcuts to skip the menu:

```bash
python main.py --dashboard   # va directo al dashboard
python main.py --terminal    # va directo a la versión de consola
```

---

## 6. Data sources: API vs. manual CSVs

The generator does not depend on the API: it works just as well with CSVs exported by hand from the portal. You pick between them in the dashboard's **Fuente de datos** card.

### 6.1 The *API Vision One* source

Downloads the month's data with `trendai_api.py` and leaves it in `CLIENTES/[empresa]/CSV/` right before generating. It needs a `.env` with an API key ([section 4](#4-initial-configuration)).

### 6.2 The *CSVs descargados* source: manual export from the portal

In the client's portal: **Cyber Risk Exposure Management → Continuous Risk Management → Threat and Exposure Management**. For each module:

1. Set `Status` = **NEW** (that's the default) and `Event Risk Level` = **ALL**
2. Press **Export** (right-hand side) and wait for the download to finish

Under **Vulnerabilities** there is no `Event Risk Level`, there is `Group By`, so two CSVs come from there: one with `Group By = CVE Event` and one with `Group By = Asset`.

Mapping the exports to their standard names:

| # | Portal module | Filter | Standard name |
|---|---|---|---|
| 1 | Highly Exploitable CVE's – Internal Assets | Group By = **CVE Event** | `cve-events.csv` |
| 2 | Highly Exploitable CVE's – Internal Assets | Group By = **Asset** | `cve-assets.csv` |
| 3 | Account Compromise Indicators | ALL | `account-compromise.csv` |
| 4 | Anomaly Detections | ALL | `anomaly-detections.csv` |
| 5 | Cloud App Activity Risk Events | ALL | `cloud-app.csv` |
| 6 | System Configuration Risk Events | ALL | `sys-conf.csv` |
| 7 | *XDR* | - | Can't be exported; entered by hand in the interactive step |
| 8 | Threat Detections | ALL | `threat-detections.csv` |
| 9 | Security Configuration Risk Events | ALL | `security-conf.csv` |
| 10 | Predictive Analytics | ALL | `predictive-analytics.csv` *(optional)* |

You don't need to rename them by hand. When you upload them through the dashboard (**Estado CSVs**, the drop zone), `normalizar_csvs()` works out the type from the raw filename (`Account Compromise Indicators_20260723095557.csv`). When the name isn't enough, because both vulnerability CSVs are called the same thing, it works it out from the file's headers:

- a header with `Vulnerability ID` / `CVE impact score` → `cve-events.csv`
- a header with `Device name` / `Total CVEs` → `cve-assets.csv`

If you upload the same type twice, the most recent file wins. After uploading, check the **Estado CSVs** list: the 8 required ones should all show an `OK` badge.

> If a module has no data that month, or the portal won't export it, copy the matching empty CSV from `plantilla/plantilla csv sin datos/` into the company's `CSV/` folder. It has the right headers and the report will show that section as zero.

---

## 7. Configuration reference (`config.json`)

One file per company at `CLIENTES/[empresa]/config.json`. Every key is optional: if one is missing, the default below is used. You can edit it from the dashboard, under **Empresa**, **Inventario activos** and **SLAs y módulos**.

| Key | Type | Default | Effect |
|---|---|---|---|
| `empresa` | string | `""` (the folder name) | Name shown in the report headers |
| `contacto_tecnico` | string | `""` | Contact shown in the executive report |
| `sla_critico_dias` | int | `1` | Target SLA in days for Critical findings (the SLA column of the executive Action Plan) |
| `sla_alto_dias` | int | `3` | Target SLA in days for High findings |
| `sla_medio_dias` | int | `7` | Target SLA in days for everything else |
| `meses_reincidente` | int | `2` | How many consecutive months a CVE has to stay unresolved before it is flagged as a repeat offender |
| `notas_adicionales` | string | `""` | Free text included in the executive report |
| `abrir_html_al_terminar` | bool | `false` | If `true`, opens the generated HTML automatically when it finishes |
| `modulos_ignorar` | list[string] | `[]` | Reserved for excluding modules from the report (schema field; it doesn't filter anything yet) |
| `nvd_api_key` | string | `""` | Per-company NVD key, for compatibility; the `.env` is preferable |
| `inventario_activos` | dict | `{}` | Map of `{nombre_o_patrón: {descripcion, criticidad}}`, detailed below |

### `inventario_activos`

Each key is a device or asset name, or a fragment of one, since matching is by substring and case-insensitive, exactly as it appears in the Vision One CSVs (`Device name`, `Asset`, and so on). The value is:

```json
"NombreOFragmento": {
  "descripcion": "Texto libre: para qué sirve el activo",
  "criticidad": "MUY CRITICO"
}
```

`criticidad` accepts exactly one of these 4 values, used in badges, filters, the CREM View ranking and the exposure summary:

| Value | Icon | Meaning |
|---|---|---|
| `MUY CRITICO` | 💀 | Maximum business impact (ERP, production databases, domain controllers…) |
| `CRITICO` | 🔴 | Important, but not maximum impact |
| `NO CRITICO` | 🟢 | Low impact (user PCs, test machines…) |
| `""` (empty) or key absent | ⬜ | Uncatalogued; shown explicitly as such in the report |

This inventory feeds the criticality badges in the tables, the CREM View ranking and the exposure-by-criticality summary row (sections 14 and 15).

---

## 8. Command-line flags for each script

Every script can be called directly, without going through `main.py`, for advanced use, cron, CI and so on.

### `informe_crem.py`

```bash
python informe_crem.py [opciones]
```

| Flag | Type | Description |
|---|---|---|
| `--mes "MES_ANO"` | string | Report period, e.g. `"Mayo 2026"`. If omitted, it asks on the console (or uses the previous month with `--no-input`) |
| `--empresa NOMBRE` | string | Name of the company folder in `CLIENTES/`. If omitted, it shows a selection menu |
| `--template {tecnico,ejecutivo,ambos}` | choice | Report type. `tecnico` = Word + full HTML; `ejecutivo` = lightweight HTML; default is `ambos` |
| `--no-input` | flag | Non-interactive mode (cron/scheduler, and what the dashboard uses). Skips every prompt |
| `--riesgo-crem SCORE` | float | Sets the CREM Risk score by hand (0-100, decimals allowed) instead of the calculated one; see [section 15](#15-crem-risk-automatic-vs-manual) |
| `--api-riesgo` | flag | Queries the real Cyber Risk Index from the Vision One API and uses it as the CREM Risk score |
| `--solo-word` | flag | Regenerates Word/HTML reusing the `.pkl` cache without rereading the CSVs (fast for iterating on the template or styles) |
| `--excels` | flag | Also generates a review spreadsheet per module |
| `--conservar-csv` | flag | Copies the CSVs into the archive instead of moving them (the `CSV/` folder is not emptied) |
| `--prueba` | flag | Generates into `[EMPRESA]/PRUEBAS/` without archiving CSVs, without persisting the CREM Risk score and without touching the history |
| `--enriquecer-cve` | flag | *(Obsolete)* CVE enrichment always happens; kept for compatibility |

### `trendai_api.py`

```bash
python trendai_api.py --empresa NOMBRE --mes "MES_ANO" [opciones]
```

| Flag | Type | Description |
|---|---|---|
| `--empresa NOMBRE` | string, **required** | Company folder holding the `.env`, and where `CSV/` will be written |
| `--mes "MES_ANO"` | string | Period to extract, e.g. `"Mayo 2026"` |
| `--env-file RUTA` | string | Explicit path to a `.env` (default is `CLIENTES/[empresa]/.env`) |
| `--test` | flag | Only test the API connection, without extracting data |
| `--discover` | flag | Only discover which modules the tenant has contracted, without downloading data |
| `--only-risk` | flag | Only fetch the Cyber Risk Index from the API |
| `--verbose` | flag | Detailed log of every HTTP request |

### `herramientas/test_api.py`

```bash
python herramientas/test_api.py [opciones]
```

| Flag | Type | Description |
|---|---|---|
| `--empresa NOMBRE` | string | Defaults to `ACME`. Looks for `CLIENTES/[empresa]/.env` |
| `--env RUTA` | string | Explicit path to the `.env`, as an alternative to `--empresa` |
| `--mes "MES_ANO"` | string | Defaults to the current month |
| `--quick` | flag | Discovery and connection test only, without downloading sample data |
| `--probe-cve` | flag | Exhaustive test of alternative CVE routes (fine-grained ASM diagnosis) |
| `--probe-all` | flag | Tests alternative routes for every module that fails |
| `--dump-endpoint` | flag | Dumps every field of the first record from each endpoint |
| `--json RUTA` | string | Saves the diagnostic results to a JSON file |

### `main.py`

| Flag | Description |
|---|---|
| `--dashboard` | Goes straight to the dashboard |
| `--terminal` | Goes straight to `informe_crem.py` in interactive mode |

---

## 9. System modules

### `trendai_api.py`, the API client

- Automatically discovers which modules the client has contracted, in parallel with 6 workers.
- Pulls from several data sources, with fallback strategies, to extract as much as possible.
- Normalises the raw API responses into homogeneous CSV rows.
- Deduplicates by alert, CVE or asset ID.
- Saves the CSVs and an `.api_meta.json` with extraction statistics.

### `informe_crem.py`, the report generator (v4.0)

- Reads the CSVs from `CLIENTES/[empresa]/CSV/` (normalising the raw names first)
- Enriches every CVE with NVD, CISA KEV and EPSS ([section 12](#12-cve-enrichment-nvd--kev--epss))
- Calculates the CREM Risk score (0 to 100), with a manual or API override ([section 15](#15-crem-risk-automatic-vs-manual))
- Identifies the TOP 3 critical incidents, the Priority Actions
- Builds the 5 CREM View panels (Devices, Internet, Accounts, Applications, Cloud), ranked by score and inventory criticality
- Calculates the CVE diff: new, resolved and persistent against the previous month
- Detects repeat-offender CVEs, unresolved for N months according to `meses_reincidente`
- Calculates the historical trend by reading the archived months
- Generates technical and executive HTML, Word and PDF
- Archives the month's CSVs into the company's history ([section 11](#11-csvs-and-historical-archiving))

### `cve_enrich.py`, the CVE enrichment

Queries NVD 2.0, CISA KEV and EPSS with an on-disk cache. See [section 12](#12-cve-enrichment-nvd--kev--epss).

### `crem_dashboard.py`, the desktop dashboard (v4.1)

A Flask interface served on a free local port and shown in a native window. See [section 16](#16-desktop-dashboard-crem_dashboardpy).

### `herramientas/test_api.py`, the API test

Diagnoses the API key's connectivity and data coverage, distinguishing:
- `[OK]`: module accessible and with data
- `[403]`: the module exists, but the API key has no permission
- `[404]`: module not contracted in the tenant

---

## 10. Vision One API endpoints covered

The system covers 32 endpoints organised into 10 categories:

### Core XDR
| Endpoint | Description | Target CSV |
|----------|-------------|-------------|
| `GET /v3.0/workbench/alerts` | Correlated XDR alerts (threats, anomalies, accounts) | threat / anomaly / account |
| `GET /v3.0/workbench/detections` | Observed ATT&CK techniques (OAT) | sys-conf |
| `POST /v3.0/search/detections` | Search across historical logs | CVEs (fallback) / network |
| `GET /v3.0/xdr/impactedEntities` | Entities affected by XDR alerts | threat |

### Endpoint Security
| Endpoint | Description | Target CSV |
|----------|-------------|-------------|
| `GET /v3.0/endpointSecurity/endpoints` | Full endpoint inventory | CVE enrichment |
| `GET /v3.0/eiqs/endpoints` | EIQS inventory (alternative) | CVE enrichment |
| `GET /v3.0/endpointSecurity/agentHealth` | Disconnected or out-of-date agents | sys-conf |
| `GET /v3.0/endpointSecurity/tasks` | Pending tasks on endpoints | sys-conf |
| `GET /v3.0/endpointSecurity/isolatedEndpoints` | Endpoints currently quarantined | sys-conf |

### CREM / ASRM (Attack Surface Risk Management)
| Endpoint | Description | Target CSV |
|----------|-------------|-------------|
| `GET /v3.0/asrm/vulnerableDevices` | Every active CVE (`cveDetectionStatus=any` is mandatory) | cve-events / cve-assets |
| `GET /v3.0/asrm/attackSurfaceDevices` | Assets with an aggregated risk score | enrichment |
| `GET /v3.0/asrm/securityPosture` | Security posture assessments | security-conf / sys-conf |
| `GET /v3.0/asrm/highRiskDevices` | Devices with the highest risk exposure | cve-assets enrichment |
| `GET /v3.0/asrm/attackSurfacePublicIpAddresses` | Assets exposed directly to the internet (public IPs) | cve-assets enrichment |
| `GET /v3.0/asrm/assetGroups` | Asset groups defined in CREM | cve-assets enrichment |
| `GET /v3.0/asm/riskScore` | The tenant's global risk score (the portal's real score) | meta / risk gauge |
| `GET /v3.0/asm/attackPaths` | Simulated attack paths (predictive) | predictive-analytics |

### Cloud & Email
| Endpoint | Description | Target CSV |
|----------|-------------|-------------|
| `GET /v3.0/cloudAccess/riskAccessEvents` | Risky cloud access (SaaS) | cloud-app |
| `GET /v3.0/emailSecurity/alerts` | Phishing, malware and BEC detected | threat |
| `GET /v3.0/emailSecurity/quarantineMessages` | Messages blocked in quarantine | threat |
| `GET /v3.0/cloudFileSecurity/events` | Malicious files in cloud storage | threat |
| `GET /v3.0/cloudPosture/assessmentSummaries` | Cloud Posture assessments (Conformity) | sys-conf |

### Threat Intelligence
| Endpoint | Description | Target CSV |
|----------|-------------|-------------|
| `GET /v3.0/sandbox/submissionList` | Malware analysis in the Sandbox | threat |
| `GET /v3.0/threatintel/suspiciousObjects` | Active IOCs (IP, domain, URL, hash) | sys-conf |
| `GET /v3.0/threatintel/intelligenceReports` | Threat intelligence reports | sys-conf |
| `GET /v3.0/threatintel/stixSweepingTasks` | Proactive STIX IOC sweeps | sys-conf |

### Identity & IAM
| Endpoint | Description | Target CSV |
|----------|-------------|-------------|
| `GET /v3.0/iam/accountsRiskInsight` | Accounts at elevated risk | account-compromise |
| `GET /v3.0/iam/accounts` | IAM account inventory | account-compromise |
| `GET /v3.0/riskInsights/riskScore` | Global risk score per identity | meta |

### Network Security
| Endpoint | Description | Target CSV |
|----------|-------------|-------------|
| `GET /v3.0/networkSecurity/sensors` | Deployed network sensors | meta (discovery) |
| `GET /v3.0/networkSecurity/policies` | Network security policies | meta (discovery) |

### Container Security
| Endpoint | Description | Target CSV |
|----------|-------------|-------------|
| `GET /v3.0/containerSecurity/alerts` | Kubernetes/Docker container alerts | threat |

### Audit & Response
| Endpoint | Description | Target CSV |
|----------|-------------|-------------|
| `GET /v3.0/auditLogs` | Configuration changes and admin access | sys-conf |
| `GET /v3.0/response/tasks` | Response tasks that were executed | threat |

---

## 11. CSVs and historical archiving

Whether they come from the API or a manual export, they all end up in `CLIENTES/[empresa]/CSV/`:

| File | Contents | Key columns | Required |
|---------|-----------|----------------|:---:|
| `threat-detections.csv` | Active threats: malware, attacks, BEC, sandbox, network, container, cloud file | Risk event, Asset, Event risk level | ✔ |
| `anomaly-detections.csv` | Anomalous behaviour detected by ML | Risk event, Asset, Event risk level | ✔ |
| `account-compromise.csv` | Compromised or at-risk accounts | Risk event, Impact scope, Event risk level | ✔ |
| `cve-events.csv` | Individual CVEs with CVSS score and exploit | Vulnerability ID, CVE impact score, Global exploit potential | ✔ |
| `cve-assets.csv` | Assets with CVEs, summarised per device | Device name, CVE event risk score, Total CVEs | ✔ |
| `security-conf.csv` | Security configuration problems | Risk event, Asset, Event risk level | ✔ |
| `sys-conf.csv` | System problems, IOCs, audit, agents, cloud posture | Risk event, Asset, Event risk level | ✔ |
| `cloud-app.csv` | Risky cloud app events | Risk event, Asset, Event risk level, Detail info | ✔ |
| `predictive-analytics.csv` | Simulated attack paths (ASM) | Entry assets, Target assets, Attack path risk score | - |

### `.api_meta.json`

Only produced on API extractions:

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

### Automatic archiving into the history

When the report finishes generating, `informe_crem.py` moves the CSVs, and the `.api_meta.json`, from `CLIENTES/[empresa]/CSV/` to `CLIENTES/[empresa]/INFORMES/CSV/csv-{mes}-{año}/`, leaving `CSV/` empty and ready for next month. This is the expected behaviour: **the `CSV/` folder being empty after generating is not an error.**

- With `--conservar-csv` they are copied instead of moved.
- With `--prueba` nothing is archived.
- That archive folder is what feeds the CVE diff, the monthly trend and the repeat-offender CVEs in later months.
- Alongside the CSVs, `risk_score.json` stores the month's final CREM Risk score. If you regenerate the same month, the CSVs are not duplicated but `risk_score.json` is updated.

---

## 12. CVE enrichment (NVD · KEV · EPSS)

Every CVE in the report is enriched every time, with nothing to switch on, from three free sources:

| Source | What it contributes |
|---|---|
| NVD 2.0 (NIST) | The version that fixes the flaw, CVSS, CWE, patch links; the *solution* text in Spanish comes from here |
| CISA KEV | Whether the CVE is being actively exploited, and the remediation deadline |
| EPSS (FIRST.org) | Probability of exploitation in the next 30 days, from 0 to 1 |

- Cache in `cve_cache/`: CVEs don't change, so only the missing ones get downloaded. With a warm cache the report regenerates offline.
- NVD rate limit: 5 requests per 30 s without a key (about 6.5 s per new CVE), or 50 per 30 s with a free key (about 0.7 s). If the client has a lot of new CVEs, the first report takes a while. That's normal.
- The NVD key is resolved in this order: the `NVD_API_KEY` environment variable, the project-wide `.env`, the company's `.env`, and `nvd_api_key` in `config.json`.
- The KEV catalog is refreshed every 24 h in a single download.

---

## 13. Files the report generates

In `CLIENTES/[EMPRESA]/INFORMES/Mes_Año/` (or `PRUEBAS/Mes_Año/` with `--prueba`):

| File | Template | Contents |
|---|---|---|
| `Revisión_CREM_Mes_Año.docx` | technical / both | Word report built from `plantilla/Revisión_CREM_MES_AÑO.docx` |
| `Revisión_CREM_Mes_Año.html` | technical / both | Full interactive report (dark theme) |
| `Revisión_CREM_Mes_Año_ejecutivo.html` | executive / both | Executive report (light theme, business language) |
| `Revisión_CREM_Mes_Año*.pdf` | - | HTML conversion (the *Exportar PDF* button in the history) |
| `log_Mes_Año_AAAAMMDD_HHMMSS.txt` | always | Run log, useful for diagnosing |
| `excels/*.xlsx` | with `--excels` | One review spreadsheet per module |

The technical HTML is a single self-contained file (the charts are inline SVG), so it can weigh tens of MB, but you can send it to the client as it is.

---

## 14. The HTML report

The interactive report (the `tecnico` and `ejecutivo` templates) is responsive. On desktop it shows a fixed navigation sidebar; on tablet and mobile, below 900px, the sidebar becomes a sliding panel reachable from the ☰ button in the header, and wide tables scroll horizontally inside their own container without breaking the page layout.

### Header
- Risk Gauge (CREM Risk): a score from 0 to 100, or the manually fixed value with 1 decimal where it applies, with its level (Critical, High, Medium or Low) and the trend against the previous month
- KPIs: total events, new CVEs, resolved CVEs, assets at risk, XDR alerts, repeat-offender CVEs

### CREM View (5 dimensions)

Each panel shows the TOP 3 highest-risk assets or events in that dimension. Above the 5 panels there is a summary row with the number of assets carrying a High or Critical CVE, grouped by inventory criticality (💀 Muy Crítico · 🔴 Crítico · 🟢 No Crítico · ⬜ Sin catalogar), to give exposure context before you go into the detail.

| Dimension | What the TOP 3 shows | Ranking criterion |
|-----------|---------------|---------------------|
| Devices | Assets with the highest CVE risk score | Numeric score plus a bonus for inventory criticality (Muy Crítico +15, Crítico +8). The displayed score is always the real one; the bonus only affects ordering |
| Internet / Exposed | Assets with a public IP or flagged as internet-facing | Same as Devices: score plus criticality bonus |
| Accounts | Highest-risk accounts | Event level (Critical > High) |
| Applications | OS/apps with the most critical CVEs | Max CVSS score |
| Cloud Assets | Highest-risk cloud apps | Event level |

Each item in the Devices and Internet panels shows its criticality chip. If the asset isn't in `config.json`'s `inventario_activos`, it appears explicitly as ⬜ Sin catalogar rather than being hidden.

### Executive summary
- Priority Actions: the TOP 3 Critical and High Workbench incidents, with a direct link to the portal
- CVE diff (new / resolved / persistent against the previous month)
- Charts: severity distribution (donut) and events per module (bars)
- Module table with totals

### Detailed sections
CVE Events · CVE Assets · System Config · Security Config · Threats · Anomalies · Cloud Apps · Accounts · XDR · Repeat offenders · Historical trend · Action Plan

### Features
- Real-time search across all the data
- Filters by severity and by inventory criticality
- CSV export per section
- Expanded detail per asset (a popup with all its CVEs, including the enriched solution)
- Navigation sidebar with live counters (a sliding drawer on mobile)

---

## 15. CREM Risk: automatic vs. manual

The CREM Risk score shown in the header pill of the technical report is, by default, a heuristic of its own (`calcular_risk_score`) computed from critical and high CVEs, active threats, compromised accounts, repeat-offender assets and configuration problems. It is not the same calculation as the "Cyber Risk Index / ASM Risk Score" in the Vision One portal, so it may not match: the heuristic can give 17 while the portal shows 36.2.

Three ways to set the real value:

- Automatically from the API, with `--api-riesgo`, which queries the tenant's real Cyber Risk Index. This is what the dashboard uses when you leave the manual field empty and an API key is present.
- Manually on the console: if you're not using `--no-input`, generating the report asks you:
  ```
  Riesgo CREM
  Score calculado automáticamente: 17
  Si el portal Vision One muestra un valor distinto, introdúcelo aquí (ej: 36.2).
  Enter = mantener el valor automático.
  → 36.2
  ```
- Manually by flag or from the dashboard: `--riesgo-crem 36.2`, or the **Riesgo CREM manual** numeric field in the dashboard, which has an *Obtener de API* button next to it to fill it in from Vision One.

The final value is shown with 1 decimal when it isn't a whole number, and is persisted in `risk_score.json` inside the month's archive folder. Later months use that real value, rather than an approximation, to calculate the trend (`▲`/`▼`).

---

## 16. Desktop dashboard (`crem_dashboard.py`)

```bash
python crem_dashboard.py
# o: python main.py --dashboard
```

The dashboard is not a web server on a fixed port. On startup it finds a free local port, brings up Flask on a background thread, and opens a native desktop window pointing at that server:

1. PyQt6 with PyQt6-WebEngine, if installed. This is the one to go for, because it integrates better on Windows.
2. Failing that, it tries pywebview, which is lighter.
3. If neither is there, it opens the URL in the system browser.

Sidebar screens:

| Section | Screen | What it's for |
|---|---|---|
| Generation | **Generar informe** | Company · template (Técnica / Ejecutiva / Ambas) · data source (API or CSVs) · period · options · manual CREM Risk. Live progress over Server-Sent Events |
| Generation | **Histórico** | Every report generated: open the HTML/Word, export to PDF, open the folder |
| Configuration | **Empresa** | Edit the whole `config.json` |
| Configuration | **Inventario activos** | Add and remove assets and their criticality, in a table |
| Configuration | **SLAs y módulos** | SLAs per severity and repeat-offender months |
| Diagnostics | **Estado CSVs** | A drop zone for uploading the raw CSVs (they get renamed and normalised on their own), plus a listing of which CSVs are present, with rows and size, and a warning about which are missing |
| Diagnostics | **Conexión API** | API key and region, test the connection, see which modules are available, and launch the month's data download |
| Diagnostics | **Acerca de** | Script paths and folder structure |

Generation buttons, in the footer:

- **Generar informe** is the normal flow: it writes into `INFORMES/`, archives the CSVs and updates the history.
- **Generar prueba** should write into `PRUEBAS/` without touching the history, but right now the dashboard doesn't pass the `--prueba` flag to the subprocess, so it generates into `INFORMES/` and then can't find the files where it looks for them. Until that's fixed, use the terminal for test mode: `python informe_crem.py --empresa X --mes "Junio 2026" --prueba`.

---

## 17. API test (`herramientas/test_api.py`)

A full diagnosis of the API key and its data coverage:

```bash
# Modo rápido: solo verifica conexión y descubre módulos (sin descargar datos)
python herramientas/test_api.py --empresa ACME --quick

# Modo completo: descarga una muestra de cada módulo disponible
python herramientas/test_api.py --empresa ACME --mes "Junio 2026"

# Guardar resultados en JSON
python herramientas/test_api.py --empresa ACME --json diagnostico.json

# Otra empresa / .env explícito
python herramientas/test_api.py --empresa ACME
python herramientas/test_api.py --env /ruta/al/.env
```

Reading the results:

| Status | Code | Meaning |
|--------|--------|-------------|
| `[OK]` | 200 | Module accessible and with data |
| `[WARN]` | - | Accessible, but the response was unexpected |
| `[403]` | 403 | Module contracted, but the API key has no permission |
| `[404]` | 404 | Module not contracted in this tenant |
| `[NET]` | 0 | Network error; check region and connectivity |

> If you see modules coming back `[403]`, check the API key's role ([section 4.1](#41-creating-the-api-key-in-vision-one)). The missing permission is almost always `Dashboards & Reports → Reports`.

---

## 18. Troubleshooting

### "Invalid API key" (HTTP 401)
- Check the key hasn't expired and that the **Status** toggle is on
- Check it was copied in full, with no stray spaces

### Modules returning HTTP 403
- The API key exists but doesn't have the role it needs
- Edit the role under **Administration → User Roles** and add `Dashboards & Reports → Reports` plus `Third-party auditing (API only)`

### "No connection" (HTTP 0)
- Check the region in `.env`, which has to match the portal you use
- Check network connectivity from the machine

### CVEs in the portal but `asm_vuln` comes back 404
- The portal can show CVEs through Endpoint Security without the full ASM module
- The system has an automatic fallback through the Search API to detect CVEs without ASM

### The `CSV/` folder is empty after generating
- That's normal: the CSVs are moved into the archive ([section 11](#11-csvs-and-historical-archiving)). They're in `INFORMES/CSV/csv-mes-año/`

### I uploaded the CSVs but some are missing or misclassified
- Check **Estado CSVs**: it says exactly which ones are missing
- The two vulnerability CSVs are told apart by their headers, not by their name, so make sure you export one with `Group By = CVE Event` and one with `Group By = Asset`
- If a module has no data, copy the empty CSV from `plantilla/plantilla csv sin datos/`

### The report takes forever the first time
- That's the CVE enrichment against NVD ([section 12](#12-cve-enrichment-nvd--kev--epss)). Set `NVD_API_KEY` in the project-wide `.env` to go about 9× faster; later runs come from the cache

### The CREM Risk score doesn't match the Vision One portal
- That's expected: the internal heuristic and the portal's Cyber Risk Index are different calculations. Use `--api-riesgo`, `--riesgo-crem`, the interactive prompt or the dashboard field ([section 15](#15-crem-risk-automatic-vs-manual))

### Empty report, or one with very little data
- Check the CSVs exist in `CLIENTES/[empresa]/CSV/`
- If you're using the API, check `.api_meta.json` to see how many rows were extracted
- Check the `log_*.txt` in the report's folder

### Strange characters in the report
- The HTML report is UTF-8; check the browser is detecting it correctly

### The dashboard doesn't open a native window, only the browser
- Install `PyQt6` and `PyQt6-WebEngine` (`pip install -r requirements.txt`); without them it falls back to the system browser automatically

### The report came out, but with odd figures
- Look at the end of the run: if something generated incompletely, an **AVISOS DE ESTA EJECUCIÓN** block appears with what failed and what was lost. The same warning shows up inside the HTML, right at the top
- Check the **Procedencia de los CSV de entrada** block in the log: rows, size, date and hash of every CSV that went in. If two runs of the same month give different results, that's where you see whether the data was the same
- If you have your own regression test with real client data, run it: if it fails, the problem is in the code, not in the data

---

## 19. Development: tests and code changes

### Regression test

Internally, this project leans on a regression test
(`tests/test_regresion.py`, not included here) that reproduces a real, already
closed month for a client over a temporary copy of its archived CSVs, never
touching `CLIENTES/`, and checks the result figure by figure: rows per module,
CVE diff, month-to-month comparison, summary, repeat offenders, trend ordering
and CREM Risk score. It was left out of this public version because its expected
figures are computed over real client data that isn't distributed here.

If you're going to change the calculation, it is worth building your own version
of this test against a month of yours that is already closed, with the expected
figures written by hand: this program's failures are not exceptions, the process
finishes with a ✓ and the report comes out with the numbers wrong, and an error
like that reaches the client without anyone noticing.

### Adding a new module

Every module (CVE, threats, cloud apps and so on) is declared in one single
place: `MODULOS`, in `informe_crem.py`. A new entry there registers the module
in the loading, the summary, the bar chart and the monthly comparison. Never
reference a module by its Spanish label: use its `id`.

### When something fails halfway

Don't use `warn()` for a failure that truncates the report: use
`degradado(ámbito, detalle, impacto)`. That way it shows up in the run's final
summary, in the log and inside the HTML itself, instead of getting lost in the
console.

### Library versions

`requirements.txt` is for installing from scratch; `requirements.lock` pins the
exact environment the delivered reports are generated with. Before bumping any
version, run the regression: a pandas upgrade once caused empty values to be
printed as the literal text `nan` inside a client's report.

---

## Technical notes

- Generating depends on no external API: with the CSVs already on disk and the CVE cache warm, the generator works 100% offline.
- Historical cache: previous months' CSVs are archived in `INFORMES/CSV/csv-mes-año/` and feed the trends, the CVE diff and the real historical CREM Risk score.
- Run cache: `datos/*.pkl` lets you regenerate Word and HTML without rereading the CSVs (`--solo-word`).
- Deduplication: Workbench alerts are deduplicated by ID, so the same alert isn't counted twice even if it turns up through several extraction strategies.
- Automatic fallback: if ASM isn't available, the system looks for CVEs through the Search API; if cloudAccess isn't there, it looks for cloud events in Workbench.
- Rate limiting: extraction respects the `Retry-After` header on 429 responses and retries with exponential backoff for 5xx errors.
- Security: the `.env` files hold credentials, so they shouldn't be pushed to git or shared over email. The repo's `.gitignore` already covers them.

---

## Notice

This is a personal, independent project, not affiliated with Trend Micro, nor endorsed or certified by them. "Trend Micro" and "Vision One" are trademarks of their respective owners; this repository only consumes their documented public API.

It is the public version of a tool I use in production. Before publishing it, the following were removed completely: real client names and CSVs, a real infrastructure inventory that was hardcoded in the code, credentials (`.env`, API keys) and any report that had already been generated. What's left is the generic engine. Any `CLIENTES/[empresa]/` you create stays on your machine and never reaches the repo, thanks to the `.gitignore`.

## License

[MIT](LICENSE). Use it, modify it and redistribute it freely.

## Author

Eduardo Olivares
