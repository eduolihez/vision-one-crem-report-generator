#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo de Enriquecimiento con Marcos de Ciberseguridad
Generador de Informes CREM / TrendAI

Asigna automáticamente a las detecciones, riesgos y CVEs:
  1. MITRE ATT&CK (Táctica, ID de Técnica y Nombre)
  2. Directiva NIS2 (Art. 21.2 - Requisitos de gestión de riesgos)
  3. ISO/IEC 27001:2022 (Anexo A - Controles de seguridad)
"""

from typing import Dict, Any, List, Optional

# Diccionario maestro de reglas de mapeo por palabras clave / patrones de eventos
_EVENT_MAPPINGS = [
    # Compromiso de cuentas / Identidad
    {
        "keywords": ["account", "compromise", "credential", "login", "password", "brute force", "identity", "authentication"],
        "mitre": {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access / Persistence"},
        "nis2": {"art": "Art. 21(2)(i)", "desc": "Políticas de control de acceso y gestión de activos"},
        "iso27001": {"control": "A.5.15 / A.8.5", "desc": "Control de acceso y autenticación segura"}
    },
    # Vulnerabilidades / CVEs
    {
        "keywords": ["cve", "vulnerability", "exploit", "unpatched", "cve-events", "cve-assets"],
        "mitre": {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        "nis2": {"art": "Art. 21(2)(e)", "desc": "Seguridad en la adquisición, desarrollo y mantenimiento de sistemas (vulnerabilidades)"},
        "iso27001": {"control": "A.8.8", "desc": "Gestión de vulnerabilidades técnicas"}
    },
    # Cloud Apps / Exfiltración / Sombras
    {
        "keywords": ["cloud", "app", "shadow", "saas", "storage", "upload", "exfiltration"],
        "mitre": {"id": "T1567", "name": "Exfiltration Over Web Service", "tactic": "Exfiltration"},
        "nis2": {"art": "Art. 21(2)(c)", "desc": "Continuidad de las actividades y seguridad en la nube"},
        "iso27001": {"control": "A.5.23", "desc": "Seguridad de la información para el uso de servicios en la nube"}
    },
    # Configuración de sistema / Endpoint Health
    {
        "keywords": ["sys-conf", "system configuration", "firewall", "antivirus", "tamper", "registry", "uac", "os"],
        "mitre": {"id": "T1562", "name": "Impair Defenses", "tactic": "Defense Evasion"},
        "nis2": {"art": "Art. 21(2)(g)", "desc": "Prácticas básicas de ciberhigiene y formación"},
        "iso27001": {"control": "A.8.9", "desc": "Gestión de la configuración"}
    },
    # Configuración de seguridad / Politicas
    {
        "keywords": ["security-conf", "security configuration", "policy", "mfa", "encryption", "tls", "ssl"],
        "mitre": {"id": "T1556", "name": "Modify Authentication Process", "tactic": "Defense Evasion / Credential Access"},
        "nis2": {"art": "Art. 21(2)(h)", "desc": "Políticas y procedimientos sobre la utilización de criptografía y cifrado"},
        "iso27001": {"control": "A.8.24", "desc": "Uso de la criptografía"}
    },
    # Amenazas / Malware / Ransomware / XDR
    {
        "keywords": ["threat", "malware", "ransomware", "trojan", "virus", "spyware", "c2", "command and control"],
        "mitre": {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
        "nis2": {"art": "Art. 21(2)(b)", "desc": "Gestión de incidentes"},
        "iso27001": {"control": "A.5.24 / A.8.16", "desc": "Gestión de incidentes de seguridad y monitorización"}
    },
    # Anomalías / Comportamiento sosopechoso
    {
        "keywords": ["anomaly", "suspicious", "behavior", "unusual", "lateral", "reconnaissance"],
        "mitre": {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement"},
        "nis2": {"art": "Art. 21(2)(a)", "desc": "Políticas relativas al análisis de riesgos y a la seguridad de los sistemas"},
        "iso27001": {"control": "A.8.16", "desc": "Actividades de monitorización"}
    },
    # Analítica predictiva / Rutas de ataque
    {
        "keywords": ["predictive", "attack path", "entry", "target", "risk score"],
        "mitre": {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
        "nis2": {"art": "Art. 21(2)(a)", "desc": "Evaluación de la eficacia de las medidas de gestión de riesgos"},
        "iso27001": {"control": "A.5.7", "desc": "Inteligencia sobre amenazas"}
    }
]

_DEFAULT_FRAMEWORK = {
    "mitre": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "nis2": {"art": "Art. 21(2)(a)", "desc": "Gestión de riesgos de seguridad de la información"},
    "iso27001": {"control": "A.8.16", "desc": "Supervisión y monitorización de seguridad"}
}

def enriquecer_evento_frameworks(nombre_evento: str, modulo: str = "") -> Dict[str, Dict[str, str]]:
    """
    Dada una cadena de evento o nombre de módulo,
    devuelve un diccionario con las asignaciones MITRE ATT&CK, NIS2 e ISO 27001.
    """
    texto = f"{nombre_evento} {modulo}".lower()
    
    for rule in _EVENT_MAPPINGS:
        if any(kw in texto for kw in rule["keywords"]):
            return {
                "mitre": rule["mitre"],
                "nis2": rule["nis2"],
                "iso27001": rule["iso27001"]
            }
            
    return _DEFAULT_FRAMEWORK

def obtener_resumen_cumplimiento(datos: Dict[str, Any]) -> Dict[str, Any]:
    """
    Genera estadísticas de cobertura y distribución por marcos normativos
    (MITRE ATT&CK, NIS2, ISO 27001) para incluir en los informes.
    """
    resumen = {
        "mitre_tactics": {},
        "nis2_articulos": {},
        "iso_controles": {},
        "total_eventos_mapeados": 0
    }
    
    modulos = [
        ("cve_events", "CVEs Vulnerabilidades"),
        ("sec_conf", "Configuración Seguridad"),
        ("sys_conf", "Configuración Sistema"),
        ("threats", "Amenazas XDR"),
        ("anomaly", "Anomalías Comportamiento"),
        ("accounts", "Compromiso Cuentas"),
        ("cloud_app", "Cloud Apps Riesgo")
    ]
    
    for key, label in modulos:
        df = datos.get(key)
        if df is None or getattr(df, "empty", True):
            continue
        
        filas = df.head(200).to_dict("records")
        for row in filas:
            evento_text = str(row.get("Risk event") or row.get("Vulnerability ID") or key)
            fw = enriquecer_evento_frameworks(evento_text, key)
            
            resumen["total_eventos_mapeados"] += 1
            
            tac = fw["mitre"]["tactic"]
            resumen["mitre_tactics"][tac] = resumen["mitre_tactics"].get(tac, 0) + 1
            
            art = f"{fw['nis2']['art']} - {fw['nis2']['desc']}"
            resumen["nis2_articulos"][art] = resumen["nis2_articulos"].get(art, 0) + 1
            
            ctrl = f"{fw['iso27001']['control']} ({fw['iso27001']['desc']})"
            resumen["iso_controles"][ctrl] = resumen["iso_controles"].get(ctrl, 0) + 1
            
    return resumen
