"""Datos semilla idempotentes para SOC-Lite.

Uso:
    python -m app.seed            # crea datos si la base está vacía
    python -m app.seed --reset    # elimina y recrea el esquema + datos demo
"""
from __future__ import annotations

import argparse
import random
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.db.session import Base, SessionLocal, engine, init_db
from app.models import (
    Alert,
    Asset,
    AuditLog,
    EnrichmentData,
    Incident,
    Permission,
    Role,
    TriageResult,
    User,
)
from app.models.enums import (
    AlertStatus,
    Criticality,
    IncidentStatus,
    Severity,
    Verdict,
)
from app.services.normalizer import fingerprint_for

PERMISSIONS = [
    ("dashboard:read", "dashboard", "Consultar dashboard y métricas"),
    ("alerts:read", "alerts", "Consultar alertas y su detalle"),
    ("alerts:create", "alerts", "Crear alertas manuales e ingerir eventos"),
    ("alerts:update", "alerts", "Actualizar estado, severidad y asignación"),
    ("alerts:triage", "alerts", "Ejecutar triaje automático o manual"),
    ("alerts:close", "alerts", "Cerrar o descartar alertas"),
    ("incidents:read", "incidents", "Consultar incidentes"),
    ("incidents:create", "incidents", "Escalar alertas y crear incidentes"),
    ("incidents:update", "incidents", "Actualizar y cerrar incidentes"),
    ("reports:read", "reports", "Consultar reportes generados"),
    ("reports:export", "reports", "Generar y descargar reportes PDF/Word/Excel"),
    ("users:read", "users", "Consultar usuarios y roles"),
    ("users:manage", "users", "Crear, editar y desactivar usuarios"),
    ("roles:read", "users", "Consultar roles y permisos"),
    ("audit:read", "audit", "Consultar la bitácora de auditoría"),
    ("settings:manage", "settings", "Administrar configuración del sistema"),
]

ROLES = {
    "admin": {
        "description": "Administrador del sistema y de la seguridad",
        "color": "rose",
        "is_system": True,
        "permissions": [code for code, _, _ in PERMISSIONS],
    },
    "supervisor": {
        "description": "Supervisor SOC: gestión de turnos, incidentes y reportes",
        "color": "violet",
        "is_system": True,
        "permissions": [
            "dashboard:read",
            "alerts:read",
            "alerts:create",
            "alerts:update",
            "alerts:triage",
            "alerts:close",
            "incidents:read",
            "incidents:create",
            "incidents:update",
            "reports:read",
            "reports:export",
            "users:read",
            "roles:read",
            "audit:read",
        ],
    },
    "analyst": {
        "description": "Analista SOC L1/L2: triaje y respuesta a incidentes",
        "color": "cyan",
        "is_system": True,
        "permissions": [
            "dashboard:read",
            "alerts:read",
            "alerts:create",
            "alerts:update",
            "alerts:triage",
            "alerts:close",
            "incidents:read",
            "incidents:create",
            "incidents:update",
            "reports:read",
            "reports:export",
        ],
    },
    "auditor": {
        "description": "Auditoría y cumplimiento: solo lectura y trazabilidad",
        "color": "amber",
        "is_system": True,
        "permissions": [
            "dashboard:read",
            "alerts:read",
            "incidents:read",
            "reports:read",
            "reports:export",
            "users:read",
            "roles:read",
            "audit:read",
        ],
    },
    "viewer": {
        "description": "Consulta ejecutiva sin capacidad de modificación",
        "color": "slate",
        "is_system": True,
        "permissions": [
            "dashboard:read",
            "alerts:read",
            "incidents:read",
            "reports:read",
        ],
    },
}

USERS = [
    {
        "email": "admin@soclite.local",
        "full_name": "Valeria Ríos",
        "password": "Admin2026!",
        "role": "admin",
        "job_title": "CISO / Administradora",
        "department": "Seguridad de la Información",
        "phone": "+51 999 100 001",
    },
    {
        "email": "supervisor@soclite.local",
        "full_name": "Diego Salazar",
        "password": "Supervisor2026!",
        "role": "supervisor",
        "job_title": "SOC Lead",
        "department": "SOC",
        "phone": "+51 999 100 002",
    },
    {
        "email": "analista@soclite.local",
        "full_name": "Camila Torres",
        "password": "Analista2026!",
        "role": "analyst",
        "job_title": "Analista SOC L2",
        "department": "SOC",
        "phone": "+51 999 100 003",
    },
    {
        "email": "auditor@soclite.local",
        "full_name": "Martín Quispe",
        "password": "Auditor2026!",
        "role": "auditor",
        "job_title": "Auditor de TI",
        "department": "Cumplimiento",
        "phone": "+51 999 100 004",
    },
    {
        "email": "consulta@soclite.local",
        "full_name": "Lucía Fernández",
        "password": "Consulta2026!",
        "role": "viewer",
        "job_title": "Gerente de Operaciones",
        "department": "Gerencia",
        "phone": "+51 999 100 005",
    },
]

ASSETS = [
    ("srv-dc01", "10.10.1.10", Criticality.CRITICAL, "Infraestructura", "produccion", "Windows Server 2022", ["dominio", "ad"]),
    ("srv-db01", "10.10.1.20", Criticality.CRITICAL, "DBA", "produccion", "Ubuntu 22.04", ["base-de-datos", "pci"]),
    ("srv-web01", "10.10.2.15", Criticality.HIGH, "Aplicaciones", "dmz", "Debian 12", ["web", "exposicion-internet"]),
    ("fw-edge01", "10.10.0.1", Criticality.CRITICAL, "Redes", "perimetro", "OPNsense 24.07", ["firewall", "perimetro"]),
    ("srv-mail01", "10.10.2.25", Criticality.HIGH, "Mesa de ayuda", "dmz", "Exchange Server 2019", ["correo"]),
    ("srv-backup01", "10.10.1.30", Criticality.HIGH, "Infraestructura", "produccion", "Ubuntu 22.04", ["backup", "ransomware"]),
    ("k8s-prod-01", "10.10.4.10", Criticality.HIGH, "Plataforma", "produccion", "Kubernetes 1.30", ["contenedores"]),
    ("vpn-gw01", "10.10.0.5", Criticality.HIGH, "Redes", "perimetro", "FortiOS 7.4", ["vpn", "acceso-remoto"]),
    ("ws-fin-014", "10.10.3.44", Criticality.MEDIUM, "Finanzas", "corporativo", "Windows 11", ["finanzas"]),
    ("ws-rrhh-07", "10.10.3.71", Criticality.LOW, "RRHH", "corporativo", "Windows 11", ["rrhh"]),
    ("ws-dev-03", "10.10.5.12", Criticality.LOW, "Desarrollo", "desarrollo", "Ubuntu 24.04", ["dev"]),
    ("srv-app01", "10.10.2.30", Criticality.HIGH, "Aplicaciones", "dmz", "Ubuntu 22.04", ["api", "exposicion-internet"]),
]

TEMPLATES = [
    {
        "title": "Fuerza bruta SSH detectada",
        "description": "Múltiples intentos de autenticación fallidos para el usuario root desde una IP externa. Wazuh correlaciona 48 eventos en 3 minutos.",
        "source": "wazuh",
        "rule_id": "5710",
        "level": 10,
        "source_ip": "203.0.113.45",
        "hostname": "srv-web01",
        "username": "root",
        "severity": Severity.HIGH,
        "verdict": Verdict.TRUE_POSITIVE,
        "risk": 82,
        "mitre": ["T1110", "T1078"],
        "summary": "Ataque de fuerza bruta SSH contra srv-web01 desde 203.0.113.45. Se observan 48 fallos en 3 minutos y un intento exitoso posterior. Riesgo alto de acceso no autorizado.",
    },
    {
        "title": "Ransomware: modificación masiva de archivos",
        "description": "FIM detecta 1,842 archivos modificados con extensión .locked en el volumen de datos. El proceso sospechoso es svchost_update.exe.",
        "source": "wazuh",
        "rule_id": "100210",
        "level": 15,
        "source_ip": "10.10.1.20",
        "hostname": "srv-db01",
        "username": "svc_backup",
        "severity": Severity.CRITICAL,
        "verdict": Verdict.TRUE_POSITIVE,
        "risk": 96,
        "mitre": ["T1486", "T1204"],
        "summary": "Actividad compatible con ransomware en srv-db01: 1,842 archivos cifrados y un binario no firmado ejecutándose con la cuenta de respaldo. Requiere contención inmediata y activación del plan de crisis.",
    },
    {
        "title": "Conexión a infraestructura de comando y control",
        "description": "El EDR detecta beaconing HTTPS cada 60 segundos hacia un dominio clasificado como C2. El proceso powershell.exe está ofuscado.",
        "source": "wazuh",
        "rule_id": "100305",
        "level": 13,
        "source_ip": "10.10.4.10",
        "hostname": "k8s-prod-01",
        "username": "system:serviceaccount",
        "severity": Severity.CRITICAL,
        "verdict": Verdict.TRUE_POSITIVE,
        "risk": 91,
        "mitre": ["T1071", "T1059"],
        "summary": "Beaconing periódico hacia un dominio de C2 desde un pod de producción. La combinación de PowerShell ofuscado y tráfico TLS periódico sugiere un implante activo.",
    },
    {
        "title": "SQL injection en aplicación web",
        "description": "El WAF de OPNsense bloquea una secuencia UNION SELECT en el parámetro id de /api/v1/productos. Se registran 12 intentos desde la misma IP.",
        "source": "opnsense",
        "rule_id": "OPN-WAF-042",
        "level": 11,
        "source_ip": "198.51.100.77",
        "hostname": "srv-app01",
        "username": None,
        "severity": Severity.HIGH,
        "verdict": Verdict.TRUE_POSITIVE,
        "risk": 79,
        "mitre": ["T1190"],
        "summary": "Intentos de inyección SQL bloqueados por el WAF contra la API de productos. Aunque el WAF contiene el ataque, la recurrencia y el objetivo expuesto justifican revisión de código y bloqueo de origen.",
    },
    {
        "title": "Ejecución de PowerShell ofuscado",
        "description": "Sysmon registra powershell.exe con encodedcommand y descarga en memoria desde una URL de baja reputación.",
        "source": "wazuh",
        "rule_id": "100412",
        "level": 12,
        "source_ip": "10.10.3.44",
        "hostname": "ws-fin-014",
        "username": "jperez",
        "severity": Severity.CRITICAL,
        "verdict": Verdict.TRUE_POSITIVE,
        "risk": 88,
        "mitre": ["T1059", "T1105"],
        "summary": "PowerShell con comando codificado y descarga en memoria en un equipo de Finanzas. Es un patrón típico de ejecución de segunda etapa; aislar el host y recolectar memoria.",
    },
    {
        "title": "Correo con macro maliciosa",
        "description": "La pasarela de correo detecta un adjunto .docm con macro que ejecuta certutil para descargar un binario.",
        "source": "wazuh",
        "rule_id": "100511",
        "level": 9,
        "source_ip": "192.0.2.88",
        "hostname": "srv-mail01",
        "username": "rrhh",
        "severity": Severity.HIGH,
        "verdict": Verdict.TRUE_POSITIVE,
        "risk": 74,
        "mitre": ["T1566", "T1204"],
        "summary": "Correo de phishing con macro que descarga un ejecutable. La entrega fue bloqueada, pero debe verificarse si otros destinatarios recibieron el mensaje y purgar la campaña.",
    },
    {
        "title": "Movimiento lateral por SMB",
        "description": "Se detectan conexiones SMB administrativas desde srv-db01 hacia srv-dc01 y srv-backup01 usando credenciales de servicio.",
        "source": "wazuh",
        "rule_id": "100620",
        "level": 12,
        "source_ip": "10.10.1.20",
        "hostname": "srv-db01",
        "username": "svc_backup",
        "severity": Severity.CRITICAL,
        "verdict": Verdict.SUSPICIOUS,
        "risk": 86,
        "mitre": ["T1021", "T1078"],
        "summary": "Conexiones SMB laterales desde el servidor de base de datos hacia controladores de dominio y respaldo. Puede ser una tarea administrativa legítima, pero requiere validación con el equipo de infraestructura.",
    },
    {
        "title": "Posible exfiltración de datos",
        "description": "Se detecta un incremento del 900% en tráfico saliente desde srv-db01 hacia una IP extranjera durante la madrugada.",
        "source": "opnsense",
        "rule_id": "OPN-NET-118",
        "level": 14,
        "source_ip": "10.10.1.20",
        "hostname": "srv-db01",
        "username": None,
        "severity": Severity.CRITICAL,
        "verdict": Verdict.TRUE_POSITIVE,
        "risk": 94,
        "mitre": ["T1041", "T1021"],
        "summary": "Pico anómalo de tráfico saliente desde la base de datos de producción hacia una IP externa. Coincide con la alerta de movimiento lateral; tratar como posible exfiltración y preservar flujos.",
    },
    {
        "title": "Fuerza bruta RDP",
        "description": "Se registran 126 inicios de sesión fallidos por RDP en 10 minutos contra una estación de trabajo.",
        "source": "wazuh",
        "rule_id": "60122",
        "level": 9,
        "source_ip": "203.0.113.91",
        "hostname": "ws-rrhh-07",
        "username": "Administrator",
        "severity": Severity.HIGH,
        "verdict": Verdict.TRUE_POSITIVE,
        "risk": 77,
        "mitre": ["T1110", "T1021"],
        "summary": "Ataque de fuerza bruta RDP contra una estación de RRHH. Verificar si el servicio RDP debe estar expuesto y bloquear el origen en el perímetro.",
    },
    {
        "title": "Autenticación desde ubicación inusual",
        "description": "El usuario jperez inicia sesión en la VPN desde un país sin historial previo, 20 minutos después de un acceso desde Lima.",
        "source": "wazuh",
        "rule_id": "100730",
        "level": 7,
        "source_ip": "198.51.100.140",
        "hostname": "vpn-gw01",
        "username": "jperez",
        "severity": Severity.MEDIUM,
        "verdict": Verdict.SUSPICIOUS,
        "risk": 61,
        "mitre": ["T1078"],
        "summary": "Acceso VPN desde geolocalización inconsistente. Posible uso de credenciales comprometidas o viaje no declarado; contactar al usuario y revisar dispositivos activos.",
    },
    {
        "title": "Integridad de archivos críticos modificada",
        "description": "FIM detecta cambios en /etc/nginx/nginx.conf y en el binario de la aplicación. No hay ticket de cambio asociado.",
        "source": "wazuh",
        "rule_id": "550",
        "level": 8,
        "source_ip": "10.10.2.15",
        "hostname": "srv-web01",
        "username": "deploy",
        "severity": Severity.MEDIUM,
        "verdict": Verdict.SUSPICIOUS,
        "risk": 58,
        "mitre": ["T1565"],
        "summary": "Cambios de configuración sin ticket de cambio en el servidor web. Validar con el equipo de aplicaciones y comparar contra el repositorio de configuración.",
    },
    {
        "title": "Usuario privilegiado fuera de horario",
        "description": "Se detecta inicio de sesión interactivo de una cuenta administrativa a las 02:14 fuera de la ventana autorizada.",
        "source": "wazuh",
        "rule_id": "100811",
        "level": 6,
        "source_ip": "10.10.1.10",
        "hostname": "srv-dc01",
        "username": "administrator",
        "severity": Severity.MEDIUM,
        "verdict": Verdict.SUSPICIOUS,
        "risk": 55,
        "mitre": ["T1078"],
        "summary": "Acceso administrativo fuera de horario. Confirmar si corresponde a una ventana de mantenimiento o a una actividad no autorizada.",
    },
    {
        "title": "Descarga de malware desde sitio comprometido",
        "description": "El proxy bloquea la descarga de un ejecutable desde un dominio de alojamiento comprometido; el usuario hizo clic en el enlace.",
        "source": "opnsense",
        "rule_id": "OPN-PROXY-021",
        "level": 10,
        "source_ip": "10.10.3.44",
        "hostname": "ws-fin-014",
        "username": "jperez",
        "severity": Severity.HIGH,
        "verdict": Verdict.TRUE_POSITIVE,
        "risk": 80,
        "mitre": ["T1204", "T1105"],
        "summary": "Intento de descarga de malware bloqueado por el proxy. El usuario interactuó con el enlace; revisar correo, navegador y persistencia en la estación.",
    },
    {
        "title": "Escaneo de puertos desde Internet",
        "description": "El firewall registra 2,340 paquetes SYN hacia 1,024 puertos en 60 segundos desde una única IP.",
        "source": "opnsense",
        "rule_id": "OPN-NET-007",
        "level": 7,
        "source_ip": "192.0.2.201",
        "hostname": "fw-edge01",
        "username": None,
        "severity": Severity.MEDIUM,
        "verdict": Verdict.SUSPICIOUS,
        "risk": 48,
        "mitre": ["T1046"],
        "summary": "Escaneo de puertos automatizado contra el perímetro. El firewall bloqueó el tráfico; correlacionar con intentos posteriores y valorar bloqueo temporal.",
    },
    {
        "title": "Regla de auditoría de prueba",
        "description": "Evento generado por el script de validación interna del SOC. Host de laboratorio y usuario de pruebas.",
        "source": "wazuh",
        "rule_id": "900001",
        "level": 3,
        "source_ip": "10.10.5.12",
        "hostname": "ws-dev-03",
        "username": "tester",
        "severity": Severity.LOW,
        "verdict": Verdict.FALSE_POSITIVE,
        "risk": 18,
        "mitre": [],
        "summary": "Evento de prueba interna del SOC. No representa una amenaza; se recomienda excluir el host de laboratorio y ajustar la regla para evitar ruido.",
        "fp_reason": "Script de validación interna sobre host de laboratorio.",
    },
    {
        "title": "Inicios de sesión fallidos en aplicación interna",
        "description": "Un usuario olvidó su contraseña y generó 6 intentos fallidos en la aplicación de RRHH.",
        "source": "wazuh",
        "rule_id": "100901",
        "level": 5,
        "source_ip": "10.10.3.71",
        "hostname": "ws-rrhh-07",
        "username": "mrivas",
        "severity": Severity.LOW,
        "verdict": Verdict.FALSE_POSITIVE,
        "risk": 22,
        "mitre": [],
        "summary": "Fallos de autenticación compatibles con error de contraseña del usuario. Se validó con mesa de ayuda y no hay indicios de ataque.",
        "fp_reason": "Error de contraseña confirmado por mesa de ayuda.",
    },
    {
        "title": "Cambio de configuración en firewall",
        "description": "Se modificó una regla NAT en fw-edge01. El cambio cuenta con ticket CHG-2026-0412.",
        "source": "opnsense",
        "rule_id": "OPN-CFG-003",
        "level": 4,
        "source_ip": "10.10.0.1",
        "hostname": "fw-edge01",
        "username": "netadmin",
        "severity": Severity.LOW,
        "verdict": Verdict.BENIGN,
        "risk": 24,
        "mitre": [],
        "summary": "Cambio de configuración autorizado y asociado a un ticket. Se recomienda conservar la evidencia y cerrar la alerta.",
    },
    {
        "title": "Beaconing a dominio sospechoso",
        "description": "Se observan conexiones DNS periódicas a un dominio recién registrado desde el servidor de respaldo.",
        "source": "wazuh",
        "rule_id": "100955",
        "level": 10,
        "source_ip": "10.10.1.30",
        "hostname": "srv-backup01",
        "username": "svc_backup",
        "severity": Severity.HIGH,
        "verdict": Verdict.TRUE_POSITIVE,
        "risk": 83,
        "mitre": ["T1071", "T1568"],
        "summary": "Consultas DNS periódicas a un dominio de reciente creación desde el servidor de respaldo. Patrón compatible con beaconing; aislar y revisar tareas programadas.",
    },
    {
        "title": "Acceso a recurso compartido con credenciales de servicio",
        "description": "La cuenta svc_backup accede a un recurso compartido de RRHH fuera de su alcance habitual.",
        "source": "wazuh",
        "rule_id": "100988",
        "level": 8,
        "source_ip": "10.10.1.30",
        "hostname": "srv-backup01",
        "username": "svc_backup",
        "severity": Severity.MEDIUM,
        "verdict": Verdict.SUSPICIOUS,
        "risk": 64,
        "mitre": ["T1078", "T1021"],
        "summary": "Acceso a un recurso fuera del ámbito de la cuenta de servicio. Validar la tarea de respaldo y revisar permisos excesivos.",
    },
]

TRIAGE_ACTIONS = {
    "critical": [
        {"priority": 1, "action": "Aislar el activo y preservar evidencia volátil.", "owner": "SOC L2", "sla_minutes": 15, "type": "containment"},
        {"priority": 2, "action": "Bloquear indicadores en firewall, proxy y DNS.", "owner": "Infraestructura", "sla_minutes": 20, "type": "containment"},
        {"priority": 3, "action": "Abrir incidente y activar el plan de respuesta.", "owner": "SOC Lead", "sla_minutes": 30, "type": "escalation"},
    ],
    "high": [
        {"priority": 1, "action": "Validar la actividad con logs de EDR, firewall y autenticación.", "owner": "SOC L1", "sla_minutes": 30, "type": "validation"},
        {"priority": 2, "action": "Bloquear el origen y recolectar evidencia.", "owner": "SOC L2", "sla_minutes": 45, "type": "containment"},
        {"priority": 3, "action": "Escalar a incidente si se confirma.", "owner": "SOC Lead", "sla_minutes": 60, "type": "escalation"},
    ],
    "medium": [
        {"priority": 1, "action": "Revisar contexto del activo y línea de tiempo.", "owner": "SOC L1", "sla_minutes": 60, "type": "validation"},
        {"priority": 2, "action": "Contactar al usuario o equipo responsable.", "owner": "SOC L1", "sla_minutes": 90, "type": "validation"},
    ],
    "low": [
        {"priority": 1, "action": "Documentar y cerrar si no hay indicios maliciosos.", "owner": "SOC L1", "sla_minutes": 120, "type": "closure"},
    ],
}


def _get_or_create_permissions(db: Session) -> dict[str, Permission]:
    existing = {permission.code: permission for permission in db.scalars(select(Permission)).all()}
    for code, module, description in PERMISSIONS:
        if code not in existing:
            permission = Permission(code=code, module=module, description=description)
            db.add(permission)
            existing[code] = permission
    db.flush()
    return existing


def _get_or_create_roles(db: Session, permissions: dict[str, Permission]) -> dict[str, Role]:
    existing = {role.name: role for role in db.scalars(select(Role)).all()}
    for name, config in ROLES.items():
        role = existing.get(name)
        if role is None:
            role = Role(name=name, description=config["description"], color=config["color"], is_system=config["is_system"])
            db.add(role)
            existing[name] = role
        role.description = config["description"]
        role.color = config["color"]
        role.permissions = [permissions[code] for code in config["permissions"]]
    db.flush()
    return existing


def _get_or_create_users(db: Session, roles: dict[str, Role]) -> dict[str, User]:
    existing = {user.email: user for user in db.scalars(select(User)).all()}
    for item in USERS:
        if item["email"] in existing:
            continue
        user = User(
            email=item["email"],
            full_name=item["full_name"],
            hashed_password=hash_password(item["password"]),
            role_id=roles[item["role"]].id,
            is_active=True,
            job_title=item["job_title"],
            department=item["department"],
            phone=item["phone"],
        )
        db.add(user)
        existing[item["email"]] = user
    db.flush()
    return existing


def _get_or_create_assets(db: Session) -> dict[str, Asset]:
    existing = {asset.hostname: asset for asset in db.scalars(select(Asset)).all()}
    for hostname, ip, criticality, owner, environment, os_name, tags in ASSETS:
        if hostname in existing:
            continue
        asset = Asset(
            hostname=hostname,
            ip_address=ip,
            criticality=criticality,
            owner=owner,
            environment=environment,
            operating_system=os_name,
            tags=tags,
        )
        db.add(asset)
        existing[hostname] = asset
    db.flush()
    return existing


def _seed_alerts(db: Session, users: dict[str, User], assets: dict[str, Asset]) -> None:
    if db.scalar(select(func.count(Alert.id))) > 0:
        return

    rng = random.Random(2026)
    analyst = users["analista@soclite.local"]
    now = datetime.now(timezone.utc)

    # 36 alertas: dos ciclos de 18 plantillas con fechas e identificadores distintos.
    sequence = 0
    for cycle in range(2):
        for template in TEMPLATES:
            sequence += 1
            days_ago = 20 - (sequence % 20)
            received = (now - timedelta(days=days_ago, hours=rng.randint(0, 12), minutes=rng.randint(0, 59))).replace(second=0, microsecond=0)
            hostname = template["hostname"]
            asset = assets.get(hostname)
            external_id = f"wazuh-{template['rule_id']}-{2026000 + sequence}"
            status: AlertStatus
            triage: TriageResult | None = None
            incident: Incident | None = None

            if sequence in {7, 18, 29}:
                status = AlertStatus.PENDING
            elif sequence in {3, 14, 27}:
                status = AlertStatus.ESCALATED
            else:
                status = AlertStatus.TRIAGED

            if sequence in {16, 17}:
                status = AlertStatus.FALSE_POSITIVE
            if sequence == 35:
                status = AlertStatus.CLOSED

            alert = Alert(
                external_id=external_id,
                fingerprint=fingerprint_for(
                    template["source"],
                    external_id,
                    template["title"],
                    template["source_ip"],
                    hostname,
                    received,
                ),
                source=template["source"],
                title=template["title"],
                description=template["description"],
                rule_id=template["rule_id"],
                rule_level=template["level"],
                severity=template["severity"],
                status=status,
                source_ip=template["source_ip"],
                destination_ip=asset.ip_address if asset else None,
                hostname=hostname,
                agent_name=hostname,
                username=template["username"],
                asset_id=asset.id if asset else None,
                assigned_to_id=analyst.id if status in {AlertStatus.TRIAGED, AlertStatus.ESCALATED} else None,
                mitre_techniques=template["mitre"],
                tags=[template["source"]],
                raw_payload={
                    "id": external_id,
                    "timestamp": received.isoformat(),
                    "rule": {"id": template["rule_id"], "level": template["level"], "description": template["title"]},
                    "agent": {"name": hostname},
                    "data": {"srcip": template["source_ip"], "dstuser": template["username"]},
                    "full_log": template["description"],
                },
                received_at=received,
                first_seen_at=received,
                last_seen_at=received + timedelta(minutes=rng.randint(1, 6)),
                closed_at=received + timedelta(hours=4) if status == AlertStatus.CLOSED else None,
            )
            db.add(alert)
            db.flush()

            if status != AlertStatus.PENDING:
                triaged_at = received + timedelta(minutes=rng.randint(1, 9))
                verdict = template["verdict"]
                confidence = round(rng.uniform(0.72, 0.96), 2)
                if status == AlertStatus.FALSE_POSITIVE:
                    verdict = Verdict.FALSE_POSITIVE
                    confidence = 0.9
                triage = TriageResult(
                    alert_id=alert.id,
                    verdict=verdict,
                    recommended_severity=template["severity"],
                    confidence=confidence,
                    risk_score=template["risk"],
                    summary=template["summary"],
                    reasoning=(
                        f"Regla {template['rule_id']} de nivel {template['level']} sobre "
                        f"{hostname}; activo con criticidad {asset.criticality.value if asset else 'desconocida'}. "
                        f"Se correlacionan {len(template['mitre']) + 2} señales y reputación de {template['source_ip']}."
                    ),
                    recommended_actions=TRIAGE_ACTIONS.get(template["severity"].value, TRIAGE_ACTIONS["medium"]),
                    mitre_techniques=template["mitre"],
                    should_escalate=template["severity"] in {Severity.CRITICAL, Severity.HIGH} and verdict != Verdict.FALSE_POSITIVE,
                    false_positive_reason=template.get("fp_reason"),
                    engine="langchain" if sequence % 3 else "heuristic-local",
                    model_name="llama3.1:8b" if sequence % 3 else "soc-lite-rules-v1",
                    prompt_version="triage-v1",
                    latency_ms=rng.randint(950, 5200),
                    tokens_used=rng.randint(420, 1300) if sequence % 3 else 0,
                    raw_response={"seed": True, "cycle": cycle},
                    created_at=triaged_at,
                )
                db.add(triage)

                if template["source_ip"] and not template["source_ip"].startswith("10."):
                    db.add(
                        EnrichmentData(
                            alert_id=alert.id,
                            provider="VirusTotal",
                            indicator=template["source_ip"],
                            indicator_type="ip",
                            status="ok",
                            risk_score=float(min(100, template["risk"] + 4)),
                            summary=f"{rng.randint(8, 24)} motores detectan la IP como maliciosa.",
                            payload={"malicious": rng.randint(8, 24), "suspicious": rng.randint(1, 6), "country": "NL"},
                            fetched_at=triaged_at,
                        )
                    )
                    db.add(
                        EnrichmentData(
                            alert_id=alert.id,
                            provider="AbuseIPDB",
                            indicator=template["source_ip"],
                            indicator_type="ip",
                            status="ok",
                            risk_score=float(min(100, template["risk"] - 3)),
                            summary=f"Confianza de abuso {min(100, template['risk'])}% en los últimos 90 días.",
                            payload={"abuse_confidence": min(100, template["risk"]), "reports": rng.randint(3, 40)},
                            fetched_at=triaged_at,
                        )
                    )

            if status == AlertStatus.ESCALATED:
                code_number = 100 + sequence
                opened = received + timedelta(minutes=rng.randint(8, 20))
                incident_status = [IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED, IncidentStatus.OPEN][sequence % 3]
                incident = Incident(
                    code=f"INC-2026-{code_number:04d}",
                    alert_id=alert.id,
                    title=f"Investigación: {template['title']}",
                    description=template["description"],
                    severity=template["severity"],
                    status=incident_status,
                    owner_id=users["supervisor@soclite.local"].id,
                    containment_actions="Aislamiento del host y bloqueo de indicadores en el perímetro.",
                    ticket_external_id=f"OST-{5000 + sequence}",
                    sla_due_at=opened + timedelta(hours=4 if template["severity"] == Severity.CRITICAL else 8),
                    opened_at=opened,
                    closed_at=None,
                )
                db.add(incident)

    db.commit()

    # Incidentes históricos cerrados para calcular MTTR/SLA.
    closed_samples = [
        ("INC-2025-0098", "Contención de malware en estación de trabajo", Severity.HIGH, 5.2, 8),
        ("INC-2025-0102", "Bloqueo de campaña de phishing", Severity.MEDIUM, 3.1, 8),
        ("INC-2025-0114", "Acceso no autorizado a VPN", Severity.HIGH, 6.4, 4),
        ("INC-2025-0121", "Fuerza bruta contra servidor web", Severity.MEDIUM, 2.5, 8),
        ("INC-2025-0130", "Exfiltración contenida en base de datos", Severity.CRITICAL, 7.8, 4),
        ("INC-2026-0201", "Contención de beaconing en servidor de respaldo", Severity.HIGH, 1.8, 8),
        ("INC-2026-0202", "Phishing contenido y credenciales rotadas", Severity.MEDIUM, 2.2, 8),
    ]
    for code, title, severity, hours, sla_hours in closed_samples:
        if code.startswith("INC-2026"):
            opened = now - timedelta(days=rng.randint(2, 9), hours=rng.randint(0, 12))
        else:
            opened = now - timedelta(days=rng.randint(25, 70), hours=rng.randint(0, 12))
        closed = opened + timedelta(hours=hours)
        db.add(
            Incident(
                code=code,
                title=title,
                description="Incidente cerrado con evidencia y lecciones aprendidas.",
                severity=severity,
                status=IncidentStatus.CLOSED,
                owner_id=users["supervisor@soclite.local"].id,
                containment_actions="Contención validada; se aplicaron reglas de detección.",
                ticket_external_id=f"OST-{code[-4:]}",
                sla_due_at=opened + timedelta(hours=sla_hours),
                opened_at=opened,
                closed_at=closed,
            )
        )
    db.commit()


def _seed_audit(db: Session, users: dict[str, User]) -> None:
    if db.scalar(select(func.count(AuditLog.id))) > 0:
        return
    now = datetime.now(timezone.utc)
    events = [
        ("admin@soclite.local", "auth", "LOGIN", "Inicio de sesión exitoso", "IN"),
        ("admin@soclite.local", "dashboard", "MODULE_ENTER", "Ingreso al módulo Dashboard", "IN"),
        ("admin@soclite.local", "dashboard", "MODULE_EXIT", "Salida del módulo Dashboard", "OUT"),
        ("analista@soclite.local", "auth", "LOGIN", "Inicio de sesión exitoso", "IN"),
        ("analista@soclite.local", "alerts", "MODULE_ENTER", "Ingreso al módulo Alertas", "IN"),
        ("analista@soclite.local", "alerts", "TRIAGE", "Triaje automático de alerta", None),
        ("analista@soclite.local", "alerts", "UPDATE", "Clasificación como falso positivo", None),
        ("analista@soclite.local", "alerts", "MODULE_EXIT", "Salida del módulo Alertas", "OUT"),
        ("supervisor@soclite.local", "auth", "LOGIN", "Inicio de sesión exitoso", "IN"),
        ("supervisor@soclite.local", "incidents", "MODULE_ENTER", "Ingreso al módulo Incidentes", "IN"),
        ("supervisor@soclite.local", "incidents", "CREATE", "Escalamiento de alerta a incidente", None),
        ("supervisor@soclite.local", "reports", "EXPORT", "Generación de reporte de gestión en PDF", None),
        ("supervisor@soclite.local", "auth", "LOGOUT", "Cierre de sesión", "OUT"),
        ("auditor@soclite.local", "auth", "LOGIN", "Inicio de sesión exitoso", "IN"),
        ("auditor@soclite.local", "audit", "MODULE_ENTER", "Ingreso al módulo Auditoría", "IN"),
        ("auditor@soclite.local", "audit", "EXPORT", "Descarga de bitácora de auditoría", None),
        ("auditor@soclite.local", "auth", "LOGOUT", "Cierre de sesión", "OUT"),
    ]
    for index, (email, module, event_type, action, direction) in enumerate(events):
        user = users.get(email)
        created = now - timedelta(days=5, hours=index * 2)
        db.add(
            AuditLog(
                user_id=user.id if user else None,
                actor_email=email,
                actor_role=user.role.name if user else "",
                event_type=event_type,
                module=module,
                action=action,
                direction=direction,
                description=action,
                ip_address="10.10.0.25",
                user_agent="Mozilla/5.0 (SOC-Lite seed)",
                request_id=uuid.uuid4().hex,
                created_at=created,
            )
        )

    # Timeline de ejemplo sobre la alerta más reciente, para que el detalle
    # muestre trazabilidad desde el primer arranque.
    alert = db.scalar(select(Alert).order_by(Alert.received_at.desc()))
    if alert:
        analyst = users.get("analista@soclite.local")
        base_time = alert.received_at + timedelta(minutes=2)
        for offset, event_type, action in (
            (0, "TRIAGE", "Triaje automático ejecutado"),
            (3, "UPDATE", "Alerta asignada al analista de turno"),
            (5, "MODULE_ENTER", "Ingreso al módulo Alertas"),
        ):
            db.add(
                AuditLog(
                    user_id=analyst.id if analyst else None,
                    actor_email=analyst.email if analyst else "sistema",
                    actor_role=analyst.role.name if analyst else "",
                    event_type=event_type,
                    module="alerts",
                    action=action,
                    direction="IN" if event_type == "MODULE_ENTER" else None,
                    entity_type="alert",
                    entity_id=str(alert.id),
                    description=action,
                    ip_address="10.10.0.25",
                    request_id=uuid.uuid4().hex,
                    created_at=base_time + timedelta(minutes=offset),
                )
            )
    db.commit()


def seed_database(db: Session, *, reset: bool = False) -> dict[str, int]:
    if reset:
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)
    else:
        init_db()

    permissions = _get_or_create_permissions(db)
    roles = _get_or_create_roles(db, permissions)
    users = _get_or_create_users(db, roles)
    assets = _get_or_create_assets(db)
    db.commit()
    _seed_alerts(db, users, assets)
    _seed_audit(db, users)

    return {
        "permissions": db.scalar(select(func.count(Permission.id))) or 0,
        "roles": db.scalar(select(func.count(Role.id))) or 0,
        "users": db.scalar(select(func.count(User.id))) or 0,
        "assets": db.scalar(select(func.count(Asset.id))) or 0,
        "alerts": db.scalar(select(func.count(Alert.id))) or 0,
        "triages": db.scalar(select(func.count(TriageResult.id))) or 0,
        "incidents": db.scalar(select(func.count(Incident.id))) or 0,
        "audit_events": db.scalar(select(func.count(AuditLog.id))) or 0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Carga los datos semilla de SOC-Lite")
    parser.add_argument("--reset", action="store_true", help="Elimina el esquema y lo recrea")
    args = parser.parse_args()
    with SessionLocal() as db:
        stats = seed_database(db, reset=args.reset)
    print("SOC-Lite · datos semilla cargados")
    for key, value in stats.items():
        print(f"  {key:14s} {value}")


if __name__ == "__main__":
    main()
