# SOC-Lite
## Plataforma de triaje automático de alertas SOC con orquestación low-code, enriquecimiento contextual y razonamiento LLM

**Caso de uso:** Triaje automático de alertas SOC (“SOC-Lite”)  
**Documento:** arquitectura, modelo de datos, backend, frontend, workflow n8n, datasets y stack  
**Versión:** 1.0.0  
**Fecha:** 19 de octubre de 2026  
**Audiencia:** arquitectura de soluciones, CISO, equipo SOC, desarrollo y auditoría  
**Clasificación:** uso interno / académico

---

## 0. Resumen ejecutivo

SOC-Lite es una aplicación de ciberseguridad orientada a PYMEs, empresas medianas y organismos públicos que necesitan reducir la fatiga de alertas sin adquirir un SOAR comercial. La solución recibe eventos de Wazuh y OPNsense, los normaliza, elimina duplicados, los enriquece con herramientas de reputación y contexto de activos, y utiliza un agente LangChain con un LLM local para producir un veredicto, una severidad recomendada, un resumen ejecutivo y un plan de acciones priorizado. Todo el proceso queda trazado en una bitácora de auditoría y es visible en un dashboard con reportes exportables en PDF, Word y Excel.

La arquitectura separa responsabilidades de forma deliberada:

- **n8n** actúa como pegamento de integración y orquestador del flujo: webhook, normalización, idempotencia, enrutamiento, notificaciones, tickets y auditoría.
- **LangChain**, expuesto mediante un microservicio FastAPI, encapsula el razonamiento, las herramientas personalizadas, la memoria de incidentes y el control de prompts.
- **FastAPI** es el sistema de registro y la API del producto: autenticación, RBAC, alertas, incidentes, métricas, reportes y administratración.
- **PostgreSQL** es la fuente única de verdad operativa.
- **React + TypeScript** entrega una consola de operación oscura, responsive y orientada a decisiones.
- **Ollama** permite ejecutar el modelo en la red de la organización, evitando enviar alertas a APIs externas por defecto.

El resultado es una solución que puede iniciar en un único servidor con Docker Compose y escalar a una arquitectura distribuida con workers, base de datos gestionada y modelo local dedicado.

### 0.1 Qué se entrega

| Artefacto | Ubicación | Estado |
|---|---|---|
| Documento de arquitectura y diseño | `docs/ARQUITECTURA_SOC_LITE.md` | Completo |
| API FastAPI con RBAC, auditoría, métricas y reportes | `backend/` | Implementado y probado |
| Microservicio LangChain con herramientas y fallback | `ai-service/` | Implementado y probado en modo heurístico |
| Esquema PostgreSQL y datos semilla | `db/init/01_schema.sql`, `db/init/02_seed.sql` | Verificado en PostgreSQL 17 |
| Workflow n8n importable | `n8n/soc-lite-triage-workflow.json` | Importado correctamente en n8n 1.111.1 |
| Frontend React | `frontend/` | Compilado (`tsc` + Vite) |
| Pruebas de integración | `backend/tests/test_api.py` | 9 pruebas OK |
| Despliegue con Docker | `docker-compose.yml`, Dockerfiles, nginx | Listo para ejecutar |
| Capturas de interfaz | `docs/screenshots/` | Generadas con navegador headless |

### 0.2 Cobertura de requisitos obligatorios

| Requisito | Implementación | Evidencia |
|---|---|---|
| Stack backend y frontend justificado | FastAPI + SQLAlchemy + React + TypeScript + Vite | Sección 7 y `backend/`, `frontend/` |
| PostgreSQL como BD principal | 12 tablas, JSONB, índices, FK, constraints | `db/init/01_schema.sql` |
| Dashboard con métricas e indicadores | KPIs, tendencia, severidad, MITRE, top IPs, SLA | `frontend/src/pages/DashboardPage.tsx` |
| Reportes PDF, Word y Excel | ReportLab, python-docx, openpyxl | `backend/app/services/reports.py` |
| Usuarios, roles y perfiles (RBAC) | 5 roles, 16 permisos, matriz de acceso | `backend/app/api/routes_admin.py` |
| Bitácora con usuario, fecha, hora y acción | `audit_log` + middleware + eventos IN/OUT | `backend/app/main.py`, `routes_audit.py` |

---

## 1. Arquitectura del sistema

### 1.1 Principios de diseño

1. **On-premise primero.** El flujo crítico debe funcionar sin dependencia de SaaS. Ollama es el proveedor por defecto; OpenAI es una opción explícita.
2. **PostgreSQL como fuente única de verdad.** n8n no mantiene estado propio del negocio; solo orquesta. Las tablas `alerts`, `triage_results`, `incidents` y `audit_log` son la referencia.
3. **Idempotencia en la ingesta.** Cada alerta tiene una huella (`fingerprint`) única con ventana temporal; los reintentos de n8n o del SIEM no generan duplicados.
4. **Auditoría por diseño.** Los accesos, entradas/salidas por módulo, triajes, cambios, exportaciones y descargas se registran con actor, rol, fecha/hora, acción, IP y resultado.
5. **RBAC de mínimo privilegio.** Los roles `viewer`, `auditor`, `analyst`, `supervisor` y `admin` separan consulta, auditoría, operación y administración.
6. **Degradación controlada.** Si el LLM o el microservicio no están disponibles, el backend aplica un motor heurístico explicable; la alerta no se pierde.
7. **Explicabilidad.** El triaje devuelve razonamiento, confianza, riesgo y acciones; no solo una etiqueta.
8. **Portabilidad.** Docker Compose permite levantar todo el stack en una PYME; los mismos contenedores se despliegan en un clúster mediano.

### 1.2 Vista de contexto

```mermaid
flowchart LR
    subgraph Fuentes["Fuentes de telemetría"]
        W["Wazuh<br/>reglas y eventos"]
        O["OPNsense<br/>firewall / IDS / WAF"]
        M["Carga manual<br/>dashboard"]
    end

    subgraph Orquestacion["Orquestación low-code"]
        N["n8n<br/>webhook, normalización,<br/>idempotencia, routing"]
    end

    subgraph IA["Plano de inteligencia"]
        A["Microservicio LangChain<br/>FastAPI :8001"]
        L["Ollama<br/>llama3.1 / mistral"]
        T["Herramientas<br/>VirusTotal · AbuseIPDB<br/>GeoIP · MITRE · CMDB"]
    end

    subgraph Producto["Plano de producto"]
        B["FastAPI SOC-Lite<br/>:8000"]
        F["React + Vite<br/>:5173 / :8080"]
        P[("PostgreSQL<br/>:5432")]
    end

    subgraph Salidas["Respuesta"]
        S["Slack / Telegram"]
        K["osTicket / Redmine"]
        R["Reportes<br/>PDF · DOCX · XLSX"]
    end

    W --> N
    O --> N
    M --> B
    N -->|"POST /triage"| A
    A --> L
    A --> T
    N -->|"INSERT / UPDATE"| P
    B -->|"SQLAlchemy"| P
    F -->|"REST /api/v1"| B
    B -->|"POST /triage"| A
    N --> S
    N --> K
    B --> R
```

**Decisión clave:** n8n es el orquestador de producción, pero FastAPI también puede ejecutar el triaje de forma autónoma (`POST /alerts/{id}/triage`) para escenarios de demo, pruebas y operación sin n8n. Ambos caminos persisten en el mismo modelo y pasan por la misma capa de auditoría.

### 1.3 Capas

| Capa | Componentes | Responsabilidad |
|---|---|---|
| Presentación | React 19, TypeScript, Vite, Tailwind, React Router, TanStack Query | Dashboard, cola de alertas, detalle, incidentes, reportes, administración y auditoría. |
| Lógica de negocio | FastAPI, SQLAlchemy 2.0, servicios de triaje, métricas y reportes | Contratos REST, RBAC, reglas de negocio, orquestación del triaje y generación de documentos. |
| Orquestación | n8n | Integración con Wazuh/OPNsense, reintentos, enrutamiento, notificaciones y tickets. |
| Inteligencia | LangChain + Ollama/OpenAI + herramientas | Enriquecimiento, clasificación, resumen, acciones y MITRE. |
| Datos | PostgreSQL 16+ | Persistencia transaccional, JSONB para evidencia, índices para consultas operativas. |
| Infraestructura | Docker, nginx, volúmenes, healthchecks | Despliegue reproducible, proxy inverso, persistencia y disponibilidad. |

### 1.4 Componentes y puertos

| Componente | Puerto | Exposure | Función |
|---|---|---|---|
| `frontend` | 5173 dev / 8080 prod | Usuarios | SPA y proxy `/api`. |
| `backend` | 8000 | API interna / proxy | API REST, RBAC, reportes, auditoría. |
| `ai-service` | 8001 | Solo red interna | Triaje LangChain; no se publica a Internet. |
| `db` | 5432 | Solo red interna / localhost | PostgreSQL. |
| `n8n` | 5678 | Solo localhost por defecto | Orquestación incluida en Compose; usa `n8n-db` para sus datos internos y accede a `db` y `ai-service` por la red Docker. |
| `ollama` | 11434 | Solo red interna | Inferencia local; perfil opcional `llm`. |

### 1.5 Flujo de ingesta y triaje

```mermaid
sequenceDiagram
    autonumber
    participant W as Wazuh/OPNsense
    participant N as n8n
    participant DB as PostgreSQL
    participant AI as LangChain
    participant O as Ollama/APIs
    participant S as Slack/osTicket
    participant API as FastAPI
    participant UI as Dashboard

    W->>N: POST /webhook/soc-lite-alert
    N->>N: Normalizar + fingerprint (5 min)
    alt severidad < media o payload inválido
        N-->>W: 200 (descartado)
    else severidad >= media
        N->>DB: INSERT alerts ... ON CONFLICT DO NOTHING
        alt duplicado
            DB-->>N: 0 filas
        else nueva
            DB-->>N: id
            N->>AI: POST /triage (alerta + contexto)
            AI->>O: consultas de reputación / LLM
            O-->>AI: señales
            AI-->>N: veredicto, riesgo, acciones
            N->>DB: INSERT triage_results + enrichment_data
            N->>DB: UPDATE alerts status='triaged'
            alt critical/high
                N->>S: notificar y crear ticket
            end
            N->>DB: INSERT audit_log
        end
    end
    UI->>API: GET /dashboard/overview
    API->>DB: consultas agregadas
    DB-->>API: KPIs
    API-->>UI: JSON
```

### 1.6 Modos de despliegue

| Modo | Escenario | Componentes | Consideraciones |
|---|---|---|---|
| **Todo en uno** | PYME, laboratorio, demo | Docker Compose: db + n8n-db + n8n + ai + backend + frontend (+ Ollama opcional) | 4 vCPU / 16 GB RAM; un solo host; backup diario de ambas bases y del volumen n8n. |
| **Distribuido** | Empresa mediana | PostgreSQL gestionado, 2+ workers FastAPI, AI en host GPU, n8n HA, nginx | Cola/Redis para rate limit y locks; balanceador; observabilidad. |
| **Aislado (air-gapped)** | Organismo público / defensa | Todos los contenedores y modelo descargado offline | Sin claves externas; enriquecimiento limitado a CMDB/MITRE; actualización por bundle firmado. |

```mermaid
flowchart TB
    subgraph DMZ["DMZ"]
        NG["nginx / WAF"]
        FE["Frontend estático"]
    end
    subgraph APP["Red de aplicación"]
        API1["FastAPI worker 1"]
        API2["FastAPI worker 2"]
        N8N["n8n"]
        AI["LangChain"]
    end
    subgraph DATA["Red de datos"]
        PG[("PostgreSQL primario")]
        PGR[("Réplica lectura")]
        OLL["Ollama / GPU"]
        BK["Backup cifrado"]
    end
    U["Usuarios SOC"] --> NG --> FE
    NG --> API1
    NG --> API2
    API1 --> PG
    API2 --> PG
    API1 --> PGR
    N8N --> PG
    N8N --> AI
    AI --> OLL
    PG --> BK
```

### 1.7 Decisiones de arquitectura (ADR)

| ID | Decisión | Motivo | Trade-off |
|---|---|---|---|
| ADR-001 | n8n para integración y orquestación | Conectores listos para Wazuh, HTTP, Slack, PostgreSQL; reintentos y edición visual; el equipo ya lo domina. | El flujo vive fuera del código; requiere versionar el JSON y credenciales. |
| ADR-002 | LangChain en microservicio FastAPI | Herramientas custom, control de prompts, memoria de incidentes y evaluación; LangFlow es insuficiente para lógica condicional y tests. | Un servicio adicional que operar. |
| ADR-003 | PostgreSQL | ACID, JSONB, índices GIN, madurez, costo y conocimiento del equipo. | Mayor esfuerzo operativo que SQLite; se mitiga con Docker/gestionado. |
| ADR-004 | FastAPI | Tipado Pydantic, OpenAPI, rendimiento, ecosistema Python para IA y reportes. | El equipo debe mantener dos lenguajes (Python/TypeScript). |
| ADR-005 | React + Vite | Componentización, ecosistema, build rápido, curva conocida. | SPA requiere manejo de tokens y RBAC en cliente; el backend siempre valida. |
| ADR-006 | Ollama local por defecto | Privacidad de alertas, costo predecible, funcionamiento offline. | Calidad inferior a modelos frontera; requiere GPU/RAM y ajuste de prompts. |
| ADR-007 | Auditoría en base de datos + middleware | Evidencia centralizada, consultable y exportable; no depende de logs del contenedor. | Volumen de escritura; se controla con índices y retención. |
| ADR-008 | Fallback heurístico | Evita que un fallo del LLM detenga la operación. | Dos motores que mantener; se mitiga con contrato único y pruebas. |

### 1.8 Límites y supuestos

- El SIEM (Wazuh) y el firewall (OPNsense) ya existen y pueden enviar webhooks.
- n8n se ejecuta en la misma red que la API y el microservicio; no se expone a Internet.
- Las claves de VirusTotal/AbuseIPDB son opcionales. Sin ellas, el triaje usa reglas, MITRE y contexto de activo.
- El modelo local recomendado para 16 GB RAM es `llama3.1:8b` cuantizado o `mistral:7b`; para 8 GB, `llama3.2:3b`.
- La primera versión no implementa SSO/MFA ni firma criptográfica por evento; se documentan en el roadmap.

---

## 2. Modelo de datos en PostgreSQL y datos semilla

### 2.1 Principios del modelo

- **UUID** como clave primaria para facilitar integración y evitar colisiones entre nodos.
- **Timestamps con zona horaria** (`TIMESTAMPTZ`) y convención UTC en backend.
- **JSONB** para `raw_payload`, enriquecimiento, acciones, MITRE y detalle de auditoría; permite evolución sin migraciones frecuentes.
- **Enums como VARCHAR + CHECK** (`native_enum=False`) para simplificar migraciones y compatibilidad.
- **Borrado lógico** de usuarios (`is_active`) para preservar la trazabilidad; las tablas operativas no se borran, se cierran.
- **Auditoría append-only** a nivel de aplicación; el rol de base de datos de la API no debería tener `UPDATE/DELETE` sobre `audit_log` en producción.
- **Índices** para las consultas del dashboard: severidad+fecha, estado+fecha, fuente+fecha, IP, hostname y fingerprint.

### 2.2 Diagrama entidad-relación

```mermaid
erDiagram
    ROLES ||--o{ USERS : asigna
    ROLES ||--o{ ROLE_PERMISSIONS : contiene
    PERMISSIONS ||--o{ ROLE_PERMISSIONS : otorga
    USERS ||--o{ REFRESH_TOKENS : emite
    USERS ||--o{ ALERTS : responsable
    USERS ||--o{ INCIDENTS : owner
    USERS ||--o{ REPORTS : genera
    USERS ||--o{ AUDIT_LOG : actor

    ASSETS ||--o{ ALERTS : afecta
    ALERTS ||--o| TRIAGE_RESULTS : triaje
    ALERTS ||--o{ ENRICHMENT_DATA : enriquece
    ALERTS ||--o| INCIDENTS : escala
    ALERTS ||--o{ AUDIT_LOG : entidad

    ROLES {
        uuid id PK
        varchar name UK
        varchar description
        boolean is_system
        varchar color
        timestamptz created_at
    }
    PERMISSIONS {
        uuid id PK
        varchar code UK
        varchar module
        varchar description
    }
    USERS {
        uuid id PK
        varchar email UK
        varchar full_name
        varchar hashed_password
        uuid role_id FK
        boolean is_active
        varchar job_title
        varchar department
        timestamptz last_login_at
    }
    ASSETS {
        uuid id PK
        varchar hostname UK
        varchar ip_address
        varchar criticality
        varchar environment
        varchar owner
        jsonb tags
    }
    ALERTS {
        uuid id PK
        varchar fingerprint UK
        varchar external_id
        varchar source
        varchar title
        int rule_level
        varchar severity
        varchar status
        varchar source_ip
        varchar hostname
        uuid asset_id FK
        uuid assigned_to_id FK
        jsonb raw_payload
        timestamptz received_at
    }
    TRIAGE_RESULTS {
        uuid id PK
        uuid alert_id FK_UK
        varchar verdict
        varchar recommended_severity
        float confidence
        int risk_score
        text summary
        jsonb recommended_actions
        jsonb mitre_techniques
        varchar engine
    }
    ENRICHMENT_DATA {
        uuid id PK
        uuid alert_id FK
        varchar provider
        varchar indicator
        float risk_score
        jsonb payload
    }
    INCIDENTS {
        uuid id PK
        varchar code UK
        uuid alert_id FK_UK
        varchar severity
        varchar status
        uuid owner_id FK
        timestamptz sla_due_at
    }
    AUDIT_LOG {
        uuid id PK
        uuid user_id FK
        varchar actor_email
        varchar event_type
        varchar module
        varchar action
        varchar direction
        varchar entity_id
        inet_like ip_address
        jsonb detail
        timestamptz created_at
    }
    REPORTS {
        uuid id PK
        varchar report_type
        varchar format
        varchar file_name
        int size_bytes
        uuid generated_by_id FK
    }
```

### 2.3 Diccionario de tablas

#### `roles`

| Columna | Tipo | Restricciones | Descripción |
|---|---|---|---|
| `id` | UUID | PK | Identificador. |
| `name` | VARCHAR(50) | UNIQUE, NOT NULL | `admin`, `supervisor`, `analyst`, `auditor`, `viewer`. |
| `description` | VARCHAR(255) | NOT NULL | Propósito del rol. |
| `is_system` | BOOLEAN | NOT NULL | Rol protegido, no editable desde la UI. |
| `color` | VARCHAR(20) | NOT NULL | Color de la etiqueta en el frontend. |
| `created_at`, `updated_at` | TIMESTAMPTZ | NOT NULL | Auditoría temporal. |

#### `permissions`

| Columna | Tipo | Restricciones | Descripción |
|---|---|---|---|
| `id` | UUID | PK | Identificador. |
| `code` | VARCHAR(80) | UNIQUE, NOT NULL | Ej. `alerts:triage`. |
| `module` | VARCHAR(40) | NOT NULL | Agrupación funcional. |
| `description` | VARCHAR(255) | NOT NULL | Texto legible. |

#### `role_permissions`

Tabla puente `(role_id, permission_id)` con PK compuesta y FK `ON DELETE CASCADE`.

#### `users`

| Columna | Tipo | Restricciones | Descripción |
|---|---|---|---|
| `id` | UUID | PK | Identificador. |
| `email` | VARCHAR(255) | UNIQUE, NOT NULL, índice | Login; se normaliza a minúsculas. |
| `full_name` | VARCHAR(150) | NOT NULL | Nombre visible. |
| `hashed_password` | VARCHAR(255) | NOT NULL | bcrypt (coste 12). |
| `role_id` | UUID | FK roles, NOT NULL | Rol efectivo. |
| `is_active` | BOOLEAN | NOT NULL, default true | Baja lógica. |
| `job_title`, `department`, `phone` | VARCHAR | NOT NULL | Perfil organizacional. |
| `last_login_at` | TIMESTAMPTZ | NULL | Último acceso exitoso. |
| `password_changed_at` | TIMESTAMPTZ | NULL | Último cambio de clave. |
| `created_at`, `updated_at` | TIMESTAMPTZ | NOT NULL | Auditoría. |

#### `refresh_tokens`

| Columna | Tipo | Restricciones | Descripción |
|---|---|---|---|
| `id` | UUID | PK | Identificador. |
| `user_id` | UUID | FK users `ON DELETE CASCADE` | Propietario. |
| `jti` | VARCHAR(64) | UNIQUE, índice | Identificador del token para revocación. |
| `expires_at` | TIMESTAMPTZ | NOT NULL | Expiración. |
| `revoked_at` | TIMESTAMPTZ | NULL | Rotación/cierre de sesión. |
| `created_at` | TIMESTAMPTZ | NOT NULL | Emisión. |

#### `assets`

| Columna | Tipo | Restricciones | Descripción |
|---|---|---|---|
| `id` | UUID | PK | Identificador. |
| `hostname` | VARCHAR(150) | UNIQUE, NOT NULL | Nombre del activo. |
| `ip_address` | VARCHAR(45) | NULL, índice | IPv4/IPv6. |
| `criticality` | VARCHAR(8) | CHECK | `critical`, `high`, `medium`, `low`. |
| `owner` | VARCHAR(150) | NOT NULL | Área responsable. |
| `environment` | VARCHAR(60) | NOT NULL | Producción, DMZ, corporativo, etc. |
| `operating_system` | VARCHAR(100) | NOT NULL | SO. |
| `tags` | JSONB | NOT NULL | Etiquetas de inventario. |

#### `alerts`

| Columna | Tipo | Restricciones | Descripción |
|---|---|---|---|
| `id` | UUID | PK | Identificador. |
| `external_id` | VARCHAR(180) | NULL, índice | ID del SIEM/firewall. |
| `fingerprint` | VARCHAR(64) | UNIQUE, NOT NULL, índice | FNV-1a 64 bits + bucket de 5 minutos para deduplicación. |
| `source` | VARCHAR(40) | NOT NULL, índice | `wazuh`, `opnsense`, `manual`, `generic`. |
| `title` | VARCHAR(300) | NOT NULL | Resumen corto. |
| `description` | TEXT | NOT NULL | Evidencia y contexto. |
| `rule_id` | VARCHAR(40) | NULL | Regla de origen. |
| `rule_level` | INT | CHECK 0..15 | Nivel Wazuh/equivalente. |
| `severity` | VARCHAR(8) | CHECK | Severidad normalizada. |
| `status` | VARCHAR(16) | CHECK, índice | `pending`, `triaging`, `triaged`, `escalated`, `false_positive`, `closed`. |
| `source_ip`, `destination_ip` | VARCHAR(45) | NULL, índice en origen | Direcciones. |
| `hostname`, `agent_name`, `username` | VARCHAR | NULL | Contexto. |
| `asset_id` | UUID | FK assets `SET NULL` | Activo inventariado. |
| `assigned_to_id` | UUID | FK users `SET NULL` | Analista responsable. |
| `mitre_techniques` | JSONB | NOT NULL | Técnicas observadas. |
| `tags` | JSONB | NOT NULL | Etiquetas. |
| `raw_payload` | JSONB | NOT NULL | Evento original completo. |
| `received_at` | TIMESTAMPTZ | NOT NULL, índice | Fecha de recepción. |
| `first_seen_at`, `last_seen_at` | TIMESTAMPTZ | NOT NULL | Ventana de correlación. |
| `closed_at` | TIMESTAMPTZ | NULL | Cierre. |

Índices compuestos: `(severity, received_at)`, `(status, received_at)`, `(source, received_at)`. En producción se recomienda añadir un índice GIN sobre `raw_payload` si se consulta por campos internos.

#### `enrichment_data`

| Columna | Tipo | Restricciones | Descripción |
|---|---|---|---|
| `id` | UUID | PK | Identificador. |
| `alert_id` | UUID | FK alerts `CASCADE` | Alerta. |
| `provider` | VARCHAR(40) | NOT NULL | VirusTotal, AbuseIPDB, GeoIP, CMDB. |
| `indicator` | VARCHAR(190) | NOT NULL | IP, dominio, hash. |
| `indicator_type` | VARCHAR(30) | NOT NULL | `ip`, `domain`, `hash`. |
| `status` | VARCHAR(30) | NOT NULL | `ok`, `error`, `skipped`, `disabled`. |
| `risk_score` | DOUBLE | NULL | 0–100. |
| `summary` | VARCHAR(500) | NOT NULL | Lectura humana. |
| `payload` | JSONB | NOT NULL | Respuesta resumida del proveedor. |
| `fetched_at` | TIMESTAMPTZ | NOT NULL | Fecha. |
| `expires_at` | TIMESTAMPTZ | NULL | Cache. |

Restricción única `(alert_id, provider, indicator)` para evitar duplicados en reintentos.

#### `triage_results`

| Columna | Tipo | Restricciones | Descripción |
|---|---|---|---|
| `id` | UUID | PK | Identificador. |
| `alert_id` | UUID | FK alerts `CASCADE`, UNIQUE | Un resultado vigente por alerta. |
| `verdict` | VARCHAR(16) | CHECK | `true_positive`, `false_positive`, `suspicious`, `benign`. |
| `recommended_severity` | VARCHAR(8) | CHECK | Severidad sugerida. |
| `confidence` | DOUBLE | 0..1 | Confianza del motor. |
| `risk_score` | INT | 0..100 | Riesgo compuesto. |
| `summary` | TEXT | NOT NULL | Resumen ejecutivo. |
| `reasoning` | TEXT | NOT NULL | Evidencia y razonamiento. |
| `recommended_actions` | JSONB | NOT NULL | Lista de acciones priorizadas. |
| `mitre_techniques` | JSONB | NOT NULL | Técnicas. |
| `should_escalate` | BOOLEAN | NOT NULL | Recomendación de escalamiento. |
| `false_positive_reason` | TEXT | NULL | Motivo de descarte. |
| `engine` | VARCHAR(40) | NOT NULL | `langchain`, `heuristic-local`, `heuristic-fallback`. |
| `model_name`, `prompt_version` | VARCHAR | NOT NULL | Reproducibilidad. |
| `latency_ms`, `tokens_used` | INT | NOT NULL | Coste/observabilidad. |
| `raw_response` | JSONB | NOT NULL | Respuesta cruda para auditoría. |
| `created_at` | TIMESTAMPTZ | NOT NULL, índice | Fecha. |

#### `incidents`

| Columna | Tipo | Restricciones | Descripción |
|---|---|---|---|
| `id` | UUID | PK | Identificador. |
| `code` | VARCHAR(30) | UNIQUE | `INC-2026-0001`. |
| `alert_id` | UUID | FK alerts `SET NULL`, UNIQUE | Alerta origen. |
| `title`, `description` | VARCHAR/TEXT | NOT NULL | Caso. |
| `severity` | VARCHAR(8) | CHECK | Severidad. |
| `status` | VARCHAR(16) | CHECK | `open`, `investigating`, `contained`, `resolved`, `closed`. |
| `owner_id` | UUID | FK users `SET NULL` | Responsable. |
| `containment_actions` | TEXT | NOT NULL | Acciones ejecutadas. |
| `ticket_external_id` | VARCHAR(80) | NULL | osTicket/Redmine. |
| `sla_due_at` | TIMESTAMPTZ | NULL | Vencimiento. |
| `opened_at`, `closed_at` | TIMESTAMPTZ | NOT NULL/NULL | Fechas. |

#### `audit_log`

| Columna | Tipo | Restricciones | Descripción |
|---|---|---|---|
| `id` | UUID | PK | Identificador. |
| `user_id` | UUID | FK users `SET NULL` | Actor; se conserva el email aunque se borre el usuario. |
| `actor_email` | VARCHAR(255) | NOT NULL | Snapshot del actor. |
| `actor_role` | VARCHAR(50) | NOT NULL | Rol en el momento. |
| `event_type` | VARCHAR(40) | NOT NULL, índice | `LOGIN`, `LOGOUT`, `MODULE_ENTER`, `MODULE_EXIT`, `API_ACCESS`, `TRIAGE`, `EXPORT`, `DOWNLOAD`, etc. |
| `module` | VARCHAR(40) | NOT NULL, índice | `auth`, `dashboard`, `alerts`, `incidents`, `reports`, `users`, `audit`. |
| `action` | VARCHAR(160) | NOT NULL | Acción legible. |
| `direction` | VARCHAR(8) | CHECK IN/OUT/NULL | Entrada o salida del módulo. |
| `entity_type`, `entity_id` | VARCHAR | NULL | Entidad afectada. |
| `description` | VARCHAR(500) | NOT NULL | Detalle. |
| `method`, `path`, `status_code` | | NULL | Contexto HTTP. |
| `ip_address`, `user_agent` | | NULL | Origen. |
| `request_id` | VARCHAR(64) | índice | Correlación. |
| `detail` | JSONB | NOT NULL | Cambios/contexto. |
| `duration_ms` | INT | NULL | Latencia. |
| `created_at` | TIMESTAMPTZ | NOT NULL, índice | Fecha/hora. |

#### `reports`

| Columna | Tipo | Restricciones | Descripción |
|---|---|---|---|
| `id` | UUID | PK | Identificador. |
| `name` | VARCHAR(200) | NOT NULL | Nombre legible. |
| `report_type` | VARCHAR(16) | CHECK | `operational`, `management`, `audit`. |
| `format` | VARCHAR(8) | CHECK | `pdf`, `docx`, `xlsx`. |
| `period_start`, `period_end` | TIMESTAMPTZ | NOT NULL | Periodo. |
| `filters` | JSONB | NOT NULL | Parámetros. |
| `file_name` | VARCHAR(255) | NOT NULL | Nombre en storage. |
| `size_bytes` | INT | NOT NULL | Tamaño. |
| `generated_by_id` | UUID | FK users `SET NULL` | Autor. |
| `created_at` | TIMESTAMPTZ | NOT NULL | Fecha. |

### 2.4 Datos semilla

El repositorio incluye dos mecanismos idempotentes:

1. **Python**: `python -m app.seed` crea permisos, roles, usuarios, activos, 38 alertas, 35 triajes, 10 incidentes y 20 eventos de auditoría. Es el mecanismo recomendado en desarrollo porque genera fechas relativas al momento de ejecución.
2. **SQL**: `db/init/02_seed.sql` (generado con `pg_dump`) permite inicializar un PostgreSQL sin ejecutar Python. Se ejecuta automáticamente en Docker al crear el volumen.

| Elemento | Cantidad | Detalle |
|---|---|---|
| Permisos | 16 | 7 módulos, acciones de lectura/escritura/exportación. |
| Roles | 5 | admin, supervisor, analyst, auditor, viewer. |
| Usuarios | 5 | Uno por rol; claves demo documentadas abajo. |
| Activos | 12 | Servidores, firewall, VPN, estaciones, Kubernetes. |
| Alertas | 38 | Wazuh/OPNsense, 10 críticas, 12 altas, 10 medias, 6 bajas. |
| Triajes | 35 | Mezcla de verdaderos positivos, sospechosos y falsos positivos. |
| Incidentes | 10 | 3 abiertos/en investigación + 7 cerrados. |
| Auditoría | 20 | Login/logout, entradas/salidas, triaje, exportación. |

**Credenciales demo** (solo `DEMO_MODE=true`):

| Rol | Correo | Contraseña |
|---|---|---|
| Administrador | `admin@soclite.local` | `Admin2026!` |
| Supervisor | `supervisor@soclite.local` | `Supervisor2026!` |
| Analista | `analista@soclite.local` | `Analista2026!` |
| Auditor | `auditor@soclite.local` | `Auditor2026!` |
| Consulta | `consulta@soclite.local` | `Consulta2026!` |

> En producción: `DEMO_MODE=false`, rotar todas las claves, eliminar `02_seed.sql` del init o reemplazarlo por un seed institucional, y desactivar `/meta/demo-accounts`.

### 2.5 Consultas de referencia

```sql
-- Alertas críticas abiertas con su último triaje
SELECT a.id, a.title, a.source, a.source_ip, a.received_at,
       t.verdict, t.risk_score, t.recommended_severity
FROM alerts a
LEFT JOIN triage_results t ON t.alert_id = a.id
WHERE a.severity = 'critical'
  AND a.status IN ('pending', 'triaging', 'triaged', 'escalated')
ORDER BY a.received_at DESC
LIMIT 50;

-- MTTT por día (PostgreSQL)
SELECT date_trunc('day', a.received_at) AS day,
       avg(extract(epoch FROM (t.created_at - a.received_at)) / 60) AS mttt_min
FROM alerts a
JOIN triage_results t ON t.alert_id = a.id
GROUP BY 1
ORDER BY 1 DESC;

-- Entradas y salidas por módulo en las últimas 24 h
SELECT module, direction, count(*)
FROM audit_log
WHERE created_at >= now() - interval '24 hours'
  AND direction IS NOT NULL
GROUP BY module, direction
ORDER BY module, direction;

-- Incidentes con SLA vencido
SELECT code, title, severity, sla_due_at
FROM incidents
WHERE status NOT IN ('resolved', 'closed')
  AND sla_due_at < now()
ORDER BY sla_due_at;
```

### 2.6 Integridad, concurrencia y retención

- **Idempotencia:** `alerts.fingerprint` único; `enrichment_data(alert_id, provider, indicator)` único; `triage_results.alert_id` único; `incidents.alert_id` único.
- **Concurrencia:** dos ejecuciones n8n simultáneas pueden competir por el mismo `fingerprint`; `ON CONFLICT DO NOTHING` evita duplicados y la segunda rama se detiene.
- **Retención sugerida:** alertas y triajes 12 meses; incidentes 24 meses; auditoría 24–60 meses según normativa; reportes 5 años. La política debe aprobarse por el comité de seguridad.
- **Particionamiento futuro:** `alerts` por rango mensual de `received_at` y `audit_log` por mes; índices BRIN para históricos. No es necesario para el volumen inicial (< 1 M alertas/año).
- **Backups:** `pg_dump` diario + WAL archiving; probar restauración trimestral. El volumen `reports` debe incluirse en el backup.

---

## 3. Desarrollo del backend

### 3.1 Estructura

```text
backend/
├── app/
│   ├── main.py                  # FastAPI, CORS, middleware de auditoría, lifespan
│   ├── core/
│   │   ├── config.py            # Settings/.env
│   │   └── security.py          # bcrypt, JWT, utilidades
│   ├── db/session.py            # engine, SessionLocal, get_db
│   ├── models/__init__.py       # SQLAlchemy 2.0 (12 tablas)
│   ├── schemas/__init__.py      # Pydantic v2
│   ├── services/
│   │   ├── normalizer.py        # Wazuh/OPNsense/generic → contrato interno
│   │   ├── triage.py            # remoto + fallback + persistencia
│   │   ├── metrics.py           # KPIs
│   │   ├── reports.py           # PDF/DOCX/XLSX
│   │   └── audit.py             # bitácora
│   ├── api/
│   │   ├── deps.py              # auth, RBAC, paginación, API key
│   │   ├── routes_auth.py
│   │   ├── routes_alerts.py
│   │   ├── routes_incidents.py
│   │   ├── routes_dashboard.py
│   │   ├── routes_reports.py
│   │   ├── routes_admin.py
│   │   ├── routes_audit.py
│   │   ├── routes_ingest.py
│   │   └── routes_meta.py
│   └── seed.py                  # datos demo idempotentes
├── tests/test_api.py
├── requirements.txt
└── Dockerfile
```

### 3.2 Configuración

| Variable | Default | Uso |
|---|---|---|
| `DATABASE_URL` | `postgresql+psycopg://soc_lite:soc_lite@localhost:5432/soc_lite` | Conexión SQLAlchemy. |
| `SECRET_KEY` | valor de desarrollo | Firma JWT; **obligatorio cambiarlo**. |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | 480 | Vida del access token. |
| `REFRESH_TOKEN_EXPIRE_DAYS` | 7 | Vida del refresh token. |
| `AUTO_SEED` | false | Carga semilla al iniciar. |
| `DEMO_MODE` | true | Muestra cuentas demo. |
| `INGEST_API_KEY` | `dev-ingest-key-cambiar` | API key para n8n. |
| `TRIAGE_SERVICE_URL` | `http://localhost:8001` | Microservicio IA. |
| `TRIAGE_API_KEY` | vacío | Header `X-Internal-Key`. |
| `TRIAGE_MODE` | `auto` | `auto`, `remote`, `heuristic`. |
| `CORS_ORIGINS` | localhost:5173 | Orígenes permitidos. |
| `REPORTS_DIR` | `storage/reports` | Archivos generados. |

### 3.3 Autenticación, sesión y RBAC

**Flujo de login**

1. `POST /api/v1/auth/login` con email y contraseña.
2. Se aplica rate limit en memoria por `email + IP`: 5 intentos / 15 minutos (para producción, Redis compartido).
3. Se valida bcrypt (coste 12).
4. Se emite `access_token` JWT (8 h) y `refresh_token` JWT (7 días) con `jti` persistido.
5. Se registra `LOGIN` con dirección `IN` y se actualiza `last_login_at`.
6. El frontend guarda los tokens y renueva con `POST /auth/refresh`; el refresh rota y revoca el anterior.
7. `POST /auth/logout` revoca el refresh y registra `LOGOUT` con dirección `OUT`.

**Claims del token**

```json
{
  "sub": "uuid-del-usuario",
  "email": "analista@soclite.local",
  "role": "analyst",
  "type": "access",
  "jti": "hex",
  "iat": 1792446000,
  "exp": 1792474800
}
```

**Matriz RBAC**

| Permiso | admin | supervisor | analyst | auditor | viewer |
|---|:---:|:---:|:---:|:---:|:---:|
| `dashboard:read` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `alerts:read` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `alerts:create` | ✓ | ✓ | ✓ | | |
| `alerts:update` | ✓ | ✓ | ✓ | | |
| `alerts:triage` | ✓ | ✓ | ✓ | | |
| `alerts:close` | ✓ | ✓ | ✓ | | |
| `incidents:read` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `incidents:create` | ✓ | ✓ | ✓ | | |
| `incidents:update` | ✓ | ✓ | ✓ | | |
| `reports:read` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `reports:export` | ✓ | ✓ | ✓ | ✓ | |
| `users:read` | ✓ | ✓ | | ✓ | |
| `users:manage` | ✓ | | | | |
| `roles:read` | ✓ | ✓ | | ✓ | |
| `audit:read` | ✓ | ✓ | | ✓ | |
| `settings:manage` | ✓ | | | | |

El rol `admin` conserva bypass explícito en `require_permissions`; los demás se evalúan contra la tabla. El frontend oculta acciones, pero **el backend siempre vuelve a validar**.

### 3.4 Endpoints principales

| Método | Ruta | Permiso | Descripción |
|---|---|---|---|
| POST | `/api/v1/auth/login` | público | Login y tokens. |
| POST | `/api/v1/auth/refresh` | refresh | Rotación de tokens. |
| POST | `/api/v1/auth/logout` | autenticado | Cierre y revocación. |
| GET | `/api/v1/auth/me` | autenticado | Perfil. |
| POST | `/api/v1/auth/change-password` | autenticado | Cambio de clave. |
| GET | `/api/v1/dashboard/overview` | `dashboard:read` | KPIs y series. |
| GET | `/api/v1/alerts` | `alerts:read` | Lista filtrada/paginada. |
| GET | `/api/v1/alerts/{id}` | `alerts:read` | Detalle + enriquecimiento. |
| POST | `/api/v1/alerts` | `alerts:create` | Alta manual. |
| PATCH | `/api/v1/alerts/{id}` | `alerts:update` | Estado, severidad, asignación. |
| POST | `/api/v1/alerts/{id}/triage` | `alerts:triage` | Ejecuta triaje. |
| POST | `/api/v1/alerts/{id}/triage-result` | `alerts:triage` | Persiste triaje externo (n8n). |
| POST | `/api/v1/alerts/{id}/escalate` | `incidents:create` | Crea incidente. |
| POST | `/api/v1/alerts/{id}/status` | `alerts:close` | Cierre/descarte con motivo. |
| GET | `/api/v1/alerts/{id}/timeline` | `alerts:read` | Eventos de auditoría. |
| GET | `/api/v1/incidents` | `incidents:read` | Lista. |
| POST | `/api/v1/incidents` | `incidents:create` | Alta. |
| PATCH | `/api/v1/incidents/{id}` | `incidents:update` | Actualización. |
| POST | `/api/v1/incidents/{id}/close` | `incidents:update` | Cierre. |
| GET | `/api/v1/reports` | `reports:read` | Historial. |
| POST | `/api/v1/reports` | `reports:export` | Genera PDF/DOCX/XLSX. |
| GET | `/api/v1/reports/{id}/download` | `reports:read` | Descarga. |
| GET | `/api/v1/users` | `users:read` | Lista. |
| POST | `/api/v1/users` | `users:manage` | Alta. |
| PATCH | `/api/v1/users/{id}` | `users:manage` | Edición. |
| POST | `/api/v1/users/{id}/reset-password` | `users:manage` | Reset. |
| GET | `/api/v1/roles` | `users:read` | Roles + permisos. |
| GET | `/api/v1/audit` | `audit:read` | Bitácora filtrada. |
| POST | `/api/v1/audit/module-event` | autenticado | Entrada/salida de módulo. |
| GET | `/api/v1/audit/stats` | `audit:read` | Agregados. |
| POST | `/api/v1/ingest/alert` | `X-API-Key` | Ingesta n8n. |
| GET | `/api/v1/meta/health` | público | Salud. |
| GET | `/api/v1/meta/catalog` | público | Catálogos UI. |

La especificación completa está en `http://localhost:8000/docs` (OpenAPI 3.1).

### 3.5 Normalización e ingesta

Wazuh y OPNsense tienen esquemas distintos. El normalizador detecta la fuente y construye un contrato único:

| Campo interno | Wazuh | OPNsense | Genérico |
|---|---|---|---|
| `title` | `rule.description` | `event` / `title` | `title` / `message` |
| `rule_id` | `rule.id` | `rule_id` | `rule_id` |
| `rule_level` | `rule.level` (0–15) | `severity`/nivel | `level` |
| `source_ip` | `data.srcip` | `src_ip` | `source_ip` |
| `destination_ip` | `data.dstip` | `dest_ip` | `destination_ip` |
| `hostname` | `agent.name` | `observer.hostname` | `hostname` |
| `username` | `data.dstuser` | `username` | `username` |
| `external_id` | `id` | `event_id` | `alert_id` |
| `received_at` | `timestamp` | `event_time` | ISO |

**Fingerprint:**

```text
FNV-1a 64 bits (source | external_id | título_normalizado | source_ip | hostname | bucket_5_min)
→ 16 hex + "-" + bucket en hex
```

Se usa una ventana de 5 minutos para no perder recurrencias legítimas (por ejemplo, fuerza bruta sostenida) pero evitar duplicados por reintentos. El mismo algoritmo se implementa en Python y en el nodo Code de n8n (BigInt). No es un hash criptográfico: su objetivo es la deduplicación, no la integridad forense. `ON CONFLICT (fingerprint) DO NOTHING` en n8n y `IntegrityError` controlado en la API cierran la carrera.

**Mapeo de severidad:**

| Nivel | Severidad |
|---:|---|
| ≥ 12 | `critical` |
| 9–11 | `high` |
| 6–8 | `medium` |
| 3–5 | `low` |
| 0–2 | `info` |

### 3.6 Motor de triaje

El backend ofrece dos caminos y un fallback:

```text
POST /alerts/{id}/triage
        │
        ├─ TRIAGE_MODE=remote  → microservicio LangChain (falla → 503)
        ├─ TRIAGE_MODE=auto    → microservicio; si falla → heurístico local
        └─ TRIAGE_MODE=heuristic → heurístico local
```

**Contrato del microservicio**

```json
{
  "alert_id": "uuid",
  "source": "wazuh",
  "title": "Fuerza bruta SSH detectada",
  "description": "48 intentos fallidos...",
  "rule_level": 10,
  "severity": "high",
  "source_ip": "203.0.113.45",
  "hostname": "srv-web01",
  "username": "root",
  "asset": {"hostname": "srv-web01", "criticality": "high"},
  "mitre_techniques": [],
  "similar_incidents": []
}
```

**Respuesta**

```json
{
  "verdict": "true_positive",
  "recommended_severity": "high",
  "confidence": 0.82,
  "risk_score": 79,
  "summary": "Ataque de fuerza bruta SSH contra srv-web01...",
  "reasoning": "Regla nivel 10 + 48 fallos + IP pública + activo DMZ...",
  "recommended_actions": [
    {"priority": 1, "action": "Aislar el host...", "owner": "SOC L2", "sla_minutes": 15, "type": "containment"}
  ],
  "mitre_techniques": ["T1110", "T1078"],
  "should_escalate": true,
  "false_positive_reason": null,
  "engine": "ollama",
  "model_name": "llama3.1:8b",
  "prompt_version": "triage-v1",
  "latency_ms": 1840,
  "tokens_used": 860,
  "enrichment": []
}
```

**Motor heurístico local**

Puntúa:

```text
riesgo = base(severidad) + 0.8 * rule_level + keywords + criticidad_activo
         + exposición_IP + cuenta_privilegiada + reputación_externa
```

- `base`: critical 62, high 50, medium 32, low 15, info 5.
- Keywords: malware +20, exploit +18, C2 +20, lateral +15, phishing +14, brute force +12, scan +5, test −25.
- Activo: critical +15, high +8, medium +3.
- IP pública +4; privada −3.
- `verdict`: ≥68 verdadero positivo; 45–67 sospechoso; <45 benigno; patrón de prueba → falso positivo.
- Devuelve `engine="heuristic-local"` y `model_name="soc-lite-rules-v1"`.

Este motor no sustituye al LLM: garantiza continuidad y sirve como línea base para evaluar si el modelo aporta valor.

**Persistencia**

1. `alerts.status = triaging` (commit).
2. Llamada remota con timeout de 60 s.
3. Upsert de `triage_results`.
4. Reemplazo de `enrichment_data` de la alerta.
5. `alerts.status = triaged`, actualización de MITRE.
6. Evento `TRIAGE` en `audit_log`.
7. En error: vuelta a `pending`, evento `TRIAGE_ERROR`, HTTP 503 con detalle.

### 3.7 Dashboard e indicadores

`GET /api/v1/dashboard/overview?days=14` devuelve:

- `total_alerts`, `open_alerts`, `critical_open`, `high_open`.
- `false_positive_rate`: alertas con veredicto/estado FP ÷ alertas triadas.
- `triage_coverage`: alertas con triaje ÷ total.
- `automation_rate`: triajes automáticos ÷ triajes.
- `mttt_minutes`: promedio `triage.created_at − alert.received_at`.
- `mttr_hours`: promedio `incident.closed_at − incident.opened_at`.
- `sla_compliance`: incidentes cerrados a tiempo u abiertos no vencidos ÷ incidentes con SLA.
- Series: alertas por día, severidad, estado, fuente, veredicto, top IPs, top reglas, MITRE, incidentes.

Las series se calculan en Python sobre las alertas del periodo para mantener compatibilidad entre PostgreSQL y SQLite en pruebas; para volúmenes mayores se recomienda mover las agregaciones a SQL con vistas materializadas.

### 3.8 Reportes PDF, Word y Excel

| Formato | Librería | Contenido |
|---|---|---|
| PDF | ReportLab 4.x | Portada, resumen ejecutivo, 9 KPIs, gráfico de severidad, tendencia, tabla de alertas, triajes, incidentes, recomendaciones y, en auditoría, bitácora. |
| DOCX | python-docx | Misma estructura en secciones y tablas editables; encabezado/pie con marca y numeración. |
| XLSX | openpyxl | Hojas `Resumen`, `Alertas`, `Triaje`, `Incidentes`, `Auditoria`, `Recomendaciones`; formato condicional, autofiltros, panel congelado y gráfico de severidad. |

Flujo:

1. `POST /reports` valida permisos y periodo (`days` o `period_start/end`).
2. Consulta alertas, incidentes, triajes y (si aplica) auditoría.
3. Genera bytes con la librería correspondiente.
4. Guarda el archivo en `storage/reports` con nombre aleatorio.
5. Inserta fila en `reports`.
6. Registra `EXPORT` en auditoría.
7. `GET /reports/{id}/download` valida path traversal, sirve el archivo y registra `DOWNLOAD`.

**Seguridad:** el nombre se genera en servidor; la descarga resuelve `reports_path / file_name` y comprueba que el path esté dentro del directorio. Los valores de usuario se escapan en PDF (`escape`) y se prefijan con `'` en Excel cuando empiezan por `=`, `+`, `-`, `@` para evitar inyección de fórmulas.

**Vista del reporte PDF**

![Reporte PDF de gestión](screenshots/report-pdf-2.png)

### 3.9 Bitácora de auditoría

La bitácora cubre tres niveles:

1. **Sesión:** `LOGIN`, `LOGIN_FAILED`, `LOGOUT`, `TOKEN_REFRESH`, `PASSWORD_CHANGE` con dirección `IN`/`OUT`.
2. **Módulo:** el hook `useModuleAudit` envía `MODULE_ENTER` al montar la página y `MODULE_EXIT` al desmontarla o cerrar la pestaña (`fetch` con `keepalive`). Además, el middleware de FastAPI registra cada llamada autenticada como `API_ACCESS` con método, ruta, status y duración.
3. **Negocio:** `TRIAGE`, `CREATE`, `UPDATE`, `CLOSE`, `ESCALATE`, `INGEST`, `EXPORT`, `DOWNLOAD`, con entidad y detalle.

Campos mínimos exigidos: **usuario** (`actor_email`/`user_id`), **fecha y hora** (`created_at` con zona), **acción** (`action`, `event_type`) y **módulo**. Se añaden rol, IP, user-agent, request ID y resultado HTTP para investigación.

**Inmutabilidad:** la API no expone `DELETE` de auditoría. En producción se recomienda:
- rol de BD `soc_lite_app` con `INSERT/SELECT` y sin `UPDATE/DELETE` sobre `audit_log`;
- exportación periódica a almacenamiento WORM o SIEM;
- hash encadenado por lote (roadmap) para evidencia criptográfica.

### 3.10 Seguridad del backend

| Control | Implementación |
|---|---|
| Contraseñas | bcrypt coste 12, mínimo 10 caracteres con mayúscula/minúscula/dígito. |
| JWT | HS256, `sub`, `type`, `jti`, expiración; refresh rotado y revocable. |
| Fuerza bruta | 5 intentos / 15 min por email+IP (memoria; Redis en HA). |
| RBAC | Dependencias por permiso en cada endpoint; admin bypass explícito. |
| Ingesta | API key comparada con `hmac.compare_digest`. |
| SQLi | SQLAlchemy parametrizado; n8n usa expresiones controladas y `ON CONFLICT`. |
| XSS | React escapa por defecto; no se usa `dangerouslySetInnerHTML`. |
| Path traversal | Validación del path de reportes. |
| CORS | Lista explícita de orígenes. |
| Cabeceras | `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`. |
| Secretos | `.env` fuera de git; Docker secrets/Vault en producción. |
| Datos personales | Minimización; `description` puede contener PII, se recomienda redacción previa y retención limitada. |

### 3.11 Pruebas

```powershell
$env:PYTHONPATH="backend"
python -m unittest discover -s backend/tests -v
```

Resultado verificado: **9 pruebas OK** (salud, dashboard, alertas, triaje, RBAC viewer/auditor, ingesta idempotente, reportes PDF/DOCX/XLSX, auditoría, usuarios, refresh/logout).

También se verificó:
- esquema y seed sobre **PostgreSQL 17**;
- importación del workflow en **n8n 1.111.1**;
- build de frontend con `tsc --noEmit` + Vite;
- generación y descarga de los tres formatos con contenido > 15 KB.

### 3.12 Ejemplos de uso

```bash
# Login
curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@soclite.local","password":"Admin2026!"}'

# Ingesta desde n8n (API key)
curl -s -X POST "http://localhost:8000/api/v1/ingest/alert?auto_triage=true" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: dev-ingest-key-cambiar" \
  -d '{
    "id":"wazuh-5710-1",
    "timestamp":"2026-10-19T15:00:00-05:00",
    "rule":{"id":"5710","level":10,"description":"Fuerza bruta SSH"},
    "agent":{"name":"srv-web01"},
    "data":{"srcip":"203.0.113.45","dstuser":"root"},
    "full_log":"48 intentos fallidos"
  }'

# Reporte de gestión en Excel
curl -s -X POST http://localhost:8000/api/v1/reports \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"report_type":"management","format":"xlsx","days":30}'
```

---

## 4. Desarrollo del frontend

### 4.1 Stack y decisiones

| Tecnología | Versión | Uso | Por qué |
|---|---|---|---|
| React | 19 | UI | Componentización, ecosistema, soporte. |
| TypeScript | 5.8 | Tipado | Contratos con la API, refactors seguros. |
| Vite | 6 | Build/dev server | Arranque rápido, proxy `/api`, build optimizado. |
| Tailwind CSS | 3.4 | Estilos | Consistencia, responsive, tema oscuro. |
| React Router | 6 | Rutas | Rutas anidadas y guards. |
| TanStack Query | 5 | Datos remotos | Cache, reintentos, invalidación, refetch. |
| Axios | 1.x | HTTP | Interceptores, refresh automático, descargas. |
| Lucide React | 0.468 | Iconografía | Ligera y coherente. |
| date-fns | 4 | Fechas | Formato en español. |

No se usa una librería de charts pesada: los gráficos son SVG propios, lo que reduce el bundle y permite un estilo consistente.

### 4.2 Estructura

```text
frontend/src/
├── main.tsx                 # QueryClient, Router, Auth, Toast
├── App.tsx                  # Rutas y guards
├── index.css                # Tailwind + tema
├── types/index.ts           # Contratos TypeScript
├── lib/api.ts               # Axios, refresh, endpoints
├── lib/utils.ts             # fechas, etiquetas, SLA, formato
├── context/AuthContext.tsx  # sesión, permisos
├── context/ToastContext.tsx # notificaciones
├── hooks/useModuleAudit.ts  # entrada/salida de módulo
├── components/
│   ├── AppShell.tsx         # sidebar, topbar, layout
│   ├── charts.tsx           # tendencia, donut, barras, KPI
│   ├── AlertsTable.tsx      # tabla reutilizable
│   ├── guards.tsx           # ProtectedRoute / RequirePermission
│   └── ui.tsx               # Button, Card, Badge, Modal, Input…
└── pages/
    ├── LoginPage.tsx
    ├── DashboardPage.tsx
    ├── AlertsPage.tsx
    ├── AlertDetailPage.tsx
    ├── IncidentsPage.tsx
    ├── ReportsPage.tsx
    ├── UsersPage.tsx
    ├── AuditPage.tsx
    └── NotFoundPage.tsx
```

### 4.3 Rutas y control de acceso

| Ruta | Página | Permiso |
|---|---|---|
| `/login` | Login | Público (redirige si hay sesión). |
| `/` | Dashboard | `dashboard:read` |
| `/alerts` | Alertas | `alerts:read` |
| `/alerts/:id` | Detalle | `alerts:read` |
| `/incidents` | Incidentes | `incidents:read` |
| `/reports` | Reportes | `reports:read` |
| `/users` | Usuarios y roles | `users:read` |
| `/audit` | Auditoría | `audit:read` |
| `*` | 404 | — |

El menú se construye filtrando por permisos. `RequirePermission` muestra una tarjeta de acceso restringido si el rol no alcanza. Las acciones sensibles (triar, escalar, descartar, crear usuario, generar reporte) se ocultan o deshabilitan, pero el backend siempre revalida.

### 4.4 Experiencia de usuario

**Login**

![Login SOC-Lite](screenshots/01-login.png)

- Panel izquierdo con propuesta de valor, cumplimiento y cuentas demo.
- Formulario con mostrar/ocultar contraseña, errores y carga.
- Acceso rápido a cuentas de distintos roles para evaluar RBAC.

**Dashboard**

![Dashboard SOC-Lite](screenshots/02-dashboard.png)

- 4 KPI principales + barra de calidad (SLA, automatización, cobertura, MTTR).
- Tendencia diaria, dona de severidad, top IPs, MITRE e incidentes.
- Tabla de alertas recientes con riesgo y estado.
- Selector de periodo 7/14/30/90 días, actualización manual y auto-refresh cada 60 s.

**Cola de alertas**

![Alertas](screenshots/03-alerts.png)

- Búsqueda por título/IP/host/regla/ID.
- Filtros por severidad, estado, fuente y “solo abiertas”.
- Paginación, orden por fecha, badges de severidad/estado y medidor de riesgo.
- Alta manual para pruebas o reportes de usuarios.

**Detalle de alerta**

![Detalle de alerta](screenshots/04-alert-detail.png)

- Contexto, triaje, riesgo, confianza, razonamiento y acciones priorizadas.
- Enriquecimiento por proveedor, activo afectado, incidente y timeline de auditoría.
- Payload original expandible y copiable.
- Acciones: re-triar, escalar, marcar falso positivo.

**Incidentes**

![Incidentes](screenshots/05-incidents.png)

- Tarjetas de volumen, tabla con SLA, severidad, estado y responsable.
- Detalle en modal con acciones de investigación/contensión/cierre.
- SLA calculado en cliente y coloreado.

**Reportes**

![Reportes](screenshots/06-reports.png)

- Tarjetas de tipo operacional/gestión/auditoría.
- Selector PDF/Word/Excel, periodo y generación + descarga.
- Historial con tamaño, autor, tipo y descarga.

**Usuarios y roles**

![Usuarios](screenshots/07-users.png)

- Tabla de usuarios con rol, área, estado y último acceso.
- Crear/editar, resetear contraseña y activar/desactivar.
- Pestaña de roles con tarjetas y matriz de permisos por módulo.

**Auditoría**

![Auditoría](screenshots/08-audit.png)

- KPIs de eventos, usuarios activos, entradas y salidas.
- Filtros por módulo, tipo de evento, dirección y texto.
- Tabla con actor, módulo, evento, acción, IN/OUT, IP y HTTP.
- Auto-refresh cada 30 s.

### 4.5 Estado y datos

- **AuthContext** restaura la sesión con `/auth/me`; si el access token expiró, el interceptor de Axios llama a `/auth/refresh`, rota el token y reintenta la petición original. Si falla, limpia y emite `soc:logout`.
- **TanStack Query** usa `staleTime=15s`, `retry=1`, sin refetch al enfocar; las mutaciones invalidan `alerts`, `alert`, `incidents`, `reports`, `users` o `audit` según corresponda.
- **ToastContext** muestra éxito/error/información con autocierre.
- **useModuleAudit** registra `IN` al entrar y `OUT` al salir/cerrar pestaña; se apoya en `fetch(..., {keepalive:true})` para el cierre.
- **Formularios** son controlados; la validación crítica vive en el backend. El frontend valida longitud y campos obligatorios para UX.

### 4.6 Accesibilidad y responsive

- Contraste alto sobre fondo oscuro, foco visible en controles, botones con `aria-label` cuando son solo icono.
- Layout responsive: sidebar colapsable en móvil, tablas con columnas ocultas progresivamente, modales a pantalla completa en pantallas pequeñas.
- Textos en español, fechas con `date-fns/locale/es`, números con `Intl.NumberFormat('es-PE')`.
- Estados de carga, error y vacío en cada vista.

### 4.7 Build y despliegue

```bash
cd frontend
npm ci
npm run build      # tsc --noEmit && vite build
npm run dev        # http://localhost:5173 con proxy /api → :8000
```

El build de producción se sirve con nginx; `nginx.conf` incluye fallback SPA, proxy `/api/`, gzip y cabeceras de seguridad. El bundle verificado fue de ~532 KB (158 KB gzip); se puede dividir por rutas con `React.lazy` en la siguiente iteración.

---

## 5. Flujo de nodos n8n

### 5.1 Diseño del workflow

El archivo `n8n/soc-lite-triage-workflow.json` contiene 12 nodos funcionales + 1 nota. Se importó correctamente en n8n 1.111.1. Los 10 nodos del caso se conservan; se añadieron normalización explícita, control de duplicado y persistencia de enriquecimiento para que el flujo sea operable.

| # | Nodo | Tipo | Función | Entrada → Salida |
|---|---|---|---|---|
| 1 | Webhook Wazuh / OPNsense | Webhook | Recibe el evento bruto y responde 200 de inmediato. | JSON crudo → payload |
| 2 | Normalizar alerta | Code | Detecta fuente, mapea severidad, calcula fingerprint de 5 min. | payload → alerta normalizada |
| 3 | ¿Severidad ≥ media? | IF | Descarta info/baja y payloads inválidos. | normalizada → boolean |
| 4 | Insertar alerta (idempotente) | PostgreSQL | `INSERT ... ON CONFLICT DO NOTHING RETURNING`. | normalizada → id o vacío |
| 5 | ¿Alerta nueva? | IF | Detiene duplicados. | fila → boolean |
| 6 | Triaje LangChain | HTTP Request | Envía alerta al microservicio; timeout 60 s. | id + datos → JSON de triaje |
| 7 | Guardar triaje | PostgreSQL | Upsert `triage_results` + `UPDATE alerts`. | JSON → fila |
| 8 | Guardar enriquecimiento | PostgreSQL | Inserta `enrichment_data` desde el array del agente. | JSON → filas |
| 9 | Enrutar por severidad | Switch | Ramas critical/high/medium/low/info. | severidad → rama |
| 10 | Notificar Slack | Slack | Solo critical/high; `onError: continue`. | resumen → mensaje |
| 11 | Crear ticket osTicket | HTTP | Ticket con resumen, riesgo y prioridad. | triaje → ticket |
| 12 | Auditoría | PostgreSQL | Registra `TRIAGE` con actor n8n y execution id. | acción → fila |

### 5.2 Diagrama

```mermaid
flowchart LR
    W["1 Webhook"] --> N["2 Normalizar"]
    N --> IF1{"3 Severidad ≥ media"}
    IF1 -->|sí| DB1["4 Insertar alerta"]
    IF1 -->|no| X["Fin"]
    DB1 --> IF2{"5 ¿Nueva?"}
    IF2 -->|no| X
    IF2 -->|sí| AI["6 Triaje LangChain"]
    AI --> DB2["7 Guardar triaje"]
    DB2 --> DB3["8 Guardar enriquecimiento"]
    DB3 --> SW{"9 Switch severidad"}
    SW -->|critical/high| SL["10 Slack"]
    SL --> TK["11 osTicket"]
    TK --> AU["12 Auditoría"]
    SW -->|medium/low/info| AU
```

### 5.3 Payload de entrada (Wazuh)

```json
{
  "id": "wazuh-5710-2026001",
  "timestamp": "2026-10-19T14:05:00-05:00",
  "rule": {
    "id": "5710",
    "level": 10,
    "description": "Fuerza bruta SSH detectada"
  },
  "agent": {"name": "srv-web01"},
  "data": {"srcip": "203.0.113.45", "dstuser": "root"},
  "full_log": "48 intentos de autenticación fallidos en 3 minutos."
}
```

### 5.4 Salida normalizada del nodo 2

```json
{
  "external_id": "wazuh-5710-2026001",
  "fingerprint": "5132d234642eeabd-5b2ad4",
  "source": "wazuh",
  "title": "Fuerza bruta SSH detectada",
  "description": "48 intentos de autenticación fallidos en 3 minutos.",
  "rule_id": "5710",
  "rule_level": 10,
  "severity": "high",
  "source_ip": "203.0.113.45",
  "destination_ip": null,
  "hostname": "srv-web01",
  "agent_name": "srv-web01",
  "username": "root",
  "mitre_techniques": [],
  "tags": ["wazuh"],
  "raw_payload": {},
  "received_at": "2026-10-19T19:05:00.000Z"
}
```

### 5.5 Consultas clave

**Nodo 4**

```sql
INSERT INTO alerts (id, external_id, fingerprint, source, title, description,
                    rule_id, rule_level, severity, status, source_ip, destination_ip,
                    hostname, agent_name, username, mitre_techniques, tags, raw_payload,
                    received_at, first_seen_at, last_seen_at, created_at, updated_at)
VALUES (gen_random_uuid(), NULLIF('…','')::varchar, '…', 'wazuh', '…', '…',
        '5710', 10, 'high', 'pending', '203.0.113.45', NULL,
        'srv-web01', 'srv-web01', 'root', '[]'::jsonb, '["wazuh"]'::jsonb,
        '{…}'::jsonb, '2026-10-19T19:05:00Z'::timestamptz,
        '2026-10-19T19:05:00Z'::timestamptz, '2026-10-19T19:05:00Z'::timestamptz,
        now(), now())
ON CONFLICT (fingerprint) DO NOTHING
RETURNING id, fingerprint, severity, title, source_ip, hostname;
```

**Nodo 7** usa un CTE `saved` + `updated` para upsert del triaje y cambio de estado. La consulta completa está en el JSON.

**Nodo 8**:

```sql
INSERT INTO enrichment_data (id, alert_id, provider, indicator, indicator_type,
                             status, risk_score, summary, payload, fetched_at)
SELECT gen_random_uuid(), '…'::uuid,
       item->>'provider', item->>'indicator', item->>'indicator_type',
       item->>'status', (item->>'risk_score')::double precision,
       item->>'summary', COALESCE(item->'payload','{}'::jsonb), now()
FROM jsonb_array_elements('[…]'::jsonb) AS item
ON CONFLICT (alert_id, provider, indicator) DO UPDATE SET …;
```

### 5.6 Reintentos, errores y observabilidad

- **Webhook:** `responseMode=onReceived` para no bloquear al SIEM; el procesamiento continúa en segundo plano.
- **PostgreSQL:** `ON CONFLICT` + unique constraint. Si el nodo devuelve 0 filas, el IF 5 detiene la rama.
- **HTTP IA:** `onError: continueErrorOutput`; en producción se recomienda un nodo de reintento con backoff (3 intentos: 2 s, 10 s, 30 s) y una cola de fallidos.
- **Slack/osTicket:** `onError: continueRegularOutput` para que un canal caído no impida la auditoría.
- **Auditoría:** se ejecuta en todas las ramas de severidad.
- **Idempotencia externa:** osTicket debe usar `alert_id` como clave idempotente si su API lo permite; Slack puede deduplicar por `alert_id` + ventana.
- **Observabilidad:** conservar `execution.id` en `audit_log.request_id`; enviar errores a un canal `#soc-lite-errors`; métricas de ejecuciones n8n.

### 5.7 Importación y credenciales

1. n8n → Workflows → Import from File → `n8n/soc-lite-triage-workflow.json`.
2. Crear credencial PostgreSQL `SOC-Lite PostgreSQL` y reemplazar `REEMPLAZAR_CREDENCIAL_POSTGRES`.
3. Crear credencial Slack y reemplazar el ID.
4. Crear credencial HTTP Basic para osTicket.
5. En Docker Compose, `SOC_AI_INTERNAL_KEY` e `INTERNAL_API_KEY` reciben el valor de `TRIAGE_API_KEY`; en instalaciones externas deben configurarse manualmente.
6. Ajustar `http://ai-service:8001` si el microservicio está en otro host.
7. Activar el workflow y registrar la URL del webhook en Wazuh/OPNsense.

### 5.8 Alternativa sin n8n

Para demo o contingencia, la API expone `POST /api/v1/ingest/alert?auto_triage=true` con `X-API-Key`. Internamente normaliza, deduplica, persiste, llama al microservicio y guarda el triaje. Esto permite validar el producto sin instalar n8n; en producción se recomienda n8n para la orquestación y la API como sistema de registro.

---

## 6. Datasets públicos recomendados

Los datasets permiten evaluar el normalizador, el motor heurístico, el prompt y la calidad del triaje. **No deben usarse para entrenar con datos personales reales sin base legal y anonimización.**

| Dataset | Contenido | Uso recomendado en SOC-Lite | Enlace / licencia |
|---|---|---|---|
| **Microsoft GUIDE** | Incidentes etiquetados con técnicas MITRE, evidencia y acciones de respuesta. | Evaluar clasificación, severidad y recomendaciones; few-shot del prompt. | `https://github.com/microsoft/GUIDE` · MIT |
| **Splunk BOTS v3** | Boss of the SOC: escenarios de intrusión, logs y preguntas de investigación. | Simular investigaciones, validar MITRE y narrativa del triaje. | `https://github.com/splunk/botsv3` · uso educativo |
| **OTRF Security Datasets (Mordor)** | Telemetría Windows/Sysmon, PowerShell, credenciales y ataques reproducibles. | Pruebas de reglas, normalización y detección de TTP. | `https://github.com/OTRF/Security-Datasets` · MIT |
| **Splunk attack_data** | Datasets de ataques y telemetría para detecciones. | Validar reglas Sigma/Wazuh y enriquecimiento. | `https://github.com/splunk/attack_data` · Apache-2.0 |
| **CICIDS2017** | Tráfico de red benigno y ataques (DDoS, brute force, web, infiltración). | Evaluar features de red y detección de anomalías. | `https://www.unb.ca/cic/datasets/ids-2017.html` · uso académico |
| **UNSW-NB15** | Paquetes/flows etiquetados con tipos de ataque. | Benchmark de clasificación de red y detección. | `https://research.unsw.edu.au/projects/unsw-nb15-dataset` · uso académico |
| **LANL Cyber Dataset** | Autenticaciones, procesos, DNS y flujos de una red empresarial. | Detección de movimiento lateral y comportamiento anómalo. | `https://csr.lanl.gov/data/cyber1/` · uso académico |
| **AIT Log Data Set** | Logs de un entorno real con escenarios de ataque etiquetados. | Evaluación de detección y triaje sobre logs. | `https://zenodo.org/records/5789060` · CC BY 4.0 |
| **Wazuh ruleset / test logs** | Reglas, decoders y eventos de ejemplo. | Pruebas de normalización y mapeo de severidad. | `https://github.com/wazuh/wazuh-ruleset` · GPL-2.0 |
| **MITRE ATT&CK STIX** | Técnicas, tácticas, grupos y mitigaciones. | Enriquecimiento local y validación de MITRE. | `https://github.com/mitre-attack/attack-stix-data` · Apache-2.0 |
| **NVD / EPSS / CISA KEV** | CVEs, probabilidad de explotación y vulnerabilidades explotadas. | Priorización de vulnerabilidades y contexto de exposición. | `https://nvd.nist.gov/`, `https://www.first.org/epss/`, `https://www.cisa.gov/known-exploited-vulnerabilities-catalog` · dominio público / CC0 |
| **AbuseIPDB / VirusTotal / GeoLite2** | Reputación de IP, países, ASN, proxy/hosting. | Enriquecimiento en tiempo de triaje (APIs, no datasets). | `https://www.abuseipdb.com/`, `https://www.virustotal.com/`, `https://dev.maxmind.com/geoip/geolite2-free-geolocation-data` · licencias propias |

### 6.1 Protocolo de evaluación propuesto

1. **Muestra estratificada:** 300–500 alertas, 20% críticas/altas, 30% medias, 30% bajas, 20% ruido/FP.
2. **Etiquetado:** dos analistas independientes (verdadero/falso positivo, severidad, acción); medir acuerdo (kappa).
3. **Métricas:** precisión/recall por veredicto, MAE de severidad, FP rate, exactitud de MITRE, utilidad de las 3 primeras acciones (Likert 1–5), latencia y coste.
4. **Baselines:** reglas heurísticas, LLM sin enriquecimiento, LLM con enriquecimiento y humano.
5. **Privacidad:** sustituir IPs/hosts/usuarios por valores sintéticos; no enviar datos reales a APIs externas sin contrato y base legal.
6. **Sesgo:** CICIDS/UNSW son tráfico de red, no alertas SOC; no sirven solos para evaluar razonamiento. Combinar con GUIDE/BOTS/Mordor para el dominio SOC.

### 6.2 Uso en el producto

- **Desarrollo:** Wazuh ruleset + eventos de ejemplo para el normalizador.
- **Evaluación offline:** GUIDE/BOTS/Mordor para medir triaje y acciones.
- **Enriquecimiento:** MITRE ATT&CK STIX local; NVD/EPSS/KEV en el roadmap de vulnerabilidades.
- **Detección:** Sigma y reglas Wazuh como fuente de reglas; no se incluyen en el repositorio por licencia y tamaño.
- **Demo:** datos sintéticos de `seed.py` (38 alertas) para no distribuir datos de terceros.

---

## 7. Stack tecnológico detallado

### 7.1 Backend

| Componente | Versión | Función | Justificación |
|---|---|---|---|
| Python | 3.11+ | Lenguaje | Ecosistema IA, reportes y rapidez de desarrollo. |
| FastAPI | 0.115+ | Framework HTTP | Tipado, OpenAPI, dependencias, rendimiento. |
| Uvicorn | 0.32+ | ASGI server | Estándar para FastAPI; workers. |
| SQLAlchemy | 2.0+ | ORM | Modelo tipado, SQL portable, relaciones. |
| Pydantic | 2.10+ | Validación | Contratos y serialización. |
| psycopg | 3.2+ | Driver PostgreSQL | Rendimiento y soporte moderno. |
| PyJWT | 2.10+ | JWT | Simple, mantenido. |
| bcrypt | 4.2+ | Hash | Coste adaptativo, estándar. |
| ReportLab | 4.2+ | PDF | Layout programático, gráficos, tablas. |
| python-docx | 1.1+ | Word | Documentos editables. |
| openpyxl | 3.1+ | Excel | Formato, fórmulas, gráficos. |
| httpx | 0.28+ | Cliente HTTP | Timeouts, llamadas al microservicio. |
| unittest/pytest | — | Pruebas | Integración y regresión. |

### 7.2 Frontend

| Componente | Versión | Función | Justificación |
|---|---|---|---|
| React | 19 | UI | Ecosistema y componentes. |
| TypeScript | 5.8 | Tipado | Menos errores de integración. |
| Vite | 6 | Build | Rapidez y proxy de desarrollo. |
| Tailwind | 3.4 | Estilos | Diseño consistente sin CSS ad hoc. |
| React Router | 6 | Navegación | Rutas y guards. |
| TanStack Query | 5 | Server state | Cache, reintentos, invalidación. |
| Axios | 1.x | HTTP | Interceptores y refresh. |
| Lucide | 0.468 | Iconos | Ligero. |
| date-fns | 4 | Fechas | Localización española. |

### 7.3 IA y orquestación

| Componente | Versión | Función |
|---|---|---|
| LangChain Core | 0.3+ / 1.x | Prompts, tools, modelos, cadenas. |
| langchain-ollama | 0.2+ | `ChatOllama` con `format=json`. |
| langchain-openai | 0.2+ | Opción OpenAI si la política lo permite. |
| Ollama | latest | Servidor de inferencia local. |
| Llama 3.1 8B / Mistral 7B | — | Modelos recomendados; 3B para 8 GB. |
| n8n | 1.111+ | Orquestación low-code. |
| PostgreSQL | 16+ | Fuente de verdad. |
| nginx | 1.27 | Proxy inverso y estáticos. |
| Docker Compose | v2 | Despliegue reproducible. |

### 7.4 Por qué no LangFlow para este caso

LangFlow es excelente para prototipar cadenas y visualizar prompts, pero el triaje requiere:

- herramientas con lógica condicional y validación estricta;
- memoria de incidentes y recuperación de contexto;
- contratos Pydantic y tests;
- control de versiones del prompt y del modelo;
- manejo de errores y fallback;
- evaluación reproducible.

LangChain en un microservicio permite todo esto y deja LangFlow para experimentación. n8n se queda con la integración y la orquestación, no con el razonamiento.

### 7.5 Dimensionamiento

| Perfil | Alertas/día | vCPU | RAM | Disco | GPU | Observación |
|---|---:|---:|---:|---:|---|---|
| PYME | 500–2.000 | 4 | 16 GB | 100 GB SSD | opcional | Todo en uno; Ollama 8B cuantizado. |
| Mediana | 5.000–20.000 | 8–16 | 32–64 GB | 500 GB SSD | 1× L4/A10 o CPU | API 2–4 workers, PG gestionado, AI separado. |
| Organismo público | 20.000+ | 16+ | 64 GB+ | 1 TB+ | 1–2 GPU | HA, WAF, SIEM, retención extendida, air-gap. |

**Coste orientativo:** infraestructura on-premise o nube pequeña; Ollama elimina el coste por token. OpenAI opcional para picos o evaluación. El ahorro frente a SOAR comercial es el argumento principal para PYME.

### 7.6 Observabilidad y operación

- **Logs:** JSON a stdout; agregar con Loki/ELK.
- **Métricas:** `/health` y `/meta/health`; en roadmap Prometheus (`/metrics`) con latencia de triaje, errores, cola y uso de tokens.
- **Trazas:** request ID propagado desde nginx/API; OpenTelemetry en roadmap.
- **Backups:** PostgreSQL + volumen de reportes; prueba de restauración.
- **Actualizaciones:** imágenes versionadas, migraciones Alembic en roadmap, ventana de mantenimiento.

---

## 8. Cumplimiento normativo

### 8.1 ISO/IEC 27001:2022

| Control | Cómo lo cubre SOC-Lite |
|---|---|
| A.5.7 Inteligencia de amenazas | Enriquecimiento VirusTotal/AbuseIPDB/GeoIP y MITRE. |
| A.5.24 Planificación y preparación de la respuesta | Workflow, roles, SLA, escalamiento a incidente. |
| A.5.25 Evaluación de eventos de seguridad | Triaje, veredicto, severidad, confianza y razonamiento. |
| A.5.26 Respuesta a incidentes | Incidentes, acciones de contención, cierre y evidencias. |
| A.8.15 Registro de eventos | `audit_log` con usuario, fecha/hora, módulo y acción. |
| A.8.16 Actividades de monitoreo | Dashboard, MTTT, FP rate, SLA, top fuentes. |
| A.8.8 Gestión de vulnerabilidades | Roadmap NVD/EPSS/KEV; base para priorización. |

### 8.2 NIST Cybersecurity Framework 2.0

| Función | Categoría | Implementación |
|---|---|---|
| GOVERN | GV.RM, GV.PO | Roles, políticas, retención, RBAC. |
| IDENTIFY | ID.AM | Inventario de activos y criticidad. |
| PROTECT | PR.AA | Autenticación, RBAC, mínimo privilegio. |
| DETECT | DE.AE-02, DE.AE-03, DE.AE-06, DE.AE-07, DE.AE-08 | Ingesta, correlación, análisis, triaje y declaración de incidentes. |
| RESPOND | RS.MA, RS.AN, RS.CO, RS.MI | Incidentes, acciones, notificaciones y contención. |
| RECOVER | RC.RP | Cierre, lecciones aprendidas y reportes. |

### 8.3 NIST SP 800-61r3

El flujo sigue las fases de preparación, detección/análisis, contención/erradicación/recuperación y actividades post-incidente. La bitácora y los reportes cubren la evidencia y las lecciones aprendidas.

### 8.4 Protección de datos

- Minimizar PII en `description` y `raw_payload`; idealmente redactar antes de persistir.
- Restringir `audit:read` a auditoría/supervisor.
- Retención aprobada; borrado seguro de reportes.
- Si se usa OpenAI, firmar DPA y excluir datos sensibles; por defecto Ollama local.
- Para organismos públicos, evaluar ENS/ISO 27001, retención documental y soberanía del dato.

---

## 9. Despliegue y operación

### 9.1 Requisitos

- Docker Engine 24+ y Compose v2.
- 4 vCPU, 16 GB RAM, 50 GB disco (mínimo demo).
- Puertos 8080 (UI), 8000 (API), 5432 (solo local), 8001 (AI, solo local) y 5678 (n8n, solo local).
- Opcional: GPU NVIDIA + Container Toolkit para Ollama.

### 9.2 Inicio rápido con Docker

```bash
cp .env.example .env
# Cambiar SECRET_KEY, POSTGRES_PASSWORD, DATABASE_URL, INGEST_API_KEY,
# TRIAGE_API_KEY, N8N_DB_PASSWORD y N8N_ENCRYPTION_KEY

docker compose up -d --build
# UI:      http://localhost:8080
# API:     http://localhost:8000/docs
# Salud:   http://localhost:8000/health
# n8n:     http://localhost:5678

# Modelo local (opcional, perfil llm)
docker compose --profile llm up -d ollama
docker compose exec ollama ollama pull llama3.1:8b
```

El contenedor de base de datos ejecuta `db/init/01_schema.sql` y `02_seed.sql` solo en el primer arranque del volumen. El backend, con `AUTO_SEED=true`, verifica y completa la semilla de forma idempotente. n8n usa su propia base `n8n-db` y el volumen `n8n_data`; el workflow se importa y activa desde el editor tras crear sus credenciales.

### 9.3 Desarrollo local

```powershell
# Backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend\requirements-dev.txt
$env:PYTHONPATH="backend"
$env:DATABASE_URL="postgresql+psycopg://soc_lite:soc_lite@localhost:5432/soc_lite"
$env:TRIAGE_MODE="heuristic"
python -m app.seed --reset
uvicorn app.main:app --reload --port 8000

# Frontend
cd frontend
npm ci
npm run dev

# AI (opcional)
cd ..\ai-service
pip install -r requirements.txt
$env:LLM_PROVIDER="heuristic"
uvicorn app.main:app --reload --port 8001
```

### 9.4 Healthchecks y troubleshooting

| Síntoma | Causa probable | Solución |
|---|---|---|
| `database: error` | URL/credenciales o PG no listo | Revisar `docker compose logs db`; `pg_isready`. |
| Triaje 503 | AI no disponible y modo `remote` | Usar `TRIAGE_MODE=auto` o levantar AI. |
| `401` en n8n | API key incorrecta | Igualar `INGEST_API_KEY` y `X-API-Key`. |
| `401` en AI | `X-Internal-Key` no coincide | Igualar `TRIAGE_API_KEY` e `INTERNAL_API_KEY`. |
| Reportes vacíos | Periodo sin datos | Ampliar `days` o revisar `received_at`. |
| Frontend 404 al refrescar | nginx sin fallback SPA | Verificar `try_files ... /index.html`. |
| Ollama lento | Modelo grande / sin GPU | Usar 3B–8B cuantizado; limitar contexto. |

### 9.5 Checklist de producción

- [ ] `SECRET_KEY` aleatorio de 32+ bytes y rotado.
- [ ] `DEMO_MODE=false` y cuentas demo eliminadas.
- [ ] `POSTGRES_PASSWORD` fuerte; acceso a BD restringido.
- [ ] TLS terminado en nginx/WAF; HSTS.
- [ ] Backups automáticos y restauración probada.
- [ ] Retención de auditoría aprobada.
- [ ] Roles revisados; MFA/SSO en roadmap.
- [ ] Ollama en red interna; sin puerto público.
- [ ] n8n con `N8N_ENCRYPTION_KEY` estable, credenciales cifradas, HTTPS y variables de entorno protegidas.
- [ ] Monitoreo de `/health`, errores 5xx y latencia de triaje.

---

## 10. Pruebas, aceptación y limitaciones

### 10.1 Evidencia de verificación

| Prueba | Resultado |
|---|---|
| Importación del esquema en PostgreSQL 17 | OK (12 tablas, índices y constraints). |
| Seed SQL en base limpia | OK (38 alertas, 5 usuarios, 10 incidentes). |
| `unittest` backend | 9/9 OK. |
| `unittest` microservicio IA | 4/4 OK en modo heurístico. |
| Reportes PDF/DOCX/XLSX | 3/3 generados y descargados; ZIP válido. |
| Frontend `tsc --noEmit` + Vite build | OK; bundle ~532 KB (158 KB gzip). |
| Importación n8n 1.111.1 | OK. |
| AI service modo heurístico | OK; veredicto, riesgo, acciones y latencia. |

### 10.2 Criterios de aceptación

- [x] Una alerta Wazuh/OPNsense se normaliza y persiste sin duplicados en reintentos.
- [x] El triaje devuelve veredicto, severidad, confianza, riesgo, resumen y acciones.
- [x] El dashboard muestra MTTT, FP rate, SLA, severidad, fuentes y MITRE.
- [x] Se generan reportes PDF, Word y Excel con datos del periodo.
- [x] RBAC impide que viewer/auditor ejecuten triaje o administren usuarios.
- [x] La bitácora registra login/logout, entradas/salidas y acciones de negocio.
- [x] El frontend es usable en escritorio y móvil.

### 10.3 Limitaciones conocidas

- El workflow n8n se validó por importación, no se ejecutó end-to-end contra Wazuh/OPNsense/osTicket reales en este entorno.
- La calidad del LLM depende del modelo y del prompt; se debe evaluar con datasets etiquetados antes de producción.
- El rate limit de login es en memoria; en múltiples workers se requiere Redis.
- No hay MFA/SSO ni firma criptográfica de auditoría en v1.
- Las APIs externas de enriquecimiento son opcionales y pueden fallar; el sistema degrada a heurístico/local.
- El seed SQL contiene fechas fijas; para demo con fechas actuales usar `python -m app.seed`.

### 10.4 Riesgos residuales y mitigación

| Riesgo | Impacto | Mitigación |
|---|---|---|
| Falso negativo del LLM | Alto | Revisión humana de críticas, umbral de confianza, baselines y muestreo. |
| Prompt injection en logs | Medio | Tratar logs como datos, no instrucciones; delimitar contexto; no ejecutar acciones automáticas destructivas. |
| Fuga de datos a APIs externas | Alto | Ollama por defecto; claves opcionales; revisión de privacidad. |
| Abuso de API key de ingesta | Alto | Rotación, red interna, rate limit, mTLS en roadmap. |
| Crecimiento de auditoría | Medio | Retención, particionado, archivado WORM. |
| Dependencia de n8n | Medio | Endpoint de ingesta alternativo y documentación del flujo. |

---

## 11. Roadmap

| Fase | Entregables |
|---|---|
| **1. Base (actual)** | Ingesta, triaje híbrido, dashboard, RBAC, auditoría, reportes, Docker. |
| **2. Hardening** | MFA/SSO OIDC, Redis para rate limit, Alembic, Prometheus/Grafana, OpenTelemetry, pruebas E2E con Wazuh. |
| **3. SOAR** | Acciones automáticas aprobadas (aislar host, bloquear IP), playbooks, aprobaciones de cuatro ojos. |
| **4. Inteligencia** | RAG sobre incidentes históricos, evaluación continua, feedback de analistas, ajuste de umbrales. |
| **5. Escala** | Multi-tenant, particionado, cola de triaje, HA de PostgreSQL, despliegue air-gapped. |

---

## 12. Anexos

### 12.1 Mapa de archivos relevantes

| Archivo | Contenido |
|---|---|
| `backend/app/main.py` | FastAPI, CORS, middleware, routers. |
| `backend/app/models/__init__.py` | 12 tablas y relaciones. |
| `backend/app/services/triage.py` | Orquestación y fallback. |
| `backend/app/services/reports.py` | PDF/DOCX/XLSX. |
| `backend/app/services/metrics.py` | KPIs. |
| `backend/app/api/routes_*.py` | Endpoints. |
| `ai-service/app/agent.py` | Prompt, LLM, heurístico. |
| `ai-service/app/tools.py` | Herramientas LangChain. |
| `frontend/src/pages/` | 9 páginas. |
| `n8n/soc-lite-triage-workflow.json` | Workflow importable. |
| `db/init/01_schema.sql` | DDL PostgreSQL. |
| `db/init/02_seed.sql` | Datos demo. |
| `backend/tests/test_api.py` | Pruebas. |

### 12.2 Glosario

- **MTTT:** Mean Time To Triage; tiempo medio desde la recepción hasta el triaje.
- **MTTR:** Mean Time To Resolve; tiempo medio de resolución de incidentes.
- **FP:** falso positivo.
- **RBAC:** control de acceso basado en roles.
- **SOAR:** Security Orchestration, Automation and Response.
- **SIEM:** Security Information and Event Management.
- **TTP:** tácticas, técnicas y procedimientos.
- **SLA:** acuerdo de nivel de servicio.

### 12.3 Nota final

SOC-Lite no pretende reemplazar un SOAR empresarial ni un equipo humano: su objetivo es **dar tiempo al analista**. Al automatizar la normalización, el enriquecimiento y el primer veredicto, el SOC puede concentrarse en los casos que realmente importan, con evidencia y trazabilidad suficientes para responder y auditar.

---

**Fin del documento.**
