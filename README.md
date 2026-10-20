# SOC-Lite

**Triaje automático de alertas SOC para PYMEs, empresas medianas y organismos públicos.**

SOC-Lite recibe alertas de Wazuh/OPNsense, las normaliza y deduplica, las enriquece con herramientas de reputación y contexto de activos, y usa un agente **LangChain + LLM local (Ollama)** para producir un veredicto, un riesgo, un resumen y acciones recomendadas. Todo queda en **PostgreSQL**, visible en un dashboard y exportable en **PDF, Word y Excel**, con **RBAC** y **bitácora de auditoría**.

> Documento principal: [`docs/ARQUITECTURA_SOC_LITE.md`](docs/ARQUITECTURA_SOC_LITE.md)  
> Workflow n8n: [`n8n/soc-lite-triage-workflow.json`](n8n/soc-lite-triage-workflow.json)

![Dashboard de SOC-Lite](docs/screenshots/02-dashboard.png)

---

## 1. Funcionalidades

- **Ingesta idempotente** desde Wazuh, OPNsense o API genérica, con fingerprint de 5 minutos.
- **Triaje híbrido**: microservicio LangChain + Ollama; fallback heurístico explicable si el LLM no está disponible.
- **Enriquecimiento**: VirusTotal, AbuseIPDB, GeoIP, MITRE ATT&CK y contexto de activo (CMDB).
- **Dashboard**: MTTT, MTTR, tasa de falsos positivos, cobertura, automatización, SLA, severidad, fuentes, top IPs y MITRE.
- **Gestión**: alertas, detalle con evidencia, acciones recomendadas, escalamiento a incidente y cierre como falso positivo.
- **Reportes**: operacional, de gestión y de auditoría en PDF, DOCX y XLSX.
- **Seguridad**: JWT con refresh rotado, bcrypt, RBAC de 5 roles/16 permisos, rate limit de login y cabeceras seguras.
- **Auditoría**: login/logout, entradas/salidas por módulo, accesos API, triajes, cambios, exportaciones y descargas.

---

## 2. Arranque rápido con Docker

Requisitos: Docker Engine 24+ y Docker Compose v2.

```bash
cp .env.example .env
# Edite .env: SECRET_KEY, POSTGRES_PASSWORD, INGEST_API_KEY y TRIAGE_API_KEY

docker compose up -d --build
```

Servicios:

| URL | Servicio |
|---|---|
| http://localhost:8080 | Interfaz web |
| http://localhost:8000/docs | OpenAPI / Swagger |
| http://localhost:8000/health | Salud de la API |
| http://localhost:8001/health | Salud del microservicio IA |

El primer arranque crea el esquema y los datos demo desde `db/init/`. El backend verifica la semilla con `AUTO_SEED=true`.

### Modelo local opcional

```bash
docker compose --profile llm up -d ollama
docker compose exec ollama ollama pull llama3.1:8b
```

Sin Ollama, el microservicio usa el motor heurístico (o el backend cae a él si `TRIAGE_MODE=auto`). Para una demo sin GPU:

```bash
docker compose -f docker-compose.demo.yml up -d --build
```

---

## 3. Cuentas demo

| Rol | Correo | Contraseña |
|---|---|---|
| Administrador | `admin@soclite.local` | `Admin2026!` |
| Supervisor | `supervisor@soclite.local` | `Supervisor2026!` |
| Analista | `analista@soclite.local` | `Analista2026!` |
| Auditor | `auditor@soclite.local` | `Auditor2026!` |
| Consulta | `consulta@soclite.local` | `Consulta2026!` |

> Solo para `DEMO_MODE=true`. En producción desactive las cuentas demo, cambie claves y elimine `db/init/02_seed.sql` o sustitúyalo por un seed institucional.

---

## 4. Arquitectura en 30 segundos

```text
Wazuh / OPNsense
      │ webhook
      ▼
    n8n  ── normaliza, deduplica, enruta, notifica, crea ticket
      │                         │
      │ POST /triage            │ SQL
      ▼                         ▼
LangChain + Ollama        PostgreSQL
      │                         ▲
      └── veredicto/acciones ───┘
                                ▲
React + TypeScript ── REST ── FastAPI ── reportes PDF/DOCX/XLSX
```

| Capa | Tecnología |
|---|---|
| Frontend | React 19, TypeScript, Vite 6, Tailwind 3.4, TanStack Query, React Router, Axios |
| Backend | FastAPI, SQLAlchemy 2.0, Pydantic 2, PyJWT, bcrypt, ReportLab, python-docx, openpyxl |
| IA | LangChain, Ollama (llama3.1/mistral), herramientas custom, fallback heurístico |
| Orquestación | n8n 1.111+ |
| Datos | PostgreSQL 16+ |
| Infra | Docker Compose, nginx, healthchecks |

Detalle completo, diagramas, modelo de datos, RBAC, endpoints, n8n, datasets y sizing: [`docs/ARQUITECTURA_SOC_LITE.md`](docs/ARQUITECTURA_SOC_LITE.md).

---

## 5. Estructura del repositorio

```text
.
├── backend/                 # FastAPI, modelos, servicios, tests
├── ai-service/              # microservicio LangChain
├── frontend/                # React + Vite
├── db/
│   ├── init/01_schema.sql   # DDL PostgreSQL
│   ├── init/02_seed.sql     # datos demo para Docker
│   └── seed_demo.sql        # copia del seed para importación manual
├── n8n/                     # workflow importable
├── docs/
│   ├── ARQUITECTURA_SOC_LITE.md
│   └── screenshots/
├── docker-compose.yml
├── docker-compose.demo.yml
└── .env.example
```

---

## 6. Desarrollo local

### Backend

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend\requirements-dev.txt

$env:PYTHONPATH="backend"
$env:DATABASE_URL="postgresql+psycopg://soc_lite:soc_lite_dev_password@localhost:5432/soc_lite"
$env:TRIAGE_MODE="heuristic"
python -m app.seed --reset
uvicorn app.main:app --reload --port 8000
```

Sin PostgreSQL local, para pruebas rápidas:

```powershell
$env:DATABASE_URL="sqlite:///./storage/dev.db"
$env:AUTO_SEED="true"
$env:TRIAGE_MODE="heuristic"
uvicorn app.main:app --reload --port 8000
```

> SQLite es solo para desarrollo/pruebas. La base principal y el esquema de producción son PostgreSQL.

### Frontend

```bash
cd frontend
npm ci
npm run dev
# http://localhost:5173 (proxy /api -> :8000)
```

### Microservicio IA

```bash
cd ai-service
pip install -r requirements.txt
$env:LLM_PROVIDER="heuristic"   # o auto/ollama/openai
uvicorn app.main:app --reload --port 8001
```

---

## 7. Pruebas

```powershell
$env:PYTHONPATH="backend"
python -m unittest discover -s backend/tests -v
```

Cobertura funcional: salud, dashboard, alertas, triaje, RBAC, ingesta idempotente, reportes PDF/DOCX/XLSX, auditoría, usuarios y refresh/logout.

Build del frontend:

```bash
cd frontend
npm run build
```

Verificaciones realizadas en este repositorio:

- 9/9 pruebas de integración del backend y 4/4 del microservicio IA.
- Esquema y seed aplicados en PostgreSQL 17.
- Reportes PDF, Word y Excel generados y descargados.
- Build de React/TypeScript OK (~532 KB, 158 KB gzip).
- Workflow importado correctamente en n8n 1.111.1.

---

## 8. n8n

1. Importar `n8n/soc-lite-triage-workflow.json`.
2. Configurar credenciales PostgreSQL, Slack y osTicket.
3. Igualar `SOC_AI_INTERNAL_KEY` (n8n) con `INTERNAL_API_KEY` (AI) y `TRIAGE_API_KEY` (backend).
4. Activar y apuntar Wazuh/OPNsense a `POST /webhook/soc-lite-alert`.

El flujo conserva los 10 nodos funcionales del caso y añade normalización explícita, control de duplicado y persistencia de enriquecimiento. Ver sección 5 del documento de arquitectura.

---

## 9. Seguridad y cumplimiento

- **ISO/IEC 27001:2022:** A.8.15, A.8.16, A.5.24, A.5.25, A.5.26, A.5.7.
- **NIST CSF 2.0:** DETECT (DE.AE), RESPOND (RS.MA/AN/CO/MI), IDENTIFY y PROTECT.
- **NIST SP 800-61r3:** fases de respuesta y lecciones aprendidas.
- **Privacidad:** Ollama local por defecto; enriquecimiento externo opcional; minimización y retención de datos.

Checklist de producción y riesgos residuales en [`docs/ARQUITECTURA_SOC_LITE.md`](docs/ARQUITECTURA_SOC_LITE.md), secciones 8–10.

---

## 10. Licencia y uso

Proyecto académico / interno. Las librerías y datasets de terceros conservan sus licencias. No se incluyen datos reales de organizaciones; las alertas, IPs y activos del seed son sintéticos o usan rangos de documentación.

---

**SOC-Lite · Menos ruido, más decisiones.**
