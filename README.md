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
- **Apariencia**: modos claro y oscuro desde el botón del encabezado o de acceso; la elección se guarda en este navegador.
- **Gestión**: alertas, detalle con evidencia, acciones recomendadas, escalamiento a incidente y cierre como falso positivo.
- **Reportes**: operacional, de gestión y de auditoría en PDF, DOCX y XLSX.
- **Seguridad**: JWT con refresh rotado, bcrypt, RBAC de 5 roles/16 permisos, rate limit de login y cabeceras seguras.
- **Auditoría**: login/logout, entradas/salidas por módulo, accesos API, triajes, cambios, exportaciones y descargas.

---

## 2. Arranque rápido con Docker

Requisitos: Docker Engine 24+ y Docker Compose v2.

```bash
cp .env.example .env
# Edite .env: SECRET_KEY, POSTGRES_PASSWORD, DATABASE_URL, INGEST_API_KEY,
# TRIAGE_API_KEY, N8N_DB_PASSWORD y N8N_ENCRYPTION_KEY

docker compose up -d --build
```

Servicios:

| URL | Servicio |
|---|---|
| http://localhost:8080 | Interfaz web |
| http://localhost:8000/docs | OpenAPI / Swagger |
| http://localhost:8000/health | Salud de la API |
| http://localhost:8001/health | Salud del microservicio IA |
| http://localhost:5678 | Editor n8n (solo desde el host) |

El primer arranque crea el esquema y los datos demo desde `db/init/`. El backend verifica la semilla con `AUTO_SEED=true`. n8n usa su propia base PostgreSQL (`n8n-db`) y conserva su configuración y credenciales en volúmenes Docker. La interfaz web y n8n escuchan solo en `127.0.0.1` por defecto.

Si el puerto local `5432` está ocupado o reservado, cambie `POSTGRES_HOST_PORT` en `.env` (por ejemplo, a `15432`). La conexión entre contenedores sigue usando `db:5432`.

### Modelo local opcional

```bash
docker compose --profile llm up -d ollama
docker compose exec ollama ollama pull llama3.1:8b
```

Sin Ollama, el microservicio usa el motor heurístico (o el backend cae a él si `TRIAGE_MODE=auto`). Para una demo sin GPU y con n8n en el mismo Compose, establezca `LLM_PROVIDER=heuristic` en `.env` y ejecute:

```bash
docker compose up -d --build
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
$env:LLM_PROVIDER="heuristic"   # o auto/ollama/openai/groq
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

1. Iniciar los servicios con `docker compose up -d --build` y abrir `http://localhost:5678` para crear el usuario propietario de n8n.
2. Importar `n8n/soc-lite-triage-workflow.json`.
3. Crear la credencial PostgreSQL del workflow con host `db`, puerto `5432`, base y usuario definidos por `POSTGRES_DB` y `POSTGRES_USER`, y la contraseña `POSTGRES_PASSWORD`. Esta es la base de SOC-Lite; `n8n-db` almacena únicamente los datos internos de n8n.
4. Configurar las credenciales Slack y osTicket si se usarán esas integraciones. `SOC_AI_INTERNAL_KEY` se toma automáticamente de `TRIAGE_API_KEY` en Compose.
5. Revisar las credenciales y URL internas del workflow; después activarlo y apuntar Wazuh/OPNsense a `POST /webhook/soc-lite-alert`.

### osTicket local para el nodo 11

osTicket es opcional. La imagen `rinkp/osticket-dockerized:1.18.4` es comunitaria; los datos y adjuntos se guardan en volúmenes Docker. Esta integración usa la API de tickets de osTicket, no HTTP Basic.

1. Definir en `.env` los valores `OSTICKET_DB_PASSWORD`, `OSTICKET_SECRET_SALT`, `OSTICKET_ADMIN_EMAIL`, `OSTICKET_ADMIN_PASSWORD` y `OSTICKET_REQUESTER_EMAIL`. Usar contraseñas aleatorias propias y no subir `.env` al repositorio.
2. Iniciar los servicios con `docker compose -f docker-compose.yml -f docker-compose.osticket.yml up -d osticket n8n` y abrir `http://localhost:8088/`, que redirige al panel de agentes `/scp/`. El portal de clientes permanece en `http://localhost:8088/index.php`. Entrar con `OSTICKET_ADMIN_EMAIL` y `OSTICKET_ADMIN_PASSWORD` de `.env`. En el primer acceso, osTicket obliga a cambiar la contraseña; actualizar después `OSTICKET_ADMIN_PASSWORD` en `.env` para conservar la referencia local.
3. En el panel de administración de osTicket, ir a **Manage → API Keys → Add New API Key**. Crear una clave para la IP de origen `172.30.91.10` (IP fija de n8n en la red de osTicket), permitir **Create Tickets**, guardar y copiar la clave. La clave está asociada a esa IP.
4. En n8n, crear una credencial **Header Auth** para el nodo 11: **Name** `X-API-Key`, **Value** la clave recién creada. Configurar el nodo como **HTTP Request**, método **POST**, URL `http://osticket/api/tickets.json`, autenticación **Generic Credential Type → Header Auth**, cuerpo **JSON**. El archivo `n8n/soc-lite-triage-workflow.json` contiene el cuerpo compatible con la API de osTicket; si el flujo ya estaba importado, actualizar manualmente el nodo 11 con esos valores.
5. Probar el nodo con una alerta alta o crítica nueva y comprobar que aparece un ticket en osTicket. Activar el nodo 11 cuando la prueba funcione. Las alertas medias y bajas siguen la ruta directa de auditoría.

Si n8n no se inició con ambos archivos Compose, no resolverá el nombre interno `osticket`. Conservar la IP fija `172.30.91.10` al recrear n8n para que la clave API siga siendo válida. No exponer el puerto 8088 fuera del equipo sin configurar HTTPS y autenticación apropiada.

El nodo 7 envía el resultado tanto al nodo 8 (enriquecimiento) como al 9 (enrutamiento). Si se importó una versión anterior del flujo, conecte 7 → 9 y quite la conexión 8 → 9; así el enrutamiento recibe `recommended_severity` aunque el enriquecimiento no genere filas.

### Groq y asignación automática

El microservicio admite `LLM_PROVIDER=groq` con la API compatible con OpenAI de Groq. En el archivo local `.env`, configurar `GROQ_API_KEY` y `GROQ_MODEL` (por defecto `openai/gpt-oss-20b`). Mantener la clave fuera del repositorio y del navegador. Ejecutar `docker compose -f docker-compose.yml -f docker-compose.osticket.yml up -d --no-deps ai-service` para cargar la clave cuando esté lista. `GET http://localhost:8001/health` indica `llm_provider=groq` y `llm_configured=true`; cada resultado de triaje debe indicar `engine=groq`. Si falta la clave o Groq falla, el servicio conserva el fallback heurístico y el resultado indica `engine=heuristic-fallback`.

El resultado de triaje incluye `routing_team`: `soc_l1`, `soc_l2`, `infrastructure` o `soc_lead`. La IA recomienda el equipo; n8n solo asigna una persona si el correo configurado corresponde a un usuario activo de SOC-Lite con permiso `alerts:update`. Definir en `.env` los correos `SOC_L1_ASSIGNEE_EMAIL`, `SOC_L2_ASSIGNEE_EMAIL`, `INFRASTRUCTURE_ASSIGNEE_EMAIL` y `SOC_LEAD_ASSIGNEE_EMAIL`, y ejecutar `docker compose -f docker-compose.yml -f docker-compose.osticket.yml up -d --no-deps n8n` para cargarlos. Se conserva cualquier asignación humana previa. Si no hay correspondencia válida, la alerta queda sin asignar para revisión.

Para osTicket, crear los agentes que atenderán tickets y cuatro temas de ayuda con **Auto-Assign** al agente o equipo apropiado. Colocar sus IDs en `OSTICKET_TOPIC_SOC_L1`, `OSTICKET_TOPIC_SOC_L2`, `OSTICKET_TOPIC_INFRASTRUCTURE` y `OSTICKET_TOPIC_SOC_LEAD`. El nodo 11 envía el `topicId` correspondiente; si no hay ID configurado, osTicket recibe el ticket sin ese tema. El workflow ya importado en n8n no cambia por editar el JSON del repositorio: se deben actualizar sus nodos 7 y 11 preservando sus credenciales y probar con una alerta nueva.

### Sincronizar el cierre de tickets

Con osTicket local, iniciar también `osticket-sync`:

```powershell
docker compose -f docker-compose.yml -f docker-compose.osticket.yml up -d --build backend frontend osticket-sync
```

El servicio lee los tickets de osTicket cada `OSTICKET_SYNC_INTERVAL_SECONDS` segundos (20 por defecto). Solo procesa tickets creados por API con el correo `OSTICKET_REQUESTER_EMAIL` y el `Alerta ID: UUID` que incluye el nodo 11. El número y estado del ticket aparecen en el detalle de la alerta. Cuando un agente cierra el ticket, la alerta pasa a **Cerrada** en SOC-Lite; si reabre ese mismo ticket, recupera su estado anterior siempre que el cierre lo haya aplicado esta integración. Cada cambio queda en Auditoría. Los tickets anteriores que ya contienen ese identificador también se enlazan al arrancar. Los incidentes de SOC-Lite se mantienen independientes y deben resolverse en su propio flujo.

La sincronización consulta la base de osTicket porque su API pública solo permite crear tickets. El proceso no escribe en la base de osTicket y usa la cuenta de base configurada para la instalación local. Para verificarlo, cerrar un ticket de prueba en el panel de agentes, esperar hasta 20 segundos y pulsar **Actualizar** en el detalle de la alerta de SOC-Lite. Si el ticket se reabre, repetir la consulta.

Para recibir webhooks desde otros equipos, publicar n8n mediante un proxy HTTPS y ajustar `N8N_HOST`, `N8N_PROTOCOL`, `N8N_EDITOR_BASE_URL`, `N8N_WEBHOOK_URL`, `N8N_PROXY_HOPS` y `N8N_SECURE_COOKIE=true` en `.env`. El puerto 5678 debe permanecer privado. Conserve `N8N_ENCRYPTION_KEY`: cambiarla después de crear credenciales impide descifrarlas.

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
