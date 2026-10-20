# Scripts de desarrollo

## Cargar datos semilla en PostgreSQL

```powershell
.\scripts\seed.ps1 -DatabaseUrl "postgresql+psycopg://soc_lite:soc_lite_dev_password@localhost:5432/soc_lite"
```

El script requiere `PYTHONPATH=backend` y las dependencias instaladas
(`pip install -r backend/requirements-dev.txt`). Es idempotente; `--reset` recrea
el esquema y los datos demo.

## Ejecutar pruebas

```powershell
.\scripts\test.ps1
```

Ejecuta las pruebas de integración del backend y del microservicio IA.
