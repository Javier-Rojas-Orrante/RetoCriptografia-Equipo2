# Gestor de Identidades Demo

Demo minimalista en FastAPI para mostrar:

- login mixto: `.p12` para `ADMIN` y `COORDINADOR`, contrasena para `OPERATIVO` y `VOLUNTARIO`,
- 4 roles visibles: `ADMIN`, `COORDINADOR`, `OPERATIVO`, `VOLUNTARIO`,
- revocacion de emergencia que invalida el acceso de inmediato,
- expiracion y reactivacion de cuentas,
- respaldo espejo del administrador,
- auditoria basica,
- certificados X.509 emitidos por una CA interna para administradores y coordinadores.

## Estado actual

`ADMIN` y `COORDINADOR` volvieron a usar autenticacion criptografica con `.p12`.
`OPERATIVO` y `VOLUNTARIO` siguen con acceso por usuario o correo y contrasena.
El panel admin ahora muestra usuarios en filas compactas expandibles para ordenar la gestion.

## Como correrlo

```bash
pip install -e .
uvicorn app.main:app --reload
```

Abre [http://127.0.0.1:8000](http://127.0.0.1:8000).

## Credenciales demo

- `admin / admin`
- `admin@demo.local + .p12 + admin`
- `coordinador@demo.local + .p12 + demo1234`
- `operativo / demo1234`
- `voluntario / demo1234`
- respaldo espejo admin: `admin.respaldo@demo.local + .p12 + respaldo1234`

Tambien puedes entrar usando los correos completos:

- `admin@demo.local`
- `coordinador@demo.local`
- `operativo@demo.local`
- `voluntario@demo.local`

## Rutas principales

- `GET /`
- `GET /login`
- `POST /login`
- `GET /portal?as_user=ID`
- `GET /dashboard?as_user=ID`
- `GET /admin/register?as_user=ID`
- `GET /api/me?as_user=ID`
- `GET /api/users?as_user=ID`
- `GET /api/audit-logs?as_user=ID`

## Documentacion

- [Manual de usuario](/Users/javier/Documents/New%20project/docs/USO_Y_FUNCIONAMIENTO.md)
- [Documentacion de codigo fuente](/Users/javier/Documents/New%20project/docs/DOCUMENTACION_FUNCIONAMIENTO.md)
- [Guia de integracion (SDK)](/Users/javier/Documents/New%20project/docs/GUIA_INTEGRACION_SDK.md)
- [Investigacion de recuperacion admin](/Users/javier/Documents/New%20project/docs/INVESTIGACION_RECUPERACION_ADMIN.md)
- [Cierre de demo de viernes](/Users/javier/Documents/New%20project/docs/CIERRE_DEMO_VIERNES.md)
