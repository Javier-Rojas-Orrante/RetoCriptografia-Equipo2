# Gestor de Identidades Demo

Demo minimalista en FastAPI para mostrar:

- login por usuario o correo y contrasena,
- 4 roles visibles: `ADMIN`, `COORDINADOR`, `OPERATIVO`, `VOLUNTARIO`,
- revocacion de emergencia que invalida el acceso de inmediato,
- expiracion y reactivacion de cuentas,
- respaldo espejo del administrador,
- auditoria basica,
- historico criptografico solo de consulta.

## Estado actual

La demo ya no usa certificados para autenticacion normal.
Los certificados existentes permanecen solo como historico legacy visible para administracion.

## Como correrlo

```bash
pip install -e .
uvicorn app.main:app --reload
```

Abre [http://127.0.0.1:8000](http://127.0.0.1:8000).

## Credenciales demo

- `admin / admin`
- `coordinador / demo1234`
- `operativo / demo1234`
- `voluntario / demo1234`
- respaldo espejo admin: `admin.respaldo@demo.local / respaldo1234`

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
