# Gestor de Identidades Demo

Demo minimalista en FastAPI para mostrar:

- login mixto: `.p12` para `ADMIN` y `COORDINADOR`, contrasena para `OPERATIVO` y `VOLUNTARIO`,
- 4 roles visibles: `ADMIN`, `COORDINADOR`, `OPERATIVO`, `VOLUNTARIO`,
- revocacion de emergencia que invalida el acceso de inmediato,
- expiracion y reactivacion de cuentas,
- respaldo espejo del administrador,
- auditoria basica,
- certificados X.509 donde el administrador usa un certificado autofirmado y firma los certificados de coordinadores,
- material criptografico centralizado con administrador firmante en la base de datos compartida.

## Estado actual

`ADMIN` y `COORDINADOR` volvieron a usar autenticacion criptografica con `.p12`.
`OPERATIVO` y `VOLUNTARIO` siguen con acceso por usuario o correo y contrasena.
El panel admin ahora muestra usuarios en filas compactas expandibles para ordenar la gestion.
El material del administrador firmante y los paquetes `.p12` se almacenan de forma centralizada en la base de datos.

## Como correrlo

```bash
pip install -e .
uvicorn app.main:app --reload
```

Abre [http://127.0.0.1:8000](http://127.0.0.1:8000).

## Credenciales demo

Estas credenciales solo existen cuando `SEED_DEMO_DATA=true`.

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
- [Revision criptografica](/Users/javier/Documents/New%20project/docs/REVISION_CRIPTOGRAFICA.md)
- [Guia de integracion (SDK)](/Users/javier/Documents/New%20project/docs/GUIA_INTEGRACION_SDK.md)
- [Investigacion de recuperacion admin](/Users/javier/Documents/New%20project/docs/INVESTIGACION_RECUPERACION_ADMIN.md)
- [Cierre de demo de viernes](/Users/javier/Documents/New%20project/docs/CIERRE_DEMO_VIERNES.md)

## Publicarlo para no correrlo local

El repo ya queda preparado para desplegarse con Docker y con un `render.yaml` opcional.

### Opcion recomendada: Render

1. Sube este repo a GitHub.
2. En Render, crea un Blueprint nuevo apuntando al repo.
3. Revisa el plan del web service y de Postgres antes de confirmar la creacion.
4. Durante el alta inicial define:
   - `BOOTSTRAP_ADMIN_FULL_NAME`
   - `BOOTSTRAP_ADMIN_EMAIL`
   - `BOOTSTRAP_ADMIN_PASSWORD`
5. En produccion la app arranca con:
   - `SEED_DEMO_DATA=false`
   - `SESSION_COOKIE_SECURE=true`
   - `SESSION_SECRET` aleatorio
   - `DATABASE_URL` tomado de Postgres administrado

### Primer acceso en produccion

- El administrador inicial puede entrar con correo + contrasena mientras todavia no tenga certificado emitido.
- En cuanto entre, puede emitir su `private_key.pem` y `certificate.pem` desde el panel.
- Los usuarios demo y el bypass `admin / admin` quedan desactivados cuando `SEED_DEMO_DATA=false`.

### Docker generico

```bash
docker build -t gestor-identidades .
docker run --rm -p 8000:8000 \
  -e ENVIRONMENT=production \
  -e SESSION_SECRET=define-un-secreto-largo \
  -e SESSION_COOKIE_SECURE=false \
  -e SEED_DEMO_DATA=false \
  -e BOOTSTRAP_ADMIN_FULL_NAME="Administrador General" \
  -e BOOTSTRAP_ADMIN_EMAIL=admin@tu-dominio.com \
  -e BOOTSTRAP_ADMIN_PASSWORD=define-una-clave-segura \
  -e DATABASE_URL=sqlite:////app/data/identity_demo.db \
  gestor-identidades
```

Si lo vas a publicar en internet, usa Postgres administrado en lugar de SQLite.
