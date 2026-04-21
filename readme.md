# Gestor de Identidades Demo

Version minima para demostrar funcionamiento con interfaz web.

## Que hace

- Crea usuarios demo.
- Cambia roles.
- Activa o revoca cuentas.
- Calcula permisos efectivos por rol.
- Registra auditoria basica.
- Emite certificados X.509 firmados por una CA interna.
- Entrega la llave privada en un `.p12` protegido con contrasena.
- Permite login demo con `.p12` y firma de reto.
- Permite bypass de prueba con `admin` / `admin` sin certificado.
- Muestra vistas distintas por rol.

## Como correrlo

2. Instala dependencias con `pip install -e .`.
3. Ejecuta `uvicorn app.main:app --reload`.
4. Abre [http://127.0.0.1:8000](http://127.0.0.1:8000).

La app crea automaticamente una base SQLite local y carga datos demo la primera vez.
Tambien crea una CA interna local y guarda los certificados emitidos en `generated/certs/`.

## Rutas utiles

- `GET /`
- `GET /login`
- `GET /dashboard` solo administrador activo
- `GET /portal?as_user=1`
- `GET /admin/register?as_user=1`
- `GET /health`
- `GET /api/me?as_user=1`
- `GET /api/users?as_user=1`
- `GET /api/audit-logs?as_user=1`
- `GET /ui/users/{id}/certificate/view?as_user=1`
- `GET /ui/ca/certificate/view`
- `GET /ui/ca/certificate`

## Documentacion

- [docs/USO_Y_FUNCIONAMIENTO.md](/Users/javier/Documents/New%20project/docs/USO_Y_FUNCIONAMIENTO.md)
