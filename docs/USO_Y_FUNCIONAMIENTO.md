# Uso y Funcionamiento

Esta version es una demo local muy simple. La meta es mostrar que el control de identidades funciona, no simular un IAM completo.

## Que se simplifico

- No usa autenticacion externa.
- No usa JWT.
- No depende de MySQL para la demo.
- No necesita migraciones manuales.
- No usa sesiones ni cookies; el login redirige a una vista demo.

## Que se mantiene

- Identidad local.
- Un rol por usuario.
- Permisos por rol.
- Estados `pending`, `active`, `revoked`, `expired`.
- Auditoria de acciones.
- Emision de certificados X.509 con CA interna para administradores y coordinadores.
- Login demostrativo con `.p12`, contrasena y firma de reto.
- Login local de voluntarios con correo y contrasena.
- Vigencia criptografica ligada a `end_date`.
- Vistas diferentes por nivel de usuario.

## Como arranca

1. FastAPI levanta la app.
2. SQLAlchemy crea las tablas automaticamente.
3. Se insertan roles, permisos y usuarios demo si la base esta vacia.
4. Si no existe, se crea una autoridad certificadora interna.
5. La pantalla inicial de login se sirve desde `GET /`.

## Flujo de la interfaz

1. Entras por `GET /`, que muestra la pantalla de login.
2. Administradores y coordinadores se autentican con correo, archivo `.p12` y contrasena.
3. Para pruebas rapidas puedes usar `admin` / `admin` sin certificado.
4. Los voluntarios se autentican con correo y contrasena, sin `.p12`.
5. La app calcula permisos con base en el rol.
6. Si es administrador, puede otorgar registros, activar, revocar, cambiar expiracion, cambiar rol y emitir certificados.
7. Al crear administrador o coordinador, el backend genera llave privada, certificado X.509 y paquete `.p12`.
8. Al crear voluntario, el backend guarda un hash PBKDF2-HMAC-SHA256 de su contrasena.
9. Cada accion deja un evento en la bitacora.
10. Si un usuario no es administrador activo, aunque intente abrir `/dashboard`, se le muestra su vista de rol.

## Usuarios demo iniciales

- `Admin Demo`
- `Cora Coordinadora`
- `Vale Voluntaria`

## Archivos clave

- [app/main.py](/Users/javier/Documents/New%20project/app/main.py): interfaz y rutas.
- [app/services.py](/Users/javier/Documents/New%20project/app/services.py): seed, permisos, usuarios, auditoria y certificados.
- [app/models.py](/Users/javier/Documents/New%20project/app/models.py): tablas.
- [app/db.py](/Users/javier/Documents/New%20project/app/db.py): base local.

## Uso rapido

```bash
pip install -e .
uvicorn app.main:app --reload
```

Luego abre `http://127.0.0.1:8000`.

## Certificados

- La CA se guarda en `generated/certs/ca/`.
- Los `.p12` de usuarios se guardan en `generated/certs/users/`.
- La UI permite ver el certificado en navegador, descargar el certificado de la CA, el certificado PEM del usuario y el `.p12`.
- Los certificados de administradores y coordinadores vencen exactamente en la fecha `end_date` del usuario.
- Cuando se cambia la vigencia de un usuario criptografico, se reemite su certificado y su `.p12`.
- Los voluntarios no usan certificados.

## Firmas criptograficas usadas

- Certificado de la CA: X.509 autofirmado con RSA 2048 y SHA-256.
- Certificado de usuario: X.509 con llave publica RSA 2048, firmado por la CA con SHA-256.
- Archivo `.p12`: no es una firma; es un contenedor cifrado que guarda la llave privada del usuario, su certificado y el certificado de la CA.
- Login con `.p12`: el backend descifra el `.p12`, verifica que el certificado fue firmado por la CA y firma un reto temporal con la llave privada del usuario usando RSA-PSS-SHA256.
- Verificacion del login: el backend valida esa firma con la llave publica del certificado del usuario.
- Login voluntario: se valida contrasena local con PBKDF2-HMAC-SHA256; no hay firma criptografica de usuario.

## Vistas principales

- `GET /login`: pantalla de acceso; `.p12` para administradores/coordinadores, contrasena local para voluntarios.
- `GET /portal?as_user=ID`: portal del usuario con contenido segun rol.
- `GET /admin/register?as_user=ID`: pantalla de administrador para otorgar un registro, emitir certificado y entregar `.p12`.
- `GET /`: pantalla inicial de login.
- `GET /dashboard`: dashboard tecnico solo para administrador activo.

## Acciones de cuenta en el panel admin

- `Activar`: sirve para usuarios nuevos o revocados.
- `Revocar`: bloquea el acceso del usuario.
- `Cambiar fecha`: para administradores/coordinadores reemite `.p12`; para voluntarios solo actualiza `end_date`. Si estaba `expired` y la fecha es futura, vuelve a `active`.
