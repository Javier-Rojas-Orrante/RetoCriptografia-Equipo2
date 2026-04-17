# Documentacion de Funcionamiento

Este documento explica como funciona la version actual del gestor de identidades demo en la rama `certificado-alt`.

## 1. Objetivo

La aplicacion demuestra de forma minima estos flujos:

- gestion local de usuarios,
- asignacion de un rol por usuario,
- autorizacion por permisos,
- cambio de estado de cuenta,
- auditoria de acciones,
- emision de certificados X.509 con una CA interna,
- descarga y visualizacion de certificados desde la interfaz.

No intenta ser un IAM completo ni una PKI enterprise. Es una demo funcional y mantenible.

## 2. Resumen de la arquitectura

La aplicacion usa:

- `FastAPI` para servidor web y rutas,
- `SQLAlchemy` para persistencia,
- `SQLite` como base local de la demo,
- `cryptography` para la CA, certificados y `.p12`.

Flujo general:

1. La app arranca.
2. Se crean tablas si no existen.
3. Se insertan roles, permisos y usuarios demo si la base esta vacia.
4. Se crea una autoridad certificadora interna si no existe.
5. La UI se sirve desde `GET /`.

## 3. Componentes principales

### [app/main.py](/Users/javier/Documents/New%20project/app/main.py)

Contiene:

- el arranque de la app,
- el dashboard HTML,
- las rutas API,
- las rutas de UI para crear usuarios, cambiar estado y rol,
- las rutas para descargar y ver certificados.

### [app/services.py](/Users/javier/Documents/New%20project/app/services.py)

Contiene la logica principal:

- `AuditService`
- `BootstrapService`
- `SchemaService`
- `CertificateAuthorityService`
- `CertificateService`
- `AuthorizationService`
- `UserService`

### [app/models.py](/Users/javier/Documents/New%20project/app/models.py)

Define las tablas:

- `roles`
- `users`
- `permissions`
- `role_permissions`
- `audit_logs`

### [app/db.py](/Users/javier/Documents/New%20project/app/db.py)

Configura la conexion SQLAlchemy y habilita SQLite local.

### [app/config.py](/Users/javier/Documents/New%20project/app/config.py)

Lee variables de entorno como:

- `APP_NAME`
- `APP_HOST`
- `APP_PORT`
- `DATABASE_URL`
- `CERTS_DIR`

## 4. Modelo de datos

## 4.1 Usuarios

La tabla `users` guarda:

- identidad local,
- rol,
- estado,
- vigencia,
- metadatos del certificado emitido.

Campos de certificado usados actualmente:

- `certificate_serial`
- `certificate_pem`
- `certificate_not_before`
- `certificate_not_after`
- `p12_path`

## 4.2 Roles y permisos

Cada usuario tiene un solo rol.

Los roles se cargan desde `ROLE_DEFINITIONS`:

- `ADMIN`
- `HUMANITARIA`
- `LEGAL_TI`
- `LECTURA`
- `EXTERNAL`

Cada rol tiene una lista fija de permisos `(resource, action)`.

## 4.3 Auditoria

Cada accion relevante escribe un registro en `audit_logs`.

Ejemplos:

- `user_created`
- `certificate_issued`
- `user_activated`
- `user_revoked`
- `role_changed`
- `access_denied`

## 5. Usuarios demo iniciales

Si la base esta vacia, la app crea:

- `Admin Demo` con rol `ADMIN`
- `Ana Humanitaria` con rol `HUMANITARIA`
- `Luis Externo` con rol `EXTERNAL`

Eso permite probar la UI sin carga manual.

## 6. Flujo de autorizacion

La demo no usa login real.

En lugar de eso:

1. El usuario selecciona en la UI con que identidad actuar.
2. El backend toma ese usuario como actor actual.
3. Se calculan sus permisos con base en el rol.
4. Cada accion valida `resource` y `action`.
5. Si no tiene permiso, se registra `access_denied`.

La funcion central esta en `AuthorizationService.authorize`.

## 7. Flujo de certificados

## 7.1 CA interna

La autoridad certificadora se maneja en `CertificateAuthorityService`.

Al arrancar:

1. Se revisa si existe la CA.
2. Si no existe, se genera una llave RSA.
3. Se construye un certificado CA autofirmado.
4. Se guardan:
   - `generated/certs/ca/ca-key.pem`
   - `generated/certs/ca/ca-cert.pem`

## 7.2 Emision para usuarios

Cuando se crea un usuario desde la UI:

1. Se crea el registro en `users`.
2. Se genera un par de llaves RSA para ese usuario.
3. Se construye un certificado X.509.
4. La CA lo firma.
5. Se serializa la llave privada con el certificado en un `.p12`.
6. El `.p12` se protege con la contrasena capturada en el formulario.
7. Se guardan en la base:
   - serial,
   - PEM del certificado,
   - vigencia,
   - ruta del `.p12`.
8. Se registra auditoria.

Si la emision falla, el usuario recien creado se elimina para no dejar un preregistro incompleto.

## 7.3 Reemision

Si un usuario no tiene certificado o se quiere regenerar, existe una accion de UI para emitirlo otra vez con una nueva contrasena de `.p12`.

## 8. Visualizacion de certificados

La aplicacion ya no solo permite descargar los certificados. Tambien permite verlos en navegador.

## 8.1 Vista de certificado de usuario

Ruta:

- `GET /ui/users/{user_id}/certificate/view?as_user={actor_id}`

Muestra:

- sujeto,
- emisor,
- serial,
- fecha de inicio,
- fecha de expiracion,
- fingerprint SHA-256,
- SAN de correo,
- PEM completo.

## 8.2 Vista de certificado de la CA

Ruta:

- `GET /ui/ca/certificate/view`

Muestra los mismos datos, pero para la autoridad certificadora interna.

## 8.3 Descargas disponibles

### Certificado de usuario en PEM

- `GET /ui/users/{user_id}/certificate.pem?as_user={actor_id}`

### Paquete `.p12`

- `GET /ui/users/{user_id}/certificate.p12?as_user={actor_id}`

### Certificado PEM de la CA

- `GET /ui/ca/certificate`

## 9. Interfaz principal

La UI principal esta en:

- `GET /`

Desde ahi se puede:

- cambiar el usuario actual,
- ver permisos efectivos,
- crear usuarios,
- activar o revocar cuentas,
- cambiar rol,
- emitir certificados,
- descargar `.p12`,
- descargar PEM,
- ver certificados en HTML,
- consultar auditoria reciente.

## 10. Rutas principales

## 10.1 Salud

- `GET /health`

## 10.2 API ligera

- `GET /api/me?as_user=1`
- `GET /api/users?as_user=1`
- `GET /api/audit-logs?as_user=1`

## 10.3 Acciones UI

- `POST /ui/users`
- `POST /ui/users/{user_id}/status`
- `POST /ui/users/{user_id}/role`
- `POST /ui/users/{user_id}/certificate`

## 10.4 Certificados

- `GET /ui/users/{user_id}/certificate/view`
- `GET /ui/users/{user_id}/certificate.pem`
- `GET /ui/users/{user_id}/certificate.p12`
- `GET /ui/ca/certificate/view`
- `GET /ui/ca/certificate`

## 11. Seguridad actual de la demo

Esta version tiene medidas basicas, no completas:

- el `.p12` se cifra con contrasena,
- el certificado de usuario solo puede verlo o descargarlo el propio usuario o un actor con permisos administrativos,
- la CA se guarda localmente en disco.

Limitaciones importantes:

- la llave privada de la CA esta sin cifrado en el filesystem local,
- no hay HSM,
- no hay CRL ni OCSP,
- no hay revocacion criptografica real del certificado,
- el control de acceso es una simulacion local de actor, no autenticacion real.

## 12. Flujo recomendado para probar

1. Instalar dependencias:

```bash
pip install -e .
```

2. Ejecutar la app:

```bash
uvicorn app.main:app --reload
```

3. Abrir:

```text
http://127.0.0.1:8000
```

4. Elegir `Admin Demo`.
5. Crear un usuario nuevo con contrasena de `.p12`.
6. En la tabla, usar:
   - `Ver certificado`
   - `Certificado PEM`
   - `Descargar .p12`
7. Abrir `Ver certificado CA` para revisar el certificado de la autoridad.

## 13. Archivos generados en runtime

- `identity_demo.db`
- `generated/certs/ca/ca-key.pem`
- `generated/certs/ca/ca-cert.pem`
- `generated/certs/users/*.p12`

## 14. Limitaciones funcionales

- un solo rol por usuario,
- sin login real,
- sin renovacion automatica,
- sin revocacion criptografica de certificados,
- sin almacenamiento seguro de secretos,
- sin panel separado para administracion de CA.

## 15. Conclusion

La version actual ya demuestra el flujo completo pedido de forma simple:

- existe una CA interna,
- se emiten certificados X.509,
- se entrega un `.p12` con contrasena,
- se guardan metadatos del certificado,
- se pueden ver y descargar certificados desde la UI.
