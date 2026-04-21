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
- descarga y visualizacion de certificados desde la interfaz,
- login demostrativo con `.p12` y firma de reto,
- vistas diferentes por rol.

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
- las rutas de login, portal por rol y registro administrativo.

### [app/services.py](/Users/javier/Documents/New%20project/app/services.py)

Contiene la logica principal:

- `AuditService`
- `BootstrapService`
- `SchemaService`
- `CertificateAuthorityService`
- `CertificateService`
- `SignatureLoginService`
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

## 6. Flujo de autorizacion y login

La demo mantiene dos entradas para que sea facil mostrar el sistema:

- Dashboard tecnico: `GET /`, donde se puede escoger un actor con `as_user`.
- Login demostrativo: `GET /login`, donde el usuario sube su `.p12` y escribe la contrasena.

El dashboard sigue siendo util para presentar administracion y pruebas rapidas. El login con `.p12` demuestra la parte criptografica estilo e.firma.

## 6.1 Dashboard tecnico

En esta vista:

1. El usuario selecciona en la UI con que identidad actuar.
2. El backend toma ese usuario como actor actual.
3. Se calculan sus permisos con base en el rol.
4. Cada accion valida `resource` y `action`.
5. Si no tiene permiso, se registra `access_denied`.

La funcion central esta en `AuthorizationService.authorize`.

## 6.2 Login con `.p12`

En esta vista:

1. El usuario escribe su correo.
2. Sube su archivo `.p12`.
3. Escribe la contrasena del `.p12`.
4. El backend abre el contenedor y extrae llave privada y certificado.
5. Se verifica que el usuario exista y este `active`.
6. Se verifica que el serial y correo del certificado correspondan al usuario.
7. Se verifica que el certificado siga vigente.
8. Se verifica que la CA interna firmo ese certificado.
9. El backend genera un reto temporal y lo firma con la llave privada del usuario.
10. El backend verifica esa firma con la llave publica del certificado.
11. Si todo pasa, registra `login_signature_verified` y redirige al portal.

Esto no crea una sesion persistente. Es intencional: para la demo basta con probar la identidad criptografica y mostrar la vista del usuario.

## 7. Firmas criptograficas usadas

| Paso | Firma usada | Para que sirve |
| --- | --- | --- |
| Creacion de la CA | X.509 autofirmado con RSA 2048 y SHA-256 | La organizacion crea su autoridad certificadora interna. |
| Emision de certificado de usuario | X.509 firmado por la CA con RSA y SHA-256 | La CA declara que esa llave publica pertenece al usuario local. |
| Archivo `.p12` | No es firma; es contenedor cifrado | Entrega la llave privada, certificado de usuario y certificado de CA protegidos con contrasena. |
| Login con `.p12` | RSA-PSS-SHA256 sobre un reto temporal | El usuario prueba que posee la llave privada sin revelarla. |
| Verificacion del login | Verificacion RSA-PSS-SHA256 con la llave publica del certificado | El backend confirma que la firma fue creada por la llave privada correspondiente. |

Ademas, antes de aceptar el login, el backend verifica la firma X.509 del certificado del usuario con la llave publica de la CA interna.

## 8. Flujo de certificados

## 8.1 CA interna

La autoridad certificadora se maneja en `CertificateAuthorityService`.

Al arrancar:

1. Se revisa si existe la CA.
2. Si no existe, se genera una llave RSA.
3. Se construye un certificado CA autofirmado.
4. Se guardan:
   - `generated/certs/ca/ca-key.pem`
   - `generated/certs/ca/ca-cert.pem`

## 8.2 Emision para usuarios

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

## 8.3 Reemision

Si un usuario no tiene certificado o se quiere regenerar, existe una accion de UI para emitirlo otra vez con una nueva contrasena de `.p12`.

## 9. Registro administrativo y vistas por rol

## 9.1 Otorgar registro

Ruta:

- `GET /admin/register?as_user={admin_id}`

El administrador captura:

- nombre,
- correo,
- rol,
- fecha opcional de expiracion,
- contrasena inicial del `.p12`.

Al enviar el formulario:

1. Se crea el usuario.
2. Se emite su certificado.
3. Se genera su `.p12`.
4. La cuenta queda `active` para que pueda probar el login inmediatamente.
5. Se registran auditorias `user_created`, `user_activated` y `certificate_issued`.

## 9.2 Portal por rol

Ruta:

- `GET /portal?as_user={user_id}`

La vista cambia segun el rol:

- `ADMIN`: administracion, registro y auditoria.
- `HUMANITARIA`: vista operativa humanitaria.
- `LEGAL_TI`: vista legal y tecnica.
- `LECTURA`: vista solo consulta.
- `EXTERNAL`: vista externa limitada.

## 10. Visualizacion de certificados

La aplicacion ya no solo permite descargar los certificados. Tambien permite verlos en navegador.

## 10.1 Vista de certificado de usuario

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

## 10.2 Vista de certificado de la CA

Ruta:

- `GET /ui/ca/certificate/view`

Muestra los mismos datos, pero para la autoridad certificadora interna.

## 10.3 Descargas disponibles

### Certificado de usuario en PEM

- `GET /ui/users/{user_id}/certificate.pem?as_user={actor_id}`

### Paquete `.p12`

- `GET /ui/users/{user_id}/certificate.p12?as_user={actor_id}`

### Certificado PEM de la CA

- `GET /ui/ca/certificate`

## 11. Interfaz principal

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
- entrar con `.p12`,
- abrir portal por rol,
- consultar auditoria reciente.

## 12. Rutas principales

## 12.1 Salud

- `GET /health`

## 12.2 API ligera

- `GET /api/me?as_user=1`
- `GET /api/users?as_user=1`
- `GET /api/audit-logs?as_user=1`

## 12.3 Acciones UI

- `POST /ui/users`
- `POST /ui/users/{user_id}/status`
- `POST /ui/users/{user_id}/role`
- `POST /ui/users/{user_id}/certificate`

## 12.4 Login, portal y registro

- `GET /login`
- `POST /login`
- `GET /portal?as_user=1`
- `GET /admin/register?as_user=1`
- `POST /admin/register`

## 12.5 Certificados

- `GET /ui/users/{user_id}/certificate/view`
- `GET /ui/users/{user_id}/certificate.pem`
- `GET /ui/users/{user_id}/certificate.p12`
- `GET /ui/ca/certificate/view`
- `GET /ui/ca/certificate`

## 13. Seguridad actual de la demo

Esta version tiene medidas basicas, no completas:

- el `.p12` se cifra con contrasena,
- el login con `.p12` verifica posesion de la llave privada,
- el certificado de usuario solo puede verlo o descargarlo el propio usuario o un actor con permisos administrativos,
- la CA se guarda localmente en disco.

Limitaciones importantes:

- la llave privada de la CA esta sin cifrado en el filesystem local,
- no hay HSM,
- no hay CRL ni OCSP,
- no hay revocacion criptografica real del certificado,
- no hay sesiones persistentes; el control de acceso posterior sigue usando `as_user` para mantener la demo simple.

## 14. Flujo recomendado para probar

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
5. Abrir `Otorgar registro`.
6. Crear un usuario nuevo con contrasena de `.p12`.
7. En la tabla, usar:
   - `Ver certificado`
   - `Certificado PEM`
   - `Descargar .p12`
8. Abrir `Login con certificado`.
9. Entrar con el correo, el `.p12` descargado y la contrasena.
10. Revisar el portal segun el rol.
11. Abrir `Ver certificado CA` para revisar el certificado de la autoridad.

## 15. Archivos generados en runtime

- `identity_demo.db`
- `generated/certs/ca/ca-key.pem`
- `generated/certs/ca/ca-cert.pem`
- `generated/certs/users/*.p12`

## 16. Limitaciones funcionales

- un solo rol por usuario,
- sin sesiones persistentes,
- sin renovacion automatica,
- sin revocacion criptografica de certificados,
- sin almacenamiento seguro de secretos,
- sin panel separado para administracion de CA.

## 17. Conclusion

La version actual ya demuestra el flujo completo pedido de forma simple:

- existe una CA interna,
- se emiten certificados X.509,
- se entrega un `.p12` con contrasena,
- se puede verificar login con firma RSA-PSS-SHA256,
- se guardan metadatos del certificado,
- se pueden ver y descargar certificados desde la UI.
