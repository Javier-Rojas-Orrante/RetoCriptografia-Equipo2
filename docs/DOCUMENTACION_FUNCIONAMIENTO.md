# Documentacion de Codigo Fuente

## 1. Resumen tecnico

La demo usa:

- `FastAPI` para rutas y UI HTML simple,
- `SQLAlchemy` para persistencia,
- `SQLite` como base local,
- `cryptography` para CA interna, certificados X.509, `.p12` y prueba de posesion de llave privada.

El sistema actual se centra en identidad local, control de acceso, revocacion y recuperacion del administrador.

## 2. Modulos principales

### [app/main.py](/Users/javier/Documents/New%20project/app/main.py)

Contiene:

- el arranque de la app,
- las rutas web,
- el login,
- el dashboard admin,
- los portales por rol,
- las rutas de UI para usuarios,
- las vistas legacy de certificados.

### [app/services.py](/Users/javier/Documents/New%20project/app/services.py)

Contiene la logica de negocio:

- `AuditService`
- `PasswordService`
- `SchemaService`
- `AuthorizationService`
- `ExpirationService`
- `AdminRecoveryService`
- `PasswordLoginService`
- `SignatureLoginService`
- `BootstrapService`
- `UserService`
- `CertificateAuthorityService`
- `CertificateService`

### [app/models.py](/Users/javier/Documents/New%20project/app/models.py)

Define:

- `Role`
- `User`
- `Permission`
- `RolePermission`
- `AuditLog`

### [app/schemas.py](/Users/javier/Documents/New%20project/app/schemas.py)

Expone los modelos de salida de la API.

## 3. Modelo de datos

## 3.1 Tabla `users`

Campos funcionales clave:

- `email`
- `full_name`
- `role_id`
- `status`
- `password_hash`
- `end_date`
- `is_backup_admin`
- `mirror_source_user_id`

Campos legacy de certificados:

- `certificate_serial`
- `certificate_pem`
- `certificate_not_before`
- `certificate_not_after`
- `p12_path`

## 3.2 Estados de cuenta

- `pending`
- `active`
- `revoked`
- `expired`

## 3.3 Roles visibles

- `ADMIN`
- `COORDINADOR`
- `OPERATIVO`
- `VOLUNTARIO`

Migracion legacy en bootstrap:

- `HUMANITARIA` -> `COORDINADOR`
- `LEGAL_TI` -> `COORDINADOR`
- `LECTURA` -> `OPERATIVO`
- `EXTERNAL` -> `VOLUNTARIO`

## 4. Flujo principal

1. La app arranca.
2. `BootstrapService.seed` crea roles, permisos y usuarios demo.
3. `SchemaService` agrega columnas faltantes en instalaciones previas.
4. `AdminRecoveryService.sync_backup_admin` asegura el espejo admin.
5. `GET /` sirve el login.

## 5. Autenticacion

La demo usa dos caminos:

- `SignatureLoginService.authenticate_with_p12` para `ADMIN` y `COORDINADOR`,
- `PasswordLoginService.authenticate_user` para `OPERATIVO` y `VOLUNTARIO`.

Reglas:

- acepta correo o alias demo como `admin`,
- exige `status == active`,
- los roles criptograficos validan `.p12`, certificado emitido por la CA y firma RSA-PSS-SHA256 sobre un reto,
- los roles no criptograficos validan `password_hash` con PBKDF2-HMAC-SHA256.

## 6. Autorizacion

`AuthorizationService` resuelve permisos por `(resource, action)`.

El dashboard admin se mantiene solo para:

- rol `ADMIN`
- estado `active`

Todos los demas usuarios ven siempre su portal por rol.

## 7. Revocacion de emergencia

La revocacion se implementa en `UserService.update_status`.

Cuando `status = revoked`:

- se borra `password_hash`,
- la cuenta deja de autenticar,
- el evento de auditoria esperado es `emergency_revoke`.

## 8. Reactivacion

Tambien se resuelve en `UserService.update_status`.

Si la cuenta no tiene hash:

- exige `new_password`,
- reescribe el hash,
- cambia el estado a `active`.

En roles criptograficos, si la cuenta fue revocada se exige una nueva contrasena `.p12` y se reemite el certificado.

## 9. Expiracion

`ExpirationService.expire_users`:

- revisa usuarios `active`,
- compara `end_date` con `datetime.utcnow()`,
- cambia a `expired`,
- registra `user_expired`.

`UserService.update_expiration`:

- guarda una nueva fecha futura,
- si la cuenta estaba `expired`, la regresa a `active`,
- en roles criptograficos reemite el certificado con la nueva vigencia.

## 10. Administrador espejo

`AdminRecoveryService` implementa tres responsabilidades:

- localizar al admin principal,
- asegurar que exista un respaldo espejo inactivo,
- activar el espejo y revocar al principal.

Decisiones:

- el espejo no aparece en la lista normal de usuarios,
- mantiene su propia contrasena,
- se sincroniza con el admin principal solo en metadatos no secretos,
- no crea un nuevo espejo automaticamente tras la recuperacion.

## 11. Certificados

`CertificateAuthorityService`, `CertificateService` y `SignatureLoginService` participan en:

- emitir certificados para `ADMIN` y `COORDINADOR`,
- construir y guardar `.p12`,
- verificar la firma de la CA,
- validar la firma del reto de login,
- reemitir certificados cuando cambia la vigencia o se reactiva una cuenta revocada.

## 12. Seed demo

`BootstrapService` garantiza un set basico:

- `admin@demo.local`
- `coordinador@demo.local`
- `operativo@demo.local`
- `voluntario@demo.local`
- `admin.respaldo@demo.local`

## 13. Puntos de extension

- agregar una sesion real con cookies o JWT,
- separar la UI en templates o frontend independiente,
- mover auditoria a un backend externo,
- endurecer la recuperacion admin con MFA o factores offline,
- eliminar definitivamente el historico criptografico cuando ya no se necesite.
