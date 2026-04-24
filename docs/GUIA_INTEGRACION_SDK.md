# Guia de Integracion (SDK)

Este proyecto no expone un SDK empaquetado; para la demo, el entregable equivalente es esta guia de integracion.

## 1. Modelo de autenticacion

La demo actual usa:

- identificador: correo o alias demo,
- contrasena,
- redireccion a portal o dashboard.

No usa:

- JWT,
- cookies de sesion robustas,
- refresh tokens,
- certificados para login.

## 2. Endpoints API

## `GET /health`

Respuesta:

```json
{"status":"ok"}
```

## `GET /api/me?as_user={id}`

Devuelve el usuario, su rol y permisos.

Ejemplo:

```bash
curl "http://127.0.0.1:8000/api/me?as_user=1"
```

## `GET /api/users?as_user={id}`

Solo para admin con permiso `users:view`.

```bash
curl "http://127.0.0.1:8000/api/users?as_user=1"
```

## `GET /api/audit-logs?as_user={id}`

Solo para admin con permiso `audit:view`.

```bash
curl "http://127.0.0.1:8000/api/audit-logs?as_user=1"
```

## 3. Endpoints UI de formulario

## `POST /login`

Campos:

- `identifier`
- `password`

Ejemplo:

```bash
curl -X POST "http://127.0.0.1:8000/login" \
  -d "identifier=admin" \
  -d "password=admin" \
  -i
```

## `POST /ui/users`

Campos:

- `actor_id`
- `full_name`
- `email`
- `role_id`
- `end_date` opcional
- `password`

## `POST /ui/users/{user_id}/status`

Campos:

- `actor_id`
- `status`
- `new_password` opcional

Valores soportados:

- `active`
- `revoked`

## `POST /ui/users/{user_id}/expiration`

Campos:

- `actor_id`
- `end_date`

## `POST /ui/users/{user_id}/role`

Campos:

- `actor_id`
- `role_id`

## `POST /ui/admin/recovery/activate-mirror`

Campos:

- `actor_id`

## 4. Modelo de usuario expuesto por API

Campos principales:

```json
{
  "id": 1,
  "email": "admin@demo.local",
  "full_name": "Admin Demo",
  "role_id": 1,
  "status": "active",
  "certificate_serial": null,
  "certificate_not_before": null,
  "certificate_not_after": null,
  "is_backup_admin": false,
  "mirror_source_user_id": null,
  "end_date": null
}
```

## 5. Codigos de error esperados

- `400`: validacion de negocio
- `403`: falta de permisos
- `404`: usuario o recurso no encontrado

Ejemplos de mensajes:

- `Contrasena incorrecta`
- `La cuenta no esta activa: revoked`
- `Debes definir una nueva contrasena para restablecer el acceso`
- `Usa la recuperacion por espejo para transferir al administrador principal`

## 6. Auditoria recomendada para integracion

Eventos clave:

- `login_password_verified`
- `login_rejected`
- `user_created`
- `user_access_restored`
- `emergency_revoke`
- `expiration_changed`
- `role_changed`
- `user_expired`
- `admin_recovery_activated`

## 7. Nota sobre certificados

Los endpoints de certificados siguen existiendo solo para historico legacy.
No deben considerarse parte del flujo principal de integracion.
