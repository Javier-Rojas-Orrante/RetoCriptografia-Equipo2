# Manual de Usuario

## 1. Que hace esta demo

La aplicacion permite:

- crear usuarios con un rol,
- activar o revocar accesos,
- cambiar vigencia,
- cambiar rol,
- ver una bitacora simple,
- recuperar al administrador principal usando un espejo,
- consultar certificados legacy ya existentes.

## 2. Pantalla inicial

La pantalla inicial es `GET /` y siempre muestra el login.

El acceso es por:

- usuario o correo,
- contrasena.

Ya no se pide `.p12` para entrar.

## 3. Credenciales demo

- `admin / admin`
- `coordinador / demo1234`
- `operativo / demo1234`
- `voluntario / demo1234`
- `admin.respaldo@demo.local / respaldo1234`

## 4. Como entrar

1. Abre la app.
2. Escribe usuario o correo.
3. Escribe contrasena.
4. Pulsa `Entrar`.

Si la cuenta es `ADMIN active`, se abre el dashboard admin.
Si la cuenta es de otro rol, se abre su portal de usuario.

## 5. Roles visibles

### Administrador

- puede crear usuarios,
- activar,
- revocar,
- cambiar fechas de expiracion,
- cambiar roles,
- consultar auditoria,
- activar el administrador espejo,
- consultar el historico de certificados.

### Coordinador

- entra con usuario y contrasena,
- tiene vista operativa amplia,
- no administra usuarios.

### Operativo

- entra con usuario y contrasena,
- tiene una vista operativa mas acotada,
- no administra usuarios.

### Voluntario

- entra con usuario y contrasena,
- tiene acceso restringido y simplificado.

## 6. Crear usuario

1. Entra como administrador.
2. Abre `Otorgar registro` o usa el formulario del dashboard.
3. Captura:
   - nombre,
   - correo,
   - rol,
   - fecha de expiracion opcional,
   - contrasena inicial.
4. Guarda.

El usuario se crea en estado `pending`.

## 7. Activar o reactivar usuario

### Activar usuario nuevo

1. Busca al usuario en el dashboard.
2. En la tarjeta del usuario, usa `Activar`.
3. Si la cuenta ya tiene contrasena inicial, no necesitas capturar una nueva.

### Reactivar usuario revocado

La revocacion de emergencia borra la contrasena guardada.
Por eso, al reactivar un revocado, el campo `Nueva contrasena` es obligatorio.

## 8. Revocacion de emergencia

La accion `Revocar de emergencia`:

- cambia el estado a `revoked`,
- borra `password_hash`,
- impide entrar de inmediato con la contrasena anterior,
- deja traza en auditoria.

Usala cuando haya extravio de dispositivo o cambio administrativo urgente.

## 9. Cambiar expiracion

1. En la tarjeta del usuario, abre la seccion `Vigencia`.
2. Selecciona una nueva fecha futura.
3. Guarda.

Si la cuenta estaba `expired` y la fecha nueva es futura, vuelve a `active`.

## 10. Cambiar rol

1. En la tarjeta del usuario, abre la seccion `Rol`.
2. Selecciona el nuevo rol.
3. Guarda.

El cambio aplica en la siguiente entrada al sistema.

## 11. Recuperacion del administrador

La demo mantiene un `administrador espejo` separado de la lista normal de usuarios.

Flujo:

1. Entra como admin principal.
2. En el bloque `Recuperacion admin`, pulsa `Activar espejo`.
3. El sistema:
   - revoca al admin principal,
   - limpia su contrasena,
   - activa al espejo,
   - registra auditoria.

Despues debes regenerar un nuevo respaldo.

## 12. Historico criptografico

Los certificados ya no se usan para login ni para emision operativa.

Solo quedan como historico:

- ver certificado de usuario,
- descargar PEM,
- descargar `.p12`,
- ver certificado de la CA interna.

Estas acciones solo aparecen para administracion.

## 13. Errores comunes

### `La cuenta no esta activa`

La cuenta esta en `pending`, `revoked` o `expired`.

### `Contrasena incorrecta`

La contrasena no coincide con el hash almacenado.

### `Actualiza la fecha de expiracion antes de activar esta cuenta`

Primero cambia la vigencia, luego activa.

### `Usa la recuperacion por espejo`

Intentaste revocar al admin principal desde la lista normal. Para eso existe la accion de espejo.
