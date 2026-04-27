# Manual de Usuario

## 1. Que hace esta demo

La aplicacion permite:

- crear usuarios con un rol,
- activar o revocar accesos,
- cambiar vigencia,
- cambiar rol,
- ver una bitacora simple,
- recuperar al administrador principal usando un espejo,
- emitir y consultar certificados para administradores y coordinadores.

## 2. Pantalla inicial

La pantalla inicial es `GET /` y siempre muestra el login.

El acceso es por:

- `ADMIN` y `COORDINADOR`: correo o usuario + archivo `.p12` + contrasena del paquete,
- `OPERATIVO` y `VOLUNTARIO`: usuario o correo + contrasena.

## 3. Credenciales demo

- `admin / admin`
- `admin@demo.local + .p12 + admin`
- `coordinador@demo.local + .p12 + demo1234`
- `operativo / demo1234`
- `voluntario / demo1234`
- `admin.respaldo@demo.local + .p12 + respaldo1234`

## 4. Como entrar

1. Abre la app.
2. Escribe usuario o correo.
3. Si eres `ADMIN` o `COORDINADOR`, adjunta tu `.p12`.
4. Escribe contrasena.
5. Pulsa `Entrar`.

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
- autenticar con `.p12`,
- consultar y reemitir certificados.

### Coordinador

- entra con `.p12`,
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
   - contrasena inicial o clave `.p12`.
4. Guarda.

El usuario se crea en estado `pending`.

## 7. Activar o reactivar usuario

### Activar usuario nuevo

1. Busca al usuario en el dashboard.
2. En la fila del usuario, pulsa `Gestionar`.
3. Usa `Activar`.
4. Si el usuario es criptografico y fue revocado, captura una nueva contrasena `.p12`.

### Reactivar usuario revocado

La revocacion de emergencia invalida el acceso de inmediato.

- En usuarios con contrasena, se borra la credencial guardada.
- En usuarios criptograficos, se exige una nueva contrasena `.p12` para reemitir el certificado al reactivar.

## 8. Revocacion de emergencia

La accion `Revocar de emergencia`:

- cambia el estado a `revoked`,
- impide entrar de inmediato con la credencial anterior,
- deja traza en auditoria.

Usala cuando haya extravio de dispositivo o cambio administrativo urgente.

## 9. Cambiar expiracion

1. En la fila del usuario, abre `Gestionar`.
2. Selecciona una nueva fecha futura.
3. Si el usuario es `ADMIN` o `COORDINADOR`, captura una nueva contrasena `.p12`.
4. Guarda.

Si la cuenta estaba `expired` y la fecha nueva es futura, vuelve a `active`.
En usuarios criptograficos se reemite el certificado con la nueva vigencia.

## 10. Cambiar rol

1. En la fila del usuario, abre `Gestionar`.
2. Selecciona el nuevo rol.
3. Si cambias a `ADMIN` o `COORDINADOR`, indica la contrasena del nuevo `.p12`.
4. Guarda.

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

Los certificados se usan de nuevo para:

- login de `ADMIN`,
- login de `COORDINADOR`,
- descarga del `.p12`,
- consulta del certificado del usuario.

Tambien puedes consultar:

- ver certificado de usuario,
- descargar PEM,
- descargar `.p12`,
- ver certificado de la CA interna.

Estas acciones solo aparecen para administracion.
La CA y los `.p12` ya no dependen del disco local de una sola maquina; viven en la base compartida.

## 13. Errores comunes

### `La cuenta no esta activa`

La cuenta esta en `pending`, `revoked` o `expired`.

### `Contrasena incorrecta`

La contrasena no coincide con el hash almacenado.

### `Este usuario requiere autenticacion con certificado .p12`

Intentaste entrar como `ADMIN` o `COORDINADOR` sin adjuntar el archivo `.p12`.

### `Actualiza la fecha de expiracion antes de activar esta cuenta`

Primero cambia la vigencia, luego activa.

### `Usa la recuperacion por espejo`

Intentaste revocar al admin principal desde la lista normal. Para eso existe la accion de espejo.
