# Cierre de Demo de Viernes

## 1. Checklist tecnico final

- login inicial abre siempre en `/`
- autenticacion mixta: `.p12` para `ADMIN` y `COORDINADOR`, contrasena para `OPERATIVO` y `VOLUNTARIO`
- roles visibles correctos: `ADMIN`, `COORDINADOR`, `OPERATIVO`, `VOLUNTARIO`
- dashboard solo para `ADMIN active`
- revocacion de emergencia borra la contrasena
- activacion pide nueva contrasena cuando hace falta
- cambio de expiracion reactiva cuentas vencidas
- administrador espejo visible en modulo separado
- accion `Activar espejo` auditada
- controles de certificados removidos del flujo operativo

## 2. Guion corto para demo

1. Entrar como `admin`.
2. Mostrar dashboard y roles.
3. Crear un usuario nuevo.
4. Activarlo.
5. Revocarlo de emergencia.
6. Probar que ya no entra con la contrasena anterior.
7. Restablecer acceso con nueva contrasena.
8. Cambiar expiracion.
9. Mostrar un portal de `COORDINADOR`, `OPERATIVO` y `VOLUNTARIO`.
10. Mostrar `Recuperacion admin`.
11. Activar el espejo.
12. Mostrar auditoria.
13. Opcional: abrir el historico criptografico legacy.

## 3. Retroalimentacion en tiempo real

Usar una tabla simple:

| Tema | Comentario | Severidad | Accion |
| --- | --- | --- | --- |
| Login |  |  |  |
| Roles |  |  |  |
| Revocacion |  |  |  |
| Recuperacion admin |  |  |  |
| UI |  |  |  |
| Documentacion |  |  |  |

## 4. Artefactos obligatorios

- manual de usuario,
- guia de integracion,
- documentacion de codigo fuente,
- investigacion de recuperacion admin.
