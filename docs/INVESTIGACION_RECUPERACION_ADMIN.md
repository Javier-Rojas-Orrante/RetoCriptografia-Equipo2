# Investigacion: Recuperacion Avanzada del Administrador

## Objetivo

Evaluar tecnicas para recuperar totalmente el perfil administrador sin complicar demasiado la demo actual.

## 1. Break-glass account

Descripcion:

- cuenta de emergencia separada,
- uso restringido,
- credenciales guardadas fuera del flujo diario.

Ventajas:

- simple de entender,
- rapida de activar,
- encaja bien con una demo minimalista.

Riesgos:

- si la contrasena se filtra, es una puerta privilegiada,
- requiere disciplina operativa para no usarla en el dia a dia.

Aplicacion en esta demo:

- es exactamente el modelo del `administrador espejo`.

## 2. Backups cifrados offline

Descripcion:

- respaldo exportado,
- cifrado,
- almacenado fuera del sistema activo.

Ventajas:

- reduce superficie en linea,
- protege contra corrupcion o borrado accidental.

Riesgos:

- recuperacion mas lenta,
- requiere procedimientos manuales claros.

Aplicacion en esta demo:

- recomendable como siguiente paso,
- no se implemento para mantener simplicidad.

## 3. Secret sharing / escrow

Descripcion:

- repartir un secreto en varias partes,
- exigir varias personas para reconstruirlo.

Ventajas:

- evita dependencia en una sola persona,
- mejora control interno.

Riesgos:

- aumenta complejidad,
- no aporta mucho valor en una demo pequena.

Aplicacion en esta demo:

- no recomendado en esta etapa,
- si el proyecto creciera, seria mejor para administracion real.

## 4. MFA de recuperacion

Descripcion:

- agregar un segundo factor dedicado a recuperacion,
- por ejemplo TOTP, llave fisica o codigo offline.

Ventajas:

- eleva seguridad,
- disminuye riesgo de abuso de la cuenta espejo.

Riesgos:

- requiere UX adicional,
- requiere manejo de alta y reposicion del segundo factor.

Aplicacion en esta demo:

- recomendable como evolucion futura,
- no implementado para no desviar el alcance.

## 5. Hardware-backed recovery

Descripcion:

- recuperar privilegios usando HSM, TPM o llaves fisicas.

Ventajas:

- muy buen nivel de seguridad,
- reduce copia accidental de secretos.

Riesgos:

- costo,
- complejidad de operacion y soporte.

Aplicacion en esta demo:

- fuera de alcance.

## Recomendacion practica para esta demo

Usar:

1. administrador espejo inactivo,
2. contrasena propia no sincronizada,
3. auditoria obligatoria al activarlo,
4. procedimiento documentado para regenerar el respaldo despues del uso.

## Tradeoff asumido

Se prioriza:

- facilidad de demostracion,
- recuperacion inmediata,
- codigo comprensible.

Se sacrifica:

- defensa profunda,
- recuperacion multiparte,
- controles de hardware o MFA avanzados.
