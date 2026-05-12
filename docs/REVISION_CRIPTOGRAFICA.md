# Revision Criptografica del Proyecto

## 1. Resumen ejecutivo

La demo implementa un esquema criptografico para los roles `ADMIN` y `COORDINADOR` basado en:

- llaves `RSA 2048`,
- certificados `X.509`,
- paquetes `PKCS#12 (.p12)` protegidos por contrasena,
- firma de reto de login con `RSA-PSS-SHA256`,
- y validacion de vigencia, identidad e integridad del certificado.

La politica actual de emision es:

- el `ADMIN` usa un certificado **autofirmado**,
- el `COORDINADOR` usa un certificado **firmado por el administrador activo**,
- `OPERATIVO` y `VOLUNTARIO` no usan certificados; entran con contrasena local.

Esta revision se verifico sobre el codigo y con una prueba aislada de emision/login.

## 2. Componentes criptograficos

### 2.1 Roles que usan criptografia

Los roles criptograficos se definen en:

- [app/services.py](/Users/javier/Documents/New%20project/app/services.py:61)
- [app/services.py](/Users/javier/Documents/New%20project/app/services.py:138)

Actualmente son:

- `ADMIN`
- `COORDINADOR`

### 2.2 Material criptografico persistido

Los campos persistidos en `users` para este flujo son:

- `certificate_serial`
- `certificate_pem`
- `certificate_not_before`
- `certificate_not_after`
- `p12_base64`
- `certificate_issuer_pem`
- `certificate_issuer_user_id`

Definidos en:

- [app/models.py](/Users/javier/Documents/New%20project/app/models.py:50)

Ademas, la llave privada del administrador firmante se centraliza en `system_secrets`:

- [app/models.py](/Users/javier/Documents/New%20project/app/models.py:100)
- [app/services.py](/Users/javier/Documents/New%20project/app/services.py:377)

## 3. Emision de certificados

### 3.1 Emision del administrador

La emision del `ADMIN` ocurre en:

- [app/services.py](/Users/javier/Documents/New%20project/app/services.py:486)

Flujo:

1. Se genera una llave privada `RSA 2048`.
2. Se deriva su llave publica.
3. Se crea un certificado `X.509`.
4. El certificado usa:
   - `subject == issuer`
   - firma `SHA-256 con RSA`
5. El certificado queda **autofirmado**.
6. Se empaqueta en un `.p12` junto con la llave privada.
7. La llave privada del admin tambien se guarda de forma centralizada para poder firmar certificados subordinados:
   - [app/services.py](/Users/javier/Documents/New%20project/app/services.py:385)
   - [app/services.py](/Users/javier/Documents/New%20project/app/services.py:611)

### 3.2 Emision del coordinador

Tambien en:

- [app/services.py](/Users/javier/Documents/New%20project/app/services.py:486)

Flujo:

1. Se genera una llave privada `RSA 2048` propia del coordinador.
2. Se obtiene el administrador activo firmante:
   - [app/services.py](/Users/javier/Documents/New%20project/app/services.py:399)
3. Se carga la llave privada centralizada del admin:
   - [app/services.py](/Users/javier/Documents/New%20project/app/services.py:390)
4. Se construye el certificado del coordinador con:
   - `subject = datos del coordinador`
   - `issuer = subject del admin firmante`
5. El certificado del coordinador se firma con la llave privada del admin.
6. El `.p12` del coordinador contiene:
   - llave privada del coordinador,
   - certificado del coordinador,
   - certificado del administrador firmante como cadena.

### 3.3 Proteccion del `.p12`

El `.p12` se genera con:

- [app/services.py](/Users/javier/Documents/New%20project/app/services.py:585)

La libreria usa:

- `serialization.BestAvailableEncryption(password.encode())`

Eso significa que el paquete queda protegido por contrasena, pero el detalle exacto de la envoltura simetrica lo decide la implementacion de `cryptography`.

## 4. Jerarquia de confianza actual

La jerarquia implementada hoy es:

```text
Administrador activo
  ├─ certificado autofirmado
  ├─ llave privada centralizada en system_secrets
  └─ firma los certificados de coordinadores

Coordinador
  ├─ certificado emitido por el admin
  └─ llave privada propia dentro de su .p12
```

El sistema guarda un snapshot del emisor del certificado en:

- `certificate_issuer_pem`
- `certificate_issuer_user_id`

Referencias:

- [app/services.py](/Users/javier/Documents/New%20project/app/services.py:596)

## 5. Login criptografico

El login con `.p12` se implementa en:

- [app/services.py](/Users/javier/Documents/New%20project/app/services.py:687)

### 5.1 Validaciones previas

Antes de firmar el reto, el sistema valida:

1. que el usuario exista;
2. que este `active`;
3. que el rol requiera criptografia;
4. que el `.p12` pueda abrirse con su contrasena;
5. que el `.p12` contenga llave privada y certificado;
6. que la llave sea `RSA`;
7. que el serial del certificado coincida con el registrado;
8. que el correo del certificado coincida con el usuario;
9. que el certificado siga vigente;
10. que la fecha final del certificado coincida con `user.end_date`.

### 5.2 Verificacion de la cadena

Despues, segun el rol:

- `ADMIN`
  - el certificado debe ser autofirmado:
    - [app/services.py](/Users/javier/Documents/New%20project/app/services.py:446)
    - [app/services.py](/Users/javier/Documents/New%20project/app/services.py:727)
- `COORDINADOR`
  - el certificado no debe ser autofirmado;
  - debe verificar contra `certificate_issuer_pem`;
  - el emisor esperado debe ser un certificado autofirmado de administrador:
    - [app/services.py](/Users/javier/Documents/New%20project/app/services.py:735)

### 5.3 Prueba de posesion

Una vez validado el certificado, el sistema crea un reto efimero:

```text
login:{user.id}:{user.email}:{timestamp}
```

Luego:

1. la llave privada del `.p12` firma el reto;
2. la llave publica del certificado verifica la firma;
3. si la verificacion pasa, el backend prueba posesion de la llave privada.

Algoritmo usado:

- `RSA-PSS-SHA256`

Referencia:

- [app/services.py](/Users/javier/Documents/New%20project/app/services.py:750)

## 6. Verificacion realizada

Se hizo una prueba aislada en una SQLite temporal para no depender de Supabase.

Resultado observado:

```text
admin_self_signed True
coord_self_signed False
coord_issuer_matches_admin True
admin_p12_bytes 2788
coord_p12_bytes 3808
coord_login_signature_algorithm RSA-PSS-SHA256
coord_certificate_signature_algorithm sha256WithRSAEncryption
oper_password_only True
```

Esto confirma:

- el admin si sale autofirmado,
- el coordinador no es autofirmado,
- el emisor del coordinador coincide con el admin,
- el login criptografico de coordinador funciona,
- `OPERATIVO` sigue fuera del flujo de certificados.

## 7. Fortalezas del mecanismo actual

- Se separa claramente el acceso criptografico del acceso por contrasena.
- El login no confia solo en subir un certificado: exige posesion real de la llave privada.
- El certificado esta vinculado al correo y a la vigencia operativa del usuario.
- El emisor del certificado del coordinador queda registrado en la base.
- La cadena del `.p12` del coordinador incluye el certificado del firmante.

## 8. Limites y riesgos actuales

### 8.1 No es una PKI estricta

El certificado del admin se usa como emisor, pero hoy se construye con:

- `BasicConstraints(ca=False)`
- `key_cert_sign=False`

Referencia:

- [app/services.py](/Users/javier/Documents/New%20project/app/services.py:514)

Eso significa que, aunque el sistema funcionalmente lo usa para firmar coordinadores, no es una autoridad certificadora `X.509` estrictamente correcta.

### 8.2 Llave privada del admin centralizada sin cifrado PEM

La llave privada del admin firmante se persiste con:

- `serialization.NoEncryption()`

Referencia:

- [app/services.py](/Users/javier/Documents/New%20project/app/services.py:389)

Eso simplifica la demo, pero vuelve a `system_secrets` el punto mas sensible del proyecto.

### 8.3 Dependencia del administrador activo

Si no existe un admin activo con certificado valido y llave privada centralizada, el sistema no puede emitir nuevos certificados de coordinador.

### 8.4 Compatibilidad legacy

El codigo conserva compatibilidad con materiales anteriores (`p12_path`, emisor legacy) para no romper instalaciones previas:

- [app/services.py](/Users/javier/Documents/New%20project/app/services.py:617)

## 9. Recomendaciones de endurecimiento

Si este proyecto evoluciona mas alla de demo, las mejoras prioritarias son:

1. Convertir el certificado del admin firmante en un verdadero certificado emisor:
   - `BasicConstraints(ca=True)`
   - `key_cert_sign=True`
2. Cifrar la llave privada del admin en reposo con una clave separada del contenido de la base.
3. Separar el concepto de "admin funcional" del de "autoridad certificadora".
4. Registrar version de politica criptografica en cada certificado emitido.
5. Agregar revocacion criptografica formal si el sistema crece:
   - CRL
   - OCSP
   - o al menos una lista interna de seriales invalidados.
6. Evitar depender de credenciales demo para materiales de firma.

## 10. Conclusion

La criptografia actual del proyecto **si esta funcionando** y es coherente con la politica operativa vigente:

- `ADMIN` autofirmado,
- `COORDINADOR` firmado por admin,
- `.p12` protegido por contrasena,
- login por firma de reto con `RSA-PSS-SHA256`.

El punto mas importante es este: el sistema ya no esta usando certificados autofirmados para coordinadores. La debilidad principal no esta en la verificacion del login, sino en que el administrador firmante todavia no esta modelado como una CA `X.509` formal y su llave privada queda centralizada sin una proteccion fuerte adicional.
