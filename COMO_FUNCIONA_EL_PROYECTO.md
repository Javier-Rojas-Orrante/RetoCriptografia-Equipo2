# Cómo funciona criptográficamente el Gestor de Identidades

---

## 🏠 ¿Qué es este proyecto?

Es un sistema de login para una organización llamada "Casa Monarca".
Hay 4 tipos de usuarios:

| Rol | ¿Cómo entra? |
|-----|-------------|
| ADMIN | Certificado digital (archivo) + contraseña |
| COORDINADOR | Certificado digital (archivo) + contraseña |
| OPERATIVO | Solo usuario + contraseña |
| VOLUNTARIO | Solo usuario + contraseña |

---

## 🔑 PARTE 1: Las "Llaves" Criptográficas

Antes de entender el sistema, necesitas entender qué es una llave criptográfica.

### Analogía: El Buzón de Correos

```
Imagina que tienes un buzón especial:

┌─────────────────────────────────┐
│         TU BUZÓN                │
│                                 │
│  Ranura para meter cartas ←──── LLAVE PÚBLICA
│  (Cualquiera puede meter cartas)│
│                                 │
│  Llave para abrir el buzón ←─── LLAVE PRIVADA
│  (Solo TÚ la tienes)            │
└─────────────────────────────────┘

Llave pública  = Cualquiera puede usarla (no es secreta)
Llave privada  = Solo TÚ la tienes (¡MUY SECRETA!)
```

### En el proyecto se llaman:

```
private_key.pem = Tu llave privada (SECRETA)
public_key.pem  = Tu llave pública (pública)
```

### ¿Cómo se generan?

Se usa el algoritmo **RSA con 2048 bits**.

```python
# services.py línea 385
private_key = rsa.generate_private_key(
    public_exponent=65537,  # número estándar
    key_size=2048           # tamaño de la llave
)
```

RSA genera DOS llaves matemáticamente relacionadas:
- Lo que cifras con una, solo la otra puede descifrar
- Lo que firmas con la privada, la pública puede verificar

```
LLAVE PRIVADA: número gigante de 2048 bits (256 bytes)
LLAVE PÚBLICA: parte pública de ese número

Ejemplo visual (muy simplificado):
  Privada: 2 × 3 = 6
  Pública: 6
  (Cualquiera sabe el 6, pero solo tú sabes el 2 y el 3)
```

---

## 📜 PARTE 2: El Certificado Digital (X.509)

### Analogía: El DNI

```
DNI FÍSICO:
┌──────────────────────────────────┐
│ CREDENCIAL DE IDENTIDAD          │
│                                  │
│ Nombre:  María Fernanda          │
│ Número:  12345678                │
│ Válido:  2024 - 2025             │
│                                  │
│ [Foto]         [Sello Gobierno]  │
└──────────────────────────────────┘

CERTIFICADO DIGITAL (certificate.pem):
┌──────────────────────────────────┐
│ CERTIFICADO X.509                │
│                                  │
│ Nombre:  María Fernanda          │
│ Email:   maria@demo.local        │
│ Serial:  5d3433e5786b...         │
│ Válido:  2024-05-13 / 2025-05-13 │
│                                  │
│ [Llave pública]  [Firma del Admin]│
└──────────────────────────────────┘
```

### ¿Qué contiene un certificado?

```
certificate.pem contiene:
├─ Subject (quién eres):
│  ├─ Nombre: María Fernanda
│  ├─ Email: maria@demo.local
│  └─ País: MX
│
├─ Validez:
│  ├─ Desde: 2024-05-13
│  └─ Hasta: 2025-05-13
│
├─ Serial: número único (ej. 5d3433e5...)
│
├─ Tu llave pública (public_key)
│
└─ Firma digital del que lo emitió (Admin o CA)
```

### ¿Cómo se crea en el código?

```python
# services.py líneas 401-431

certificate = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([           # ← Datos del usuario
        NameAttribute(COUNTRY_NAME, "MX"),
        NameAttribute(ORGANIZATION_NAME, "Casa Monarca"),
        NameAttribute(COMMON_NAME, user.full_name),
        NameAttribute(EMAIL_ADDRESS, user.email),
    ]))
    .public_key(private_key.public_key())  # ← Su llave pública
    .serial_number(x509.random_serial_number())  # ← Número único
    .not_valid_before(now - timedelta(minutes=5))  # ← Desde
    .not_valid_after(valid_until)                  # ← Hasta
    .sign(private_key=ca_key, algorithm=hashes.SHA256())  # ← Firma del Admin/CA
)
```

---

## 🏛️ PARTE 3: La Autoridad Certificadora (CA)

### Analogía: La Notaría

```
En el mundo real:
  Para que un documento sea oficial, lo firma un NOTARIO.
  El notario garantiza que el documento es legítimo.

En el proyecto:
  Para que un certificado sea oficial, lo firma la CA.
  La CA garantiza que el certificado fue emitido por Casa Monarca.

┌─────────────────────────────────────────────────────┐
│               AUTORIDAD CERTIFICADORA (CA)           │
│           "Casa Monarca Internal CA"                 │
│                                                      │
│  Tiene su propia private_key y certificate          │
│  Firma los certificados de los usuarios             │
│  Es la raíz de confianza del sistema                │
└─────────────────────────────────────────────────────┘
```

### ¿Cómo funciona la CA en el proyecto?

```
1. Al iniciar el sistema, se crea la CA (si no existe):
   ├─ Genera su propio par de llaves RSA 2048
   ├─ Crea su propio certificado (se autofirma)
   └─ Guarda TODO en la base de datos

2. Cuando se crea un nuevo usuario COORDINADOR:
   ├─ La CA firma el certificado del coordinador
   └─ El certificado queda "avalado" por la CA

3. Cuando el usuario entra:
   ├─ Sistema verifica que el certificado fue firmado por la CA
   └─ Si la firma es válida → el certificado es legítimo
```

### El ADMIN es especial:

```
ADMIN → Se autofirma su propio certificado
        (El Admin ES la autoridad máxima)

COORDINADOR → Su certificado es firmado por el Admin/CA
              (El Admin garantiza que el Coordinador es legítimo)
```

---

## 🔐 PARTE 4: El Archivo .p12

### Analogía: La Caja Fuerte

```
El archivo .p12 es una CAJA FUERTE que contiene:

┌─────────────────────────────────────┐
│   archivo.p12 (protegido por        │
│   contraseña con AES-256)           │
│                                     │
│   Dentro hay:                       │
│   ├─ private_key.pem (tu secreto)   │
│   ├─ certificate.pem (tu DNI)       │
│   └─ certificate de la CA           │
│      (para verificar la cadena)     │
└─────────────────────────────────────┘

La contraseña = La combinación de la caja fuerte
Sin contraseña = No puedes abrir la caja
```

### ¿Cómo se crea en el código?

```python
# services.py líneas 434-440

p12_bytes = pkcs12.serialize_key_and_certificates(
    name=user.email.encode(),     # "maria@demo.local"
    key=private_key,              # Tu llave privada
    cert=certificate,             # Tu certificado
    cas=[ca_cert],                # Certificado de la CA
    encryption_algorithm=serialization.BestAvailableEncryption(
        password.encode()         # La contraseña para protegerlo
    ),
)
```

### ¿Dónde se guarda?

```
El .p12 se guarda en la base de datos, NO en un archivo.
Se guarda codificado en Base64 (texto legible):

Tabla: users
└─ p12_base64 = "MIIJrQIBAzCC..." (texto largo)

¿Por qué en BD?
└─ Centralizado: El admin puede descargarlo para entregarlo
└─ No depende del disco duro del servidor
```

---

## 🏭 PARTE 5: Emisión del Certificado (El Proceso Completo)

### Paso a paso de cuando el Admin crea a un nuevo COORDINADOR:

```
ADMIN crea usuario "Javier" (Coordinador)
              │
              ▼
┌─────────────────────────────────────────────────────┐
│ PASO 1: Generar par de llaves RSA para Javier        │
│                                                      │
│  private_key = RSA.generate(2048 bits)               │
│  public_key  = private_key.public_key()              │
│                                                      │
│  private_key: [256 bytes, SECRETO]                   │
│  public_key:  [extraída de la privada, PÚBLICA]      │
└─────────────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────┐
│ PASO 2: Crear el certificado de Javier               │
│                                                      │
│  Datos del certificado:                              │
│  ├─ Subject: CN=Javier, O=Casa Monarca, C=MX         │
│  ├─ Email: javier@gmail.com                          │
│  ├─ Public Key: [la que generamos]                   │
│  ├─ Serial: número aleatorio único                   │
│  └─ Válido: desde hoy hasta 2025                     │
└─────────────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────┐
│ PASO 3: Admin FIRMA el certificado de Javier         │
│                                                      │
│  1. Hash del certificado:                            │
│     hash = SHA256(datos_del_certificado)             │
│     = 32 bytes (256 bits)                            │
│                                                      │
│  2. Firma con llave privada del Admin:               │
│     firma = RSA_sign(hash, admin_private_key)        │
│     = 256 bytes                                      │
│                                                      │
│  3. La firma se agrega al certificado                │
│     certificate.signature = firma                    │
│                                                      │
│  Algoritmo: sha256WithRSAEncryption                  │
└─────────────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────┐
│ PASO 4: Empaquetar en .p12                           │
│                                                      │
│  .p12 = {                                            │
│    private_key de Javier,                            │
│    certificate de Javier (firmado por Admin),        │
│    certificate del Admin/CA                          │
│  } encriptado con AES-256 + contraseña               │
└─────────────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────┐
│ PASO 5: Guardar en base de datos                     │
│                                                      │
│  users:                                              │
│  ├─ certificate_pem = certificado de Javier          │
│  ├─ certificate_serial = número único                │
│  ├─ p12_base64 = archivo .p12 en base64              │
│  └─ end_date = fecha de expiración                   │
└─────────────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────┐
│ PASO 6: Admin descarga y entrega a Javier            │
│                                                      │
│  Admin descarga: javier.p12 desde la UI              │
│  Admin entrega a Javier: por email, USB, etc.        │
│  Javier guarda el archivo en su computadora          │
└─────────────────────────────────────────────────────┘
```

---

## 🚪 PARTE 6: El Login (Autenticación Criptográfica)

### Analogía: La Entrada a un Club Exclusivo

```
Guardia del club = El servidor
Tu credencial   = certificate.pem
Tu llave        = private_key.pem
La contraseña   = Para desencriptar tu llave privada

El guardia verifica:
1. ¿Tu credencial es auténtica? (firmada por la autoridad correcta)
2. ¿Realmente POSEES la llave que corresponde? (prueba de posesión)
```

### Paso a paso del login:

```
Javier quiere entrar:
  - Correo: javier@gmail.com
  - Carga:  private_key.pem
  - Carga:  certificate.pem
  - Escribe: su contraseña
              │
              ▼
┌─────────────────────────────────────────────────────┐
│ PASO 1: Servidor lee los archivos                    │
│                                                      │
│  certificate = leer(certificate.pem)                 │
│  private_key = leer(private_key.pem, contraseña)    │
│                ↑ La contraseña desencripta la llave  │
└─────────────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────┐
│ PASO 2: Validar el certificado                       │
│                                                      │
│  ¿El serial del certificado coincide con el de BD?  │
│    certificate.serial == user.certificate_serial?   │
│    ✓ Sí → Continuar                                  │
│    ✗ No → ERROR: "Certificado no corresponde"        │
│                                                      │
│  ¿El email del certificado coincide?                │
│    certificate.email == user.email?                  │
│    ✓ Sí → Continuar                                  │
│    ✗ No → ERROR: "Email no coincide"                 │
│                                                      │
│  ¿El certificado está vigente?                       │
│    now > not_valid_before AND now < not_valid_after? │
│    ✓ Sí → Continuar                                  │
│    ✗ No → ERROR: "Certificado expirado"              │
└─────────────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────┐
│ PASO 3: Verificar la firma del certificado           │
│                                                      │
│  Quien firmó el certificado de Javier?               │
│  └─ El Admin (o la CA)                               │
│                                                      │
│  Verificar con la public_key del Admin:              │
│  admin_public_key.verify(                            │
│      certificate.signature,                          │
│      certificate.datos                               │
│  )                                                   │
│  ✓ Válida → El Admin realmente firmó esto            │
│  ✗ Inválida → ERROR: "Certificado no es legítimo"    │
└─────────────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────┐
│ PASO 4: Prueba de Posesión (Challenge-Response)      │
│                                                      │
│  PREGUNTA: ¿Realmente tienes la llave privada?       │
│                                                      │
│  Servidor crea un DESAFÍO (número/texto único):      │
│  challenge = "login:3:javier@gmail.com:2024-05-13T10:30:45"
│              ↑id    ↑email             ↑timestamp    │
│                                                      │
│  Servidor le dice a Javier: "Firma esto"            │
│                                                      │
│  Javier firma con su private_key:                   │
│  firma = RSA_PSS_SHA256.sign(challenge, private_key) │
│  = 256 bytes                                         │
│                                                      │
│  Servidor verifica con la public_key del certificado:│
│  certificate.public_key.verify(firma, challenge)     │
│  ✓ Válida → Javier POSEE la llave privada correcta  │
│  ✗ Inválida → ERROR: "Llave no corresponde"         │
└─────────────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────┐
│ PASO 5: Sesión creada → Javier entra                 │
│                                                      │
│  Sistema crea una cookie firmada:                    │
│  cookie = HMAC_sign({"uid": 3, ...})                 │
│                                                      │
│  Se guarda en el navegador de Javier                 │
│  Dura 8 horas                                        │
│  Es HTTPOnly (JavaScript no puede leerla)            │
└─────────────────────────────────────────────────────┘
```

### ¿Por qué el Challenge-Response es importante?

```
Sin Challenge-Response:
  Alguien roba certificate.pem de Javier
  Intenta entrar con solo el certificado
  Servidor ve: "Certificate válido" → ✓ Entra
  ❌ INSEGURO: Solo robar el certificado es suficiente

Con Challenge-Response:
  Alguien roba certificate.pem de Javier
  No tiene private_key.pem
  Servidor pide firmar el desafío
  No puede firmarlo → ✗ No entra
  ✅ SEGURO: Necesita AMBOS archivos + contraseña
```

---

## 🔒 PARTE 7: Contraseñas (PBKDF2-HMAC-SHA256)

Para OPERATIVO y VOLUNTARIO se usan contraseñas normales.
Pero las contraseñas **NUNCA se guardan en claro** en la BD.

### Analogía: La Licuadora

```
Una licuadora:
  Metes: ingredientes
  Sale: batido
  PERO: No puedes meter el batido y recuperar los ingredientes

Un hash es igual:
  Metes: contraseña "demo1234"
  Sale: "pbkdf2_sha256$120000$salt$hash"
  PERO: No puedes meter el hash y recuperar "demo1234"
```

### PBKDF2: ¿Por qué tan complicado?

```
SHA256 simple (INSEGURO ❌):
  hash("demo1234") = a1b2c3d4...
  Un hacker puede probar 1 MILLÓN de contraseñas por SEGUNDO

PBKDF2 con 120,000 iteraciones (SEGURO ✓):
  Repite SHA256 120,000 veces
  Un hacker puede probar ~8 contraseñas por SEGUNDO

120,000 veces más lento = 120,000 veces más seguro
```

### Proceso de hash:

```python
# services.py líneas 228-239

def hash_password(password):
    # Paso 1: Salt aleatorio (evita ataques de tabla arcoíris)
    salt = secrets.token_bytes(16)  # 16 bytes aleatorios únicos

    # Paso 2: PBKDF2 repite SHA256 120,000 veces
    digest = hashlib.pbkdf2_hmac(
        "sha256",        # algoritmo
        password.encode(), # contraseña
        salt,            # sal
        120_000          # iteraciones
    )

    # Resultado: "pbkdf2_sha256$120000$saltBase64$hashBase64"
    return f"pbkdf2_sha256$120000${b64(salt)}${b64(digest)}"
```

### ¿Qué es el salt?

```
Sin salt (INSEGURO ❌):
  hash("demo1234") = a1b2c3d4  ← Siempre igual
  Un hacker precalcula MILLONES de hashes → Tabla arcoíris
  Ve "a1b2c3d4" → Sabe que es "demo1234"

Con salt (SEGURO ✓):
  salt_María = "xk29f..."
  salt_Pedro = "m7q1a..."
  
  hash("demo1234" + salt_María) = z9y8x7
  hash("demo1234" + salt_Pedro) = q1w2e3
  
  Aunque tengan la MISMA contraseña, el hash es DIFERENTE
  El hacker no puede usar tablas precalculadas
```

---

## 🍪 PARTE 8: La Sesión (Cookies Firmadas)

Una vez que entras, el servidor necesita "recordarte" en cada página.

### Analogía: La Pulsera del Festival

```
Cuando entras a un festival:
  1. Guardias verifican tu identidad en la entrada
  2. Te dan una PULSERA
  3. En cada área del festival, muestras tu pulsera
  4. Guardias internos verifican la pulsera, no tu identidad

La PULSERA:
  ├─ Es única y difícil de falsificar
  ├─ Tiene el sello del festival
  └─ Expira al final del día

La COOKIE:
  ├─ Contiene tu ID de usuario
  ├─ Está firmada con HMAC (imposible falsificar)
  └─ Expira en 8 horas
```

### ¿Cómo funciona en el código?

```python
# main.py líneas 47-83

# El signer usa una clave secreta del servidor
_signer = URLSafeTimedSerializer(settings.session_secret)

# Al entrar exitosamente:
def crear_cookie(user_id):
    payload = {"uid": 3}  # ID de Javier
    token = _signer.dumps(payload)  # Firma el payload
    # token = "eyJ1aWQiOjN9.Z1.AbC123..."
    return token

# En cada página:
def verificar_cookie(token):
    payload = _signer.loads(token, max_age=28800)  # 8 horas
    return payload  # {"uid": 3}
    # Si expiró o fue alterada → Error → Redirige a login
```

### ¿Por qué es segura?

```
Si alguien intenta falsificar la cookie:
  Cookie real:  {"uid": 3}.Z1.AbC123  ← Firma válida
  Cookie falsa: {"uid": 1}.Z1.XYZ789  ← Firma inválida

El servidor rechaza cualquier cookie sin firma válida.
Sin la clave secreta del servidor, es imposible crear una válida.
```

---

## 🔄 PARTE 9: El Flujo Completo del Sistema

```
╔══════════════════════════════════════════════════════════════╗
║                    FLUJO COMPLETO                            ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  ADMIN crea cuenta de COORDINADOR                            ║
║       │                                                      ║
║       ▼                                                      ║
║  Sistema genera:                                             ║
║    ├─ Par RSA 2048: private_key + public_key                 ║
║    ├─ Certificado X.509 con los datos del usuario            ║
║    ├─ Admin FIRMA el certificado (sha256WithRSAEncryption)    ║
║    └─ Empaqueta todo en .p12 (AES-256 + contraseña)          ║
║       │                                                      ║
║       ▼                                                      ║
║  Todo se guarda en la Base de Datos:                         ║
║    ├─ certificate_pem (certificado)                          ║
║    ├─ certificate_serial (número único)                      ║
║    └─ p12_base64 (caja fuerte encriptada)                    ║
║       │                                                      ║
║       ▼                                                      ║
║  Admin descarga .p12 → Lo entrega al Coordinador             ║
║       │                                                      ║
║       ▼                                                      ║
║  Coordinador ABRE el .p12 con contraseña:                    ║
║    ├─ Obtiene private_key.pem                                ║
║    └─ Obtiene certificate.pem                                ║
║       │                                                      ║
║       ▼                                                      ║
║  Coordinador ENTRA al sistema:                               ║
║    1. Carga private_key.pem + certificate.pem + contraseña  ║
║    2. Servidor valida el certificado:                        ║
║       ├─ Serial correcto?                                    ║
║       ├─ Email correcto?                                     ║
║       ├─ No expirado?                                        ║
║       └─ Firma del Admin válida?                             ║
║    3. Servidor hace Challenge-Response:                      ║
║       ├─ Crea desafío único                                  ║
║       ├─ Usuario firma con private_key                       ║
║       └─ Servidor verifica con public_key del certificado    ║
║    4. ✓ Acceso concedido → Cookie de sesión firmada          ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
```

---

## 🧮 PARTE 10: Los Algoritmos Usados

### RSA (Rivest–Shamir–Adleman)

```
¿Qué es?
  Algoritmo de criptografía ASIMÉTRICA.
  Genera un par de llaves: pública y privada.

¿Por qué 2048 bits?
  Más bits = más seguro pero más lento.
  2048 bits es el estándar de seguridad actual.

¿Para qué se usa aquí?
  ├─ Generar llaves de usuario
  ├─ Firmar certificados
  └─ Firmar el desafío en el login
```

### SHA-256

```
¿Qué es?
  Función de HASH. Convierte cualquier texto a 32 bytes fijos.

¿Por qué es importante?
  ├─ No se puede invertir (hash → texto)
  ├─ Cambiar 1 letra → hash completamente diferente
  └─ Dos textos distintos NO pueden tener el mismo hash

¿Para qué se usa aquí?
  ├─ Crear "huella digital" del certificado para firmar
  ├─ Como parte de PBKDF2 para contraseñas
  └─ Como parte de RSA-PSS en el login
```

### RSA-PSS (Probabilistic Signature Scheme)

```
¿Qué es?
  Variante mejorada de RSA para FIRMAR.

¿Por qué PSS y no RSA normal?
  RSA normal: la misma entrada da la MISMA firma
              (predecible, vulnerable a ataques)
  RSA-PSS:    incluye un SALT aleatorio
              la misma entrada da DIFERENTE firma cada vez
              (más seguro)

¿Para qué se usa aquí?
  └─ En el Challenge-Response del login (firma del desafío)
```

### AES-256

```
¿Qué es?
  Algoritmo de criptografía SIMÉTRICA.
  La misma clave encripta y desencripta.

¿Para qué se usa aquí?
  └─ Para proteger el archivo .p12 con contraseña
```

### PBKDF2 (Password-Based Key Derivation Function 2)

```
¿Qué es?
  Función para convertir una contraseña en un hash seguro.
  Repite el hash miles de veces para hacerlo más lento.

¿Para qué se usa aquí?
  └─ Para guardar contraseñas de OPERATIVO y VOLUNTARIO
```

---

## 💡 PARTE 11: ¿Por qué estas decisiones de diseño?

### ¿Por qué ADMIN/COORDINADOR usan certificados y no contraseñas?

```
Mayor privilegio = Mayor seguridad requerida

ADMIN puede:
  ├─ Crear usuarios
  ├─ Revocar cuentas
  ├─ Ver auditoría
  └─ Todo

Si alguien roba la contraseña del Admin → Compromete TODO
Si alguien roba el certificado del Admin → Necesita TAMBIÉN
  la private_key.pem + la contraseña del .p12

Triple capa: archivo + archivo + contraseña
```

### ¿Por qué la fecha de expiración está "sellada" en el certificado?

```
El certificado tiene fechas fijas:
  not_valid_after = 2025-05-13

¿Por qué no se puede cambiar?
  Porque la firma del certificado cubre ESAS fechas.
  Si cambias las fechas, la firma ya no es válida.

Es como cambiar la fecha en un documento notariado:
  El notario firmó el documento con esa fecha.
  Si cambias la fecha, su firma ya no corresponde.

Para extender el acceso → Emitir un NUEVO certificado.
```

### ¿Por qué guardar el .p12 en la base de datos?

```
Opción A: Guardar en archivos del servidor
  ❌ Si el servidor cambia, se pierden los archivos
  ❌ No escala bien

Opción B: Guardar en base de datos (lo que hace este proyecto)
  ✓ Siempre disponible para descarga
  ✓ Centralizado
  ✓ Fácil de respaldar
  ✓ Admin puede entregar .p12 al usuario cuando quiera
```

---

## 📋 RESUMEN FINAL

```
El proyecto implementa una PKI (Public Key Infrastructure) mini:

1. CA interna = Autoridad que avala certificados
2. Certificados X.509 = Identidad digital de usuarios
3. RSA-2048 = Algoritmo para generar llaves y firmar
4. SHA-256 = Huella digital para firmas e integridad
5. RSA-PSS = Firma del desafío en el login
6. AES-256 = Protección del archivo .p12
7. PBKDF2 = Protección de contraseñas
8. HMAC = Firma de cookies de sesión

Flujo en 6 palabras:
  Generar → Firmar → Empaquetar → Entregar → Validar → Acceder
```
