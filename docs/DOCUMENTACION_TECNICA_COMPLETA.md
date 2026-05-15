# Documentación Técnica Completa — Gestor de Identidades Casa Monarca

> **Audiencia**: Desarrolladores del equipo, revisores académicos y cualquier persona con conocimiento básico de programación y criptografía que desee entender el sistema desde adentro.
> **Fecha**: Mayo 2026  
> **Stack**: Python 3.11+, FastAPI, SQLAlchemy, biblioteca `cryptography`, `itsdangerous`, SQLite / PostgreSQL

---

## Tabla de Contenidos

1. [Contexto General](#1-contexto-general)
2. [Arquitectura del Sistema](#2-arquitectura-del-sistema)
3. [Modelo de Datos](#3-modelo-de-datos)
4. [Sistema de Roles y Permisos (RBAC)](#4-sistema-de-roles-y-permisos-rbac)
5. [Autenticación por Contraseña — PBKDF2-HMAC-SHA256](#5-autenticación-por-contraseña--pbkdf2-hmac-sha256)
6. [Cookies de Sesión — HMAC con itsdangerous](#6-cookies-de-sesión--hmac-con-itsdangerous)
7. [Infraestructura de Clave Pública (PKI)](#7-infraestructura-de-clave-pública-pki)
8. [Emisión de Certificados X.509](#8-emisión-de-certificados-x509)
9. [Autenticación Criptográfica con Firma Digital](#9-autenticación-criptográfica-con-firma-digital)
10. [Entrega y Ciclo de Vida de la Llave Privada](#10-entrega-y-ciclo-de-vida-de-la-llave-privada)
11. [Administrador Espejo (Recuperación)](#11-administrador-espejo-recuperación)
12. [Bloqueo de Cuenta y Control de Intentos](#12-bloqueo-de-cuenta-y-control-de-intentos)
13. [Expiración Automática de Usuarios](#13-expiración-automática-de-usuarios)
14. [Registro de Auditoría](#14-registro-de-auditoría)
15. [Reportes PDF con Hash de Integridad](#15-reportes-pdf-con-hash-de-integridad)
16. [Configuración y Secretos](#16-configuración-y-secretos)
17. [Comparaciones Criptográficas: Por Qué Se Eligió Cada Algoritmo](#17-comparaciones-criptográficas-por-qué-se-eligió-cada-algoritmo)
18. [Flujos Completos Paso a Paso](#18-flujos-completos-paso-a-paso)
19. [Superficie de Ataque y Decisiones de Seguridad](#19-superficie-de-ataque-y-decisiones-de-seguridad)

---

## 1. Contexto General

El sistema es un **Gestor de Identidades** para la organización "Casa Monarca". Su propósito es controlar quién puede acceder, qué puede hacer y con qué nivel de confianza criptográfica.

El sistema distingue dos clases de usuarios:

| Clase | Roles | Método de acceso |
|---|---|---|
| **Usuarios comunes** | `OPERATIVO`, `VOLUNTARIO` | Email + contraseña |
| **Usuarios privilegiados** | `ADMIN`, `COORDINADOR` | Archivos criptográficos: `private_key.pem` + `certificate.pem` + contraseña |

Esta bifurcación es central: los roles con más poder tienen **autenticación de dos factores basada en criptografía asimétrica**, en lugar de simples contraseñas.

> **Analogía**: Es como el acceso a un servidor SSH. Un operativo tiene usuario+contraseña. Un administrador tiene que subir su llave privada y certificado, y demostrar que tiene la contraseña para descifrarla.

---

## 2. Arquitectura del Sistema

```
app/
├── main.py        ← Rutas HTTP, rendering HTML, manejo de sesión, lógica de presentación
├── services.py    ← Toda la lógica de negocio y criptografía
├── models.py      ← Modelos SQLAlchemy (ORM)
├── schemas.py     ← Esquemas Pydantic (validación/serialización)
├── config.py      ← Configuración con Pydantic Settings
├── db.py          ← Motor SQLAlchemy y sesión
└── deps.py        ← Dependencias FastAPI (inyección de DB)
```

### Servicios en `services.py`

| Clase | Responsabilidad |
|---|---|
| `PasswordService` | Hash y verificación de contraseñas (PBKDF2) |
| `CertificateAuthorityService` | Gestión de la CA interna (clave + certificado raíz) |
| `AdminSignerService` | Almacena la llave privada del admin para firmar certificados de coordinadores |
| `CertificateService` | Emitir, describir y entregar material criptográfico por usuario |
| `SignatureLoginService` | Autenticación criptográfica completa (validar cert + firmar challenge) |
| `PasswordLoginService` | Autenticación por contraseña simple |
| `AuthorizationService` | Control de acceso basado en roles (RBAC) |
| `AuditService` | Registro de eventos |
| `NotificationService` | Alertas internas (cert próximo a vencer, cuenta bloqueada, etc.) |
| `AdminRecoveryService` | Gestión del administrador espejo / recuperación |
| `ExpirationService` | Expirar automáticamente cuentas con `end_date` vencida |
| `BootstrapService` | Inicialización del sistema: roles, permisos, usuarios demo |

### Inicio de la aplicación (`lifespan`)

```python
@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)   # Crear tablas si no existen
    with Session(bind=engine) as db:
        BootstrapService.seed(db)           # Sembrar roles, permisos y usuarios demo
    yield
```

En cada arranque se garantiza que la base de datos tiene el esquema correcto y los datos iniciales.

---

## 3. Modelo de Datos

### Tabla `users` — Los campos criptográficos son los más importantes

```
users
├── id, email, full_name, role_id, status
├── password_hash              ← Hash PBKDF2 de la contraseña
│
│   ── Material PKI ──
├── certificate_serial         ← Número de serie del certificado X.509 (hex)
├── certificate_pem            ← Certificado público (PEM) — compartible
├── public_key_pem             ← Llave pública extraída del cert
├── private_key_pem_encrypted  ← Llave privada cifrada con contraseña del usuario
├── private_key_delivered_at   ← Timestamp de cuándo se entregó (NULL = no entregada)
├── certificate_not_before     ← Inicio de vigencia del certificado
├── certificate_not_after      ← Fin de vigencia del certificado
├── certificate_issuer_pem     ← Certificado del firmante (para coordis = cert del admin)
├── certificate_issuer_user_id ← ID del usuario que firmó el certificado
│
│   ── Control de acceso ──
├── is_backup_admin            ← Boolean: es el admin espejo?
├── mirror_source_user_id      ← ID del admin principal que este espeja
├── end_date                   ← Fecha de vencimiento de la cuenta
├── login_attempts             ← Contador de intentos fallidos
└── login_locked_until         ← NULL = no bloqueado; fecha = bloqueado hasta
```

### Tabla `system_secrets`

Almacena secretos del sistema como pares clave-valor en texto plano dentro de la BD:

```
system_secrets
├── key          ← "ca_private_key_pem", "ca_certificate_pem",
│                   "admin_signer_private_key_pem:{user_id}"
└── value_text   ← Contenido PEM
```

> **Nota de seguridad**: En producción, este almacén debería reemplazarse por un servicio de gestión de secretos (HashiCorp Vault, AWS Secrets Manager, etc.). Para el demo, la BD actúa como almacén centralizado.

---

## 4. Sistema de Roles y Permisos (RBAC)

RBAC = **Role-Based Access Control**. En lugar de asignar permisos individualmente a cada usuario, se asignan a roles, y los usuarios tienen un rol.

### Jerarquía de Roles

```
ADMIN (Administrador)
  ├── users: create, view, activate, revoke, change_role, change_expiration
  ├── audit: view
  ├── admin_recovery: activate
  └── certificates: view

COORDINADOR
  ├── documents: view, edit
  ├── operations: view
  └── certificates: view

OPERATIVO
  ├── documents: view
  └── operations: view, edit

VOLUNTARIO
  └── documents: view
```

### Cómo funciona la autorización

```python
# AuthorizationService.authorize(db, user, "users", "create")
# → Hace JOIN de role_permissions + permissions para ese rol
# → Retorna True si (resource="users", action="create") existe para ese rol
```

El sistema es **aditivo**: un usuario solo puede hacer lo que su rol le permite explícitamente. No hay herencia entre roles.

---

## 5. Autenticación por Contraseña — PBKDF2-HMAC-SHA256

### Código en `PasswordService`

```python
class PasswordService:
    iterations = 120_000

    @classmethod
    def hash_password(cls, password: str) -> str:
        salt = secrets.token_bytes(16)                              # 16 bytes = 128 bits
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, cls.iterations)
        return "pbkdf2_sha256${}${}${}".format(
            cls.iterations,
            base64.b64encode(salt).decode(),
            base64.b64encode(digest).decode(),
        )
```

### Formato almacenado

```
pbkdf2_sha256$120000$<base64_salt>$<base64_digest>
```

**Ejemplo real** (valores ilustrativos):
```
pbkdf2_sha256$120000$c2FsdGFsZWF0b3Jpbw==$dGhpcyBpcyBhbiBleGFtcGxlIGhhc2g=
```

### Cómo funciona PBKDF2

**PBKDF2** = Password-Based Key Derivation Function 2 (RFC 2898).

La función hace lo siguiente:
```
PBKDF2(password, salt, iterations, keyLen, PRF)
```

donde `PRF` (Pseudo-Random Function) es HMAC-SHA256 en este caso.

Internamente ejecuta:
```
T₁ = PRF(password, salt ∥ 0x00000001)
T₂ = PRF(password, salt ∥ 0x00000002)
...
resultado = T₁ ∥ T₂ ∥ ...
```

Cada `Tᵢ` es el XOR de `iterations` aplicaciones de HMAC sobre la salida anterior:
```
U₁ = HMAC-SHA256(password, salt)
U₂ = HMAC-SHA256(password, U₁)
...
Tᵢ = U₁ XOR U₂ XOR ... XOR U_iterations
```

**¿Por qué 120,000 iteraciones?** OWASP recomienda mínimo 600,000 para PBKDF2-SHA256 en 2023, pero 120,000 sigue siendo un valor que hace la fuerza bruta costosa. Cada intento requiere 120,000 operaciones de HMAC-SHA256.

### Comparación de Tiempo por Candidato

| Iteraciones | Tiempo/hash (CPU moderna) | Intentos/segundo |
|---|---|---|
| 1 | ~0.001 ms | ~1,000,000 |
| 10,000 | ~1 ms | ~1,000 |
| 120,000 | ~12 ms | ~80 |
| 1,000,000 | ~100 ms | ~10 |

Con 120,000 iteraciones, un atacante que roba la BD y tiene una GPU puede probar ~80 contraseñas por segundo por core, lo cual hace inviable un diccionario de millones de contraseñas en tiempo razonable.

### Sal (Salt)

El salt es generado con `secrets.token_bytes(16)` = 16 bytes aleatorios criptográficamente seguros. Esto garantiza:
- Dos usuarios con la misma contraseña tienen hashes completamente distintos.
- Los ataques de **Rainbow Tables** (tablas precomputadas de hashes) son inútiles.

**Ejemplo sin salt (INSEGURO)**:
```
SHA256("admin") = 8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918
```
→ Un atacante con una Rainbow Table encuentra "admin" en un instante.

**Con salt (SEGURO)**:
```
PBKDF2("admin", salt=random_bytes, 120000) = valor único diferente cada vez
```

### Verificación con Tiempo Constante

```python
return hmac.compare_digest(actual, expected)
```

**Por qué `hmac.compare_digest` y no `==`?**

La comparación normal `a == b` en Python retorna `False` en el primer byte diferente, lo que hace que tome menos tiempo cuando los primeros bytes son distintos. Un atacante puede medir estos tiempos (**timing attack**) y deducir el hash byte a byte.

`hmac.compare_digest` siempre compara todos los bytes en tiempo constante, sin importar cuántos bytes sean iguales.

---

## 6. Cookies de Sesión — HMAC con itsdangerous

### Código en `main.py`

```python
_SESSION_COOKIE = "cm_session"
_SESSION_MAX_AGE = 8 * 3600   # 8 horas en segundos
_signer = URLSafeTimedSerializer(settings.session_secret, salt="cm-session")
```

### Estructura de la Cookie

La librería `itsdangerous` genera un token con el siguiente formato:

```
<payload_base64_urlsafe>.<timestamp_base64>.<firma_hmac_base64>
```

**Payload típico:**
```json
{"uid": 3}
```

El servidor firma este payload con HMAC usando `session_secret` como clave. Nadie puede crear un token válido sin conocer ese secreto.

### Flujo de Sesión

```
1. Login exitoso → _make_session_cookie(user_id=3) → token firmado
2. Token enviado al browser en Set-Cookie (httponly, samesite=lax)
3. Browser envía cookie automáticamente en cada request
4. Servidor llama _read_session_cookie(token):
   - Verifica firma HMAC
   - Verifica que no hayan pasado más de 8 horas
   - Retorna {"uid": 3}
```

### Atributos de Seguridad de la Cookie

```python
response.set_cookie(
    _SESSION_COOKIE, token,
    max_age=_SESSION_MAX_AGE,
    httponly=True,          # ← JavaScript NO puede leer la cookie (protección XSS)
    secure=True,            # ← Solo se envía en HTTPS (en producción)
    samesite="lax",         # ← Protección contra CSRF
    path="/",
)
```

| Atributo | Protege contra |
|---|---|
| `httponly=True` | XSS (Cross-Site Scripting) — el script malicioso no puede robar la cookie |
| `secure=True` | Interceptación en red (Man-in-the-Middle) — solo viaja por HTTPS |
| `samesite="lax"` | CSRF (Cross-Site Request Forgery) — peticiones desde otros sitios no incluyen la cookie en navegaciones normales |

### Diferencia `lax` vs `strict` vs `none`

| Valor | Comportamiento | Caso de uso |
|---|---|---|
| `strict` | Cookie nunca enviada desde otro sitio | Máxima seguridad, pero rompe links externos |
| `lax` | Cookie enviada en GET desde links externos, no en POST | Balance seguridad/usabilidad (elegido aquí) |
| `none` | Siempre enviada (requiere `secure`) | APIs de terceros |

---

## 7. Infraestructura de Clave Pública (PKI)

La PKI es la parte más sofisticada del sistema. Vamos a entenderla antes de ver el código.

### Conceptos Clave de PKI

Una **PKI** (Public Key Infrastructure) es un conjunto de políticas, procedimientos y tecnologías para gestionar certificados digitales y llaves asimétricas.

En RSA, cada entidad tiene un par de llaves:
- **Llave privada** (`private_key.pem`): Solo la conoce el dueño. Se usa para **firmar** o **descifrar**.
- **Llave pública** (`public_key.pem`): Conocida por todos. Se usa para **verificar firmas** o **cifrar**.

La relación matemática es:
$$\text{cifrado} = \text{mensaje}^e \mod n$$
$$\text{mensaje} = \text{cifrado}^d \mod n$$

donde $(e, n)$ es la llave pública y $(d, n)$ es la llave privada.

### La CA (Certificate Authority) del Sistema

```python
class CertificateAuthorityService:
    @classmethod
    def ensure_ca(cls, db: Session) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
        # 1. Intentar cargar desde BD
        key_pem = cls._get_secret(db, "ca_private_key_pem")
        cert_pem = cls._get_secret(db, "ca_certificate_pem")
        if key_pem and cert_pem:
            return deserialized_key, deserialized_cert

        # 2. Si no existe, generar
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(issuer)       # ← subject == issuer = autofirmado
            .issuer_name(issuer)
            .not_valid_after(now + timedelta(days=3650))   # 10 años
            .add_extension(x509.BasicConstraints(ca=True, ...), critical=True)  # ← Marca como CA
            .sign(private_key=private_key, algorithm=hashes.SHA256())
        )
```

**Parámetros RSA:**
- `key_size=2048`: Tamaño del módulo $n$ en bits
- `public_exponent=65537`: El valor $e$ de la llave pública. Se elige $65537 = 2^{16} + 1$ porque:
  - Es un número primo de Fermat: eficiente para calcular potencias
  - Es suficientemente grande para evitar ataques con exponentes pequeños
  - Es el estándar de la industria (PKCS#1, FIPS 186)

**`BasicConstraints(ca=True)`**: Esta extensión X.509 le dice a cualquier sistema que verifique el certificado que este certificado pertenece a una CA — es decir, que puede firmar otros certificados. Sin este flag, un cliente TLS rechazaría usar ese cert para verificar una cadena.

### Por qué RSA 2048 y no Curva Elíptica (ECDSA)?

| Algoritmo | Tamaño de llave | Seguridad equivalente | Velocidad |
|---|---|---|---|
| RSA-2048 | 2048 bits | ~112 bits | Más lento en generación |
| RSA-4096 | 4096 bits | ~140 bits | Mucho más lento |
| ECDSA P-256 | 256 bits | ~128 bits | Más rápido |
| ECDSA P-384 | 384 bits | ~192 bits | Muy rápido |

Se eligió **RSA-2048** porque:
1. Es el estándar más compatible con herramientas legacy y clientes de correo
2. El nivel de seguridad de 112 bits es suficiente para un sistema interno con vigencia de 1 año
3. La extensión `cryptography` en Python lo soporta nativamente con la interfaz más madura
4. Los X.509 con ECDSA requieren más cuidado en la validación de curvas (el código ya es complejo)

> **Comparación**: Para contexto, RSA-2048 requeriría factorizar un número de 617 dígitos decimales. El récord mundial actual es RSA-829 (250 bits). RSA-2048 es computacionalmente inviable de romper con hardware actual.

---

## 8. Emisión de Certificados X.509

### ¿Qué es un Certificado X.509?

Un certificado X.509 es un documento digital estándar (RFC 5280) que vincula una **identidad** (nombre, email) con una **llave pública**. Contiene:

```
Subject:     CN=Juan Coordinador, O=Casa Monarca, emailAddress=juan@casa.org
Issuer:      CN=Admin Principal, O=Casa Monarca
Serial:      3a9f12bc8e...
Not Before:  2026-01-01
Not After:   2027-01-01
Public Key:  RSA-2048 (llave pública del usuario)
Extensions:
  - BasicConstraints: CA=False
  - KeyUsage: digitalSignature, keyEncipherment
  - ExtendedKeyUsage: clientAuth, emailProtection
  - SAN: juan@casa.org
Signature:   <firma del emisor sobre todos los campos anteriores>
```

La firma del emisor garantiza que nadie alteró el contenido del certificado.

### Diferencia entre Certificado de ADMIN y COORDINADOR

#### ADMIN — Certificado Autofirmado

```python
certificate = (
    x509.CertificateBuilder()
    .subject_name(subject)   # ← {"CN": "Admin Demo", ...}
    .issuer_name(subject)    # ← mismo que subject → autofirmado
    .public_key(private_key.public_key())
    .sign(private_key=private_key, algorithm=hashes.SHA256())
    # ↑ firmado con la propia llave privada del admin
)
```

Diagrama:
```
┌─────────────────────────┐
│ Certificado ADMIN       │
│  Subject = Admin A      │
│  Issuer  = Admin A      │ ← subject == issuer
│  Sig: firmado con       │
│       llave privada de  │
│       Admin A           │
└─────────────────────────┘
```

La autofirma funciona porque el admin es la raíz de confianza del sistema. Su certificado es verificado usando su propia llave pública. Es análogo a un certificado raíz de CA.

#### COORDINADOR — Certificado Firmado por el Admin

```python
signer_admin, signer_key, signer_certificate = AdminSignerService.get_signing_material(db)
certificate = (
    x509.CertificateBuilder()
    .subject_name(subject)                      # ← {"CN": "Coord Legal", ...}
    .issuer_name(signer_certificate.subject)    # ← nombre del admin firmante
    .public_key(private_key.public_key())       # ← llave pública del coordinador
    .sign(private_key=signer_key, algorithm=hashes.SHA256())
    # ↑ firmado con la llave privada del ADMIN
)
```

Diagrama de cadena de confianza:
```
┌─────────────────────────┐
│ Certificado ADMIN A     │
│  Subject = Admin A      │
│  Issuer  = Admin A      │ ← autofirmado
└────────────┬────────────┘
             │ firma
             ▼
┌─────────────────────────┐
│ Certificado Coord B     │
│  Subject = Coord B      │
│  Issuer  = Admin A      │ ← firmado por el admin
└─────────────────────────┘
```

Esta cadena permite verificar que Coord B fue autorizado por Admin A: tomamos la llave pública de Admin A y verificamos la firma del certificado de Coord B.

### Extensiones del Certificado

```python
.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
.add_extension(
    x509.KeyUsage(
        digital_signature=True,   # ← puede firmar datos
        key_encipherment=True,    # ← puede cifrar llaves de sesión
        ...rest=False
    ), critical=True,
)
.add_extension(
    x509.ExtendedKeyUsage([
        ExtendedKeyUsageOID.CLIENT_AUTH,        # ← puede autenticarse como cliente TLS
        ExtendedKeyUsageOID.EMAIL_PROTECTION,   # ← puede cifrar/firmar correos (S/MIME)
    ]), critical=False,
)
.add_extension(
    x509.SubjectAlternativeName([x509.RFC822Name(user.email)]),
    critical=False
)
```

| Extensión | Valor | Propósito |
|---|---|---|
| `BasicConstraints` | `ca=False` | Evita que el cert del usuario sea usado para firmar otros certs |
| `KeyUsage.digital_signature` | `True` | Necesario para el challenge de login |
| `KeyUsage.key_encipherment` | `True` | Permite cifrar llaves simétricas (TLS, S/MIME) |
| `ExtendedKeyUsage.CLIENT_AUTH` | OID 1.3.6.1.5.5.7.3.2 | Autenticación de cliente en TLS |
| `ExtendedKeyUsage.EMAIL_PROTECTION` | OID 1.3.6.1.5.5.7.3.4 | Firmar/cifrar emails (S/MIME) |
| `SubjectAlternativeName` | `RFC822Name(email)` | Vincula explícitamente el certificado al email del usuario |

**¿Por qué `critical=True` en KeyUsage?** Si se marca `critical`, cualquier sistema que no entienda esa extensión debe rechazar el certificado. Esto garantiza que solo se use para los propósitos declarados.

### Cifrado de la Llave Privada para Almacenamiento Temporal

```python
private_key_pem_encrypted = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
)
```

`BestAvailableEncryption` usa el esquema de cifrado más seguro disponible en la versión de OpenSSL en uso. En las versiones modernas de la biblioteca `cryptography`, esto produce:

```
AES-256-CBC con clave derivada de la contraseña usando scrypt o PBKDF2
```

El resultado en PEM se ve así:
```
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAIIGjR+...
<datos binarios cifrados en base64>
-----END ENCRYPTED PRIVATE KEY-----
```

La llave privada **nunca se almacena en claro** en la BD. Si la BD es comprometida, el atacante no puede usar las llaves sin conocer la contraseña de cada usuario.

---

## 9. Autenticación Criptográfica con Firma Digital

Este es el mecanismo más elaborado del sistema: en lugar de verificar una contraseña, el sistema verifica que el usuario **posee** la llave privada correspondiente al certificado registrado.

### El Flujo Completo

```
Usuario                           Servidor
  │                                  │
  │── POST /login/crypto ──────────► │
  │   - identifier: "coord@..."      │
  │   - private_key.pem (file)       │
  │   - certificate.pem (file)       │
  │   - password: "mi_contraseña"    │
  │                                  │
  │                                  │ 1. Buscar usuario por email
  │                                  │ 2. Cargar certificate.pem
  │                                  │ 3. Descifrar private_key.pem con password
  │                                  │ 4. Validar certificado (serie, email, vigencia, firma)
  │                                  │ 5. Construir challenge
  │                                  │ 6. Firmar challenge con private_key
  │                                  │ 7. Verificar firma con public key del cert
  │                                  │ 8. Si OK → crear sesión
  │◄── Redirect /portal ────────────│
```

### Paso 3: Descifrado de la Llave Privada

```python
private_key = serialization.load_pem_private_key(
    private_key_bytes,
    password=password.encode() if password else None,
)
```

Si la contraseña es incorrecta, `load_pem_private_key` lanza una excepción. El sistema:
1. Incrementa `user.login_attempts`
2. Si llega a 10, bloquea la cuenta
3. Si no alcanza 10, informa cuántos intentos quedan

### Paso 4: Validación del Certificado

```python
# 4a. Número de serie coincide con el registrado
if format(certificate.serial_number, "x") != user.certificate_serial:
    raise ValueError("El certificado no corresponde al usuario registrado")

# 4b. Email del certificado coincide con el del usuario
# (verificado via SAN RFC822Name o Subject emailAddress)

# 4c. Certificado dentro de su vigencia
now = datetime.now(UTC)
if certificate.not_valid_before_utc > now or certificate.not_valid_after_utc < now:
    raise ValueError("El certificado esta fuera de vigencia")

# 4d. Fecha de vencimiento del cert == end_date del usuario (coincidencia exacta)
if certificate.not_valid_after_utc.replace(tzinfo=None) != user.end_date.replace(microsecond=0):
    raise ValueError("El certificado no coincide con la vigencia actual del usuario")
```

**¿Por qué verificar que `not_valid_after == user.end_date`?**
Esto previene que un coordinador use un certificado antiguo (de antes de que le cambiaran la vigencia). Si el admin extiende o reduce la vigencia del usuario, todos sus certificados anteriores quedan inválidos automáticamente.

#### Verificación del ADMIN (autofirmado)

```python
if user.role.code == "ADMIN":
    if certificate.subject != certificate.issuer:
        raise ValueError("El certificado del administrador debe ser autofirmado")
    
    # Verificar que la firma es válida
    public_key.verify(
        certificate.signature,            # firma del cert
        certificate.tbs_certificate_bytes,# datos firmados (TBS = To Be Signed)
        padding.PKCS1v15(),
        certificate.signature_hash_algorithm,  # SHA256
    )
```

`tbs_certificate_bytes` son los campos del certificado serializados en DER antes de firmar. La verificación con `PKCS1v15` es el esquema estándar para certificados X.509 (`sha256WithRSAEncryption`).

#### Verificación del COORDINADOR (cadena de confianza)

```python
else:
    # 1. Cargar el cert del admin firmante almacenado en el usuario
    issuer_certificate = x509.load_pem_x509_certificate(user.certificate_issuer_pem.encode())
    
    # 2. Verificar que el cert del admin es válido (autofirmado)
    CertificateService._verify_self_signed_certificate(issuer_certificate)
    
    # 3. Verificar que el cert del coordinador fue firmado por ese admin
    ca_public_key.verify(
        certificate.signature,
        certificate.tbs_certificate_bytes,
        padding.PKCS1v15(),
        certificate.signature_hash_algorithm,
    )
```

### Paso 5-7: El Challenge-Response

Este es el mecanismo que **prueba posesión** de la llave privada.

```python
# Construcción del challenge — único por sesión gracias al timestamp
challenge = f"login:{user.id}:{user.email}:{now.isoformat()}".encode()
# Ejemplo: b"login:5:coord@casa.org:2026-05-14T10:30:00+00:00"

# Firmar el challenge con la llave privada del usuario
signature = private_key.sign(
    challenge,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    ),
    hashes.SHA256(),
)

# Verificar que la firma es correcta usando la llave pública del certificado
certificate.public_key().verify(
    signature,
    challenge,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    ),
    hashes.SHA256(),
)
```

**¿Qué demuestra esto?**

Si la verificación pasa, significa:
1. El usuario tiene la llave privada correspondiente a la llave pública en el certificado
2. El certificado fue validado (emisor correcto, vigente, serial correcto)
3. La combinación de (llave privada + certificado) pertenece al usuario registrado

Sin la llave privada, es **matemáticamente imposible** generar una firma que pase la verificación.

### PKCS1v15 vs PSS — Por Qué Se Usan Dos Paddings Distintos

Este es un detalle importante que confunde a muchos:

| Operación | Padding usado | Razón |
|---|---|---|
| Verificar firma del **certificado X.509** | `PKCS1v15` | El estándar RFC 5280 define `sha256WithRSAEncryption` que usa PKCS#1 v1.5 |
| Firmar/verificar el **challenge de login** | `PSS` | Más moderno y seguro; NIST SP 800-131A recomienda PSS para nuevas aplicaciones |

**PKCS#1 v1.5** (firma):
```
mensaje → hash → padding determinístico → cifrar con llave privada
```
El padding es siempre el mismo para un mensaje dado. Bajo ciertos ataques adaptivos de texto cifrado (Bleichenbacher 1998), puede ser vulnerable.

**PSS** (Probabilistic Signature Scheme, RFC 8017):
```
mensaje → hash → padding aleatorio (con salt) → cifrar con llave privada
```
Cada firma es diferente aunque el mensaje sea el mismo, gracias al salt. Es **probabilísticamente seguro** y resistente a los ataques conocidos contra PKCS#1 v1.5.

**Analogía**: PKCS#1 v1.5 para firma es como un sello de cera que siempre tiene la misma forma. PSS es un sello que incluye un número aleatorio único cada vez, imposible de falsificar.

---

## 10. Entrega y Ciclo de Vida de la Llave Privada

El ciclo completo de la llave privada de un usuario es:

```
1. ADMIN emite credenciales:
   - Se genera par de llaves RSA-2048 nuevo
   - Llave privada se cifra con contraseña elegida por el admin
   - Llave privada cifrada se almacena en users.private_key_pem_encrypted
   - private_key_delivered_at = NULL  (no entregada aún)

2. ADMIN descarga la llave para dársela al usuario:
   GET /ui/users/{id}/private-key.pem
   → CertificateService.deliver_user_private_key(db, user)
   → users.private_key_delivered_at = NOW
   → users.private_key_pem_encrypted = NULL   ← BORRADA del servidor

3. Usuario usa la llave para autenticarse:
   POST /login/crypto
   ← sube private_key.pem (del archivo descargado) + certificate.pem + contraseña

4. Si se necesita renovar:
   ADMIN emite nuevas credenciales (reissue=True)
   → vuelve al paso 1
```

**Principio de entrega única**: La llave privada solo puede descargarse **una vez**. Después de la descarga, el servidor ya no la tiene. Esto limita la exposición: aunque el servidor sea comprometido después de la entrega, la llave privada no está disponible.

```python
@staticmethod
def deliver_user_private_key(db: Session, user: User) -> str:
    if not CertificateService.private_key_download_available(user):
        raise ValueError("La llave privada ya fue entregada...")

    private_key_pem = user.private_key_pem_encrypted
    user.private_key_delivered_at = datetime.utcnow()
    user.private_key_pem_encrypted = None   # ← Eliminar del servidor
    db.commit()
    return private_key_pem   # ← Devolver al cliente
```

---

## 11. Administrador Espejo (Recuperación)

### El Problema

¿Qué pasa si el único ADMIN pierde su llave privada o sus credenciales?  
→ Nadie puede entrar al sistema con acceso de admin.

### La Solución: Admin Espejo

El sistema mantiene automáticamente un **administrador espejo** (`is_backup_admin=True`) que es una copia del admin principal pero en estado `revoked`.

```python
class AdminRecoveryService:
    @classmethod
    def sync_backup_admin(cls, db: Session) -> User | None:
        primary = cls.get_primary_admin(db)
        backup = cls.get_backup_admin(db)
        
        if not backup:
            # Crear espejo
            backup = User(
                full_name=f"{primary.full_name} Respaldo",
                email="admin.respaldo@demo.local",
                role_id=admin_role.id,
                status="revoked",   # ← comienza revocado
                is_backup_admin=True,
                mirror_source_user_id=primary.id,
            )
        
        # Emitir su propio certificado
        CertificateService.issue_for_user(db, backup, DEMO_BACKUP_ADMIN_PASSWORD, reissue=True)
```

### Activación del Espejo

```python
@classmethod
def activate_mirror(cls, db: Session, actor: User) -> tuple[User, User]:
    # Revocar al admin principal
    actor.status = "revoked"
    actor.password_hash = None    # ← Sin contraseña: ya no puede entrar

    # Activar el espejo
    backup.status = "active"
    db.commit()
    return actor, backup
```

Cuando se activa el espejo:
1. El admin principal queda `revoked` y sin contraseña
2. El espejo queda `active` con sus propias credenciales
3. El nuevo admin puede emitir credenciales nuevas

**Uso típico**: El equipo de seguridad tiene las credenciales del espejo en un sobre sellado. Si el admin principal queda inaccesible, abren el sobre y usan el espejo.

---

## 12. Bloqueo de Cuenta y Control de Intentos

```python
class NotificationService:
    MAX_LOGIN_ATTEMPTS = 10

# En PasswordLoginService y SignatureLoginService:
user.login_attempts = (user.login_attempts or 0) + 1
if user.login_attempts >= 10:
    user.login_locked_until = datetime.utcnow()   # ← Bloqueo indefinido
    NotificationService.create(db, type="login_blocked", ...)
    raise ValueError("Cuenta bloqueada...")

db.commit()
remaining = 10 - user.login_attempts
raise ValueError(f"Contraseña incorrecta. {remaining} intentos restantes...")
```

| Evento | Acción |
|---|---|
| Intento fallido (contraseña incorrecta) | `login_attempts += 1` |
| Intento fallido (llave privada cifrada con contraseña incorrecta) | `login_attempts += 1` |
| Llegó a 10 intentos | `login_locked_until = NOW`, notificación al admin |
| Login exitoso | `login_attempts = 0`, `login_locked_until = NULL` |
| Desbloqueo manual por admin | `login_locked_until = NULL` |

El bloqueo es **indefinido** — no se desbloquea automáticamente con el tiempo. Requiere acción del administrador. Esto previene ataques de fuerza bruta lentos que esperan el timeout.

---

## 13. Expiración Automática de Usuarios

```python
class ExpirationService:
    @staticmethod
    def expire_users(db: Session) -> int:
        users = db.scalars(
            select(User).where(
                User.status == "active",
                User.is_backup_admin.is_(False),
                User.end_date.is_not(None),
                User.end_date < datetime.utcnow(),   # ← ya venció
            )
        ).all()

        for user in users:
            user.status = "expired"
            # + registrar en audit_log
```

Este método se llama periódicamente (al acceder al dashboard, al portal, etc.).

La fecha `end_date` coincide exactamente con `certificate_not_after` — el sistema los mantiene sincronizados. Cuando un certificado vence, la cuenta también vence. Cuando la cuenta se renueva, se debe re-emitir el certificado.

**Notificaciones preventivas**: 30 días antes del vencimiento del certificado o de `end_date`, se crea una notificación interna:

```python
if user.certificate_not_after <= cutoff:  # cutoff = hoy + 30 días
    NotificationService.create(db, type="cert_expiring_soon", ...)
```

---

## 14. Registro de Auditoría

Toda acción significativa se registra:

```python
AuditService.log(
    db,
    event_type="user_status_updated",
    actor_user_id=actor.id,       # quién hizo la acción
    target_user_id=user.id,       # sobre quién
    action="activate",
    resource="users",
    result="success",             # o "failure"
    metadata={"previous_status": "pending"},
    ip_address=request.client.host,
    user_agent=request.headers.get("User-Agent"),
)
```

### Eventos Auditados

| `event_type` | Cuándo se registra |
|---|---|
| `login_password` | Intento de login por contraseña (éxito o fallo) |
| `login_crypto` | Intento de login criptográfico |
| `user_created` | Nuevo usuario creado |
| `user_status_updated` | Activación/revocación de usuario |
| `certificate_issued` | Emisión de certificado |
| `admin_recovery_activated` | Activación del admin espejo |
| `access_denied` | Intento de acceso sin permiso |
| `user_expired` | Expiración automática |

---

## 15. Reportes PDF con Hash de Integridad

```python
def _pdf_report(...) -> bytes:
    # 1. Serializar datos del reporte como texto
    data_lines = ["\t".join(col_headers)]
    for row in rows:
        data_lines.append("\t".join(str(c) for c in row))
    
    # 2. Calcular SHA-256 del contenido
    sha256 = hashlib.sha256("\n".join(data_lines).encode()).hexdigest()
    
    # 3. Incluir el hash en el pie del PDF
    pdf.multi_cell(0, 5, f"Integridad SHA-256: {sha256}")
```

**SHA-256** (Secure Hash Algorithm 256) es una función hash criptográfica que:
- Produce siempre 256 bits (64 caracteres hexadecimales) sin importar el tamaño de entrada
- Es determinista: el mismo input siempre produce el mismo output
- Es resistente a colisiones: es computacionalmente inviable encontrar dos inputs con el mismo hash
- Es unidireccional: no se puede reconstruir el input desde el hash

**Propósito**: Si alguien altera los datos del reporte después de generarlo, el hash en el PDF ya no coincidirá con el hash calculado sobre los datos alterados. Esto permite detectar **tampering** (manipulación).

**Ejemplo**:
```
Datos originales: "Juan\tCoordinador\t2026-01-01"
SHA-256:          a3f9b2c1... (hash X)

Datos alterados:  "Juan\tAdministrador\t2026-01-01"
SHA-256:          ff1234ab... (hash Y ≠ X)
```

---

## 16. Configuración y Secretos

```python
class Settings(BaseSettings):
    session_secret: str = "cambia-esto-en-produccion"    # ← ¡CAMBIAR EN PROD!
    database_url: str = "sqlite:///identity_demo.db"
    environment: str = "development"
    seed_demo_data: bool = True
    
    @model_validator(mode="after")
    def validate_production_settings(self):
        if self.is_production and self.session_secret == DEFAULT_SESSION_SECRET:
            raise ValueError("SESSION_SECRET debe definirse con un valor seguro")
```

En producción, si `SESSION_SECRET` no se cambia, el servidor **se niega a arrancar**. Esto es una salvaguarda activa contra errores de despliegue.

### Variables de Entorno (`.env`)

```bash
SESSION_SECRET=<mínimo 32 bytes aleatorios, ej. openssl rand -hex 32>
DATABASE_URL=postgresql+psycopg://user:password@host/db
ENVIRONMENT=production
SEED_DEMO_DATA=false
BOOTSTRAP_ADMIN_EMAIL=real_admin@org.org
BOOTSTRAP_ADMIN_PASSWORD=<contraseña segura>
```

---

## 17. Comparaciones Criptográficas: Por Qué Se Eligió Cada Algoritmo

### Hashing de Contraseñas: PBKDF2 vs Argon2 vs bcrypt vs scrypt

| Algoritmo | Uso en este sistema | Resistencia GPU | Resistencia ASIC | Configurabilidad |
|---|---|---|---|---|
| MD5 / SHA1 | ❌ No usado | ❌ | ❌ | ❌ |
| SHA256 sin sal | ❌ No usado | ❌ | ❌ | ❌ |
| **PBKDF2-SHA256** | ✅ Passwords | Media | Baja | Iteraciones |
| bcrypt | ❌ No usado | Alta | Media | Cost factor |
| scrypt | ❌ No usado | Muy alta | Alta | N, r, p |
| Argon2id | ❌ No usado | Muy alta | Muy alta | Memory, time, parallelism |

PBKDF2 fue elegido porque:
- Está en el módulo estándar `hashlib` de Python (sin dependencias extra)
- NIST FIPS 140-2 lo aprueba
- Es suficiente para las amenazas contempladas (atacante con CPU/GPU moderada)
- Argon2id sería la opción ideal para una versión de producción robusta

### Firma Digital: RSA-PSS vs ECDSA vs EdDSA

| Algoritmo | Tamaño firma | Velocidad | Seguridad |
|---|---|---|---|
| RSA-PSS-2048 | 256 bytes | Moderada | Buena (112 bits) |
| ECDSA P-256 | 64 bytes | Rápida | Buena (128 bits) |
| EdDSA Ed25519 | 64 bytes | Muy rápida | Excelente (128 bits) |

RSA-PSS fue elegido por:
- Compatibilidad con X.509 y la cadena de herramientas existente
- El sistema ya usa RSA para los certificados; mezclar ECDSA habría complicado la validación
- Para un sistema interno con pocas firmas por segundo, la diferencia de velocidad es irrelevante

### Autenticación: Contraseña vs Certificado

| Aspecto | Solo contraseña | Certificado + firma |
|---|---|---|
| Factor | Algo que **sabes** | Algo que **tienes** + algo que **sabes** |
| Replay attack | Vulnerable si se intercepta | Inmune (challenge único por timestamp) |
| Phishing | Vulnerable | Difícil (necesitas el archivo físico) |
| Brute force | Con tiempo, posible | Requiere también el archivo `.pem` |
| Revocación | Cambiar contraseña | Revocar certificado, inválido inmediatamente |

Los roles de mayor privilegio (ADMIN, COORDINADOR) usan certificado precisamente por estos beneficios adicionales.

---

## 18. Flujos Completos Paso a Paso

### Flujo 1: El Admin Emite Credenciales para un Coordinador

```
ADMIN inicia sesión (crypto)
  └── POST /login/crypto → sesión válida

ADMIN navega a /ui/users/{coord_id}/certificates/issue
  └── POST /ui/users/{coord_id}/certificates/issue
      ├── password = "contraseña_para_coord"
      └── → CertificateService.issue_for_user(db, coordinador, "contraseña_para_coord")

Dentro de issue_for_user:
  1. private_key = rsa.generate_private_key(65537, 2048)
     → Par RSA fresco, único

  2. signer, signer_key, signer_cert = AdminSignerService.get_signing_material(db)
     → Carga la llave privada del admin desde system_secrets

  3. certificate = x509.CertificateBuilder()
      .subject_name({CN: "Coord Legal", O: "Casa Monarca", email: "..."})
      .issuer_name(signer_cert.subject)       ← Admin como emisor
      .public_key(private_key.public_key())   ← Llave pública del coordinador
      .not_valid_after(coordinador.end_date)
      .sign(private_key=signer_key, algorithm=SHA256)
      → Certificado firmado por el admin

  4. private_key_pem_encrypted = private_key.private_bytes(
      PKCS8, BestAvailableEncryption("contraseña_para_coord")
     )
     → Llave privada cifrada con la contraseña

  5. Guardar en BD:
     coordinador.certificate_pem = <cert_pem>
     coordinador.public_key_pem = <pub_key_pem>
     coordinador.private_key_pem_encrypted = <cifrado>
     coordinador.certificate_issuer_pem = <cert_del_admin>
     coordinador.private_key_delivered_at = NULL

ADMIN descarga llave → GET /ui/users/{coord_id}/private-key.pem
  └── CertificateService.deliver_user_private_key(db, coord)
      ├── Retorna private_key_pem_encrypted (la llave cifrada)
      ├── coord.private_key_delivered_at = NOW
      └── coord.private_key_pem_encrypted = NULL  ← Borrada del servidor

ADMIN entrega a coordinador: private_key.pem + contraseña (por canal seguro)
COORDINADOR descarga su certificate.pem desde el portal
```

### Flujo 2: Coordinador Se Autentica con Sus Archivos

```
COORDINADOR sube:
  - identifier: "coord.legal@demo.local"
  - private_key.pem (archivo descargado previamente)
  - certificate.pem (archivo del portal)
  - password: "contraseña_para_coord"

Servidor ejecuta SignatureLoginService.authenticate_with_private_key_and_certificate:

  1. user = find_user_by_identifier("coord.legal@demo.local")

  2. certificate = x509.load_pem_x509_certificate(certificate_bytes)
     → Parsear el certificado

  3. private_key = serialization.load_pem_private_key(
         private_key_bytes, password=b"contraseña_para_coord"
     )
     → Descifrar con la contraseña
     → Si falla: login_attempts += 1

  4. Validar certificado:
     a. serial == user.certificate_serial  ✓
     b. email en SAN == user.email         ✓
     c. not_valid_before <= NOW <= not_valid_after  ✓
     d. not_valid_after == user.end_date   ✓
     e. subject != issuer (no autofirmado) ✓
     f. Verificar que cert del admin (issuer) es válido (autofirma)
     g. Verificar firma del cert del coord con public key del admin

  5. Challenge:
     challenge = b"login:5:coord.legal@...:2026-05-14T10:30:00+00:00"
     
     signature = private_key.sign(challenge, PSS(MGF1(SHA256), MAX), SHA256)
     
     certificate.public_key().verify(signature, challenge, PSS(...), SHA256)
     → Si pasa: el usuario TIENE la llave privada  ✓

  6. Crear sesión → cookie firmada → redirect /portal
```

---

## 19. Superficie de Ataque y Decisiones de Seguridad

### Amenazas Mitigadas

| Amenaza | Mitigación Implementada |
|---|---|
| Robo de BD con contraseñas | PBKDF2 + sal aleatoria → brute force costoso |
| Falsificación de cookie | HMAC firmado con `session_secret` |
| Replay de cookie | Expiración de 8 horas + `max_age` en cookie |
| XSS → robo de cookie | `httponly=True` en cookie |
| CSRF | `samesite="lax"` + formularios POST |
| Brute force de login | Bloqueo tras 10 intentos, notificación al admin |
| Certificado falsificado | Verificación criptográfica de firma (RSA verify) |
| Certificado de otro usuario | Serial number vinculado al usuario en BD |
| Certificado vencido | Verificación de `not_valid_before/after` |
| Llave privada robada del servidor | Entrega única → eliminada después de la descarga |
| Admin bloqueado | Admin espejo con credenciales propias |
| Suplantación de email | SAN RFC822Name verificado contra email registrado |
| Timing attack en comparación | `hmac.compare_digest()` en vez de `==` |
| Reporte PDF alterado | SHA-256 embebido en el PDF |

### Limitaciones del Sistema (Para Contexto Académico)

1. **La CA privada no tiene CRL ni OCSP**: No hay mecanismo de revocación inmediata de certificados fuera del servidor. En producción real se implementaría una CRL (Certificate Revocation List) o OCSP.

2. **Llave privada del admin en BD en claro**: `AdminSignerService` almacena la llave privada del admin en `system_secrets` sin cifrado adicional. En producción debería estar cifrada con un HSM o KMS.

3. **Sin HTTPS en desarrollo**: `session_cookie_secure` se desactiva en desarrollo. En producción es obligatorio.

4. **PBKDF2 con 120,000 iteraciones**: OWASP recomienda 600,000 en 2023. Argon2id sería preferible para producción.

5. **Secrets en BD**: Usar HashiCorp Vault o AWS Secrets Manager en lugar de la tabla `system_secrets`.

6. **Sin rate limiting global**: El bloqueo por intentos fallidos es por usuario, pero no hay rate limiting a nivel de IP para prevenir ataques distribuidos.

---

*Documento generado con base en el código fuente completo del repositorio. Versión: Mayo 2026.*
