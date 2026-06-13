# Gestor de Identidades - Casa Monarca

## Descripción

Sistema web de gestión de identidades y accesos digitales desarrollado para
Casa Monarca, Ayuda Humanitaria al Migrante A.B.P. Permite administrar
usuarios con distintos niveles de privilegio mediante criptografía de llave
pública (PKI), certificados digitales X.509, firma digital de documentos
y cifrado de información sensible en reposo.

## Características principales

- Cuatro roles con distintos niveles de acceso: Administrador, Coordinador, Operativo y Voluntario.
- Autenticación con llave privada + certificado + contraseña para roles privilegiados (Administrador y Coordinador).
- Autenticación con correo y contraseña para roles básicos (Operativo y Voluntario).
- Generación de pares de llaves RSA-2048 y certificados X.509 firmados por el administrador (cadena de confianza interna).
- Cifrado de llaves privadas con AES-256 en formato PKCS#8.
- Hashing de contraseñas con PBKDF2-HMAC-SHA256 (120,000 iteraciones).
- Cifrado en reposo de toda la información sensible en la base de datos con Fernet (AES-128-CBC + HMAC).
- Búsqueda ciega sobre datos cifrados mediante digests HMAC-SHA256 (columnas lookup).
- Firma digital de documentos con RSA-PSS-SHA256 y verificación pública.
- Soporte para documentos con múltiples firmantes (co-firma secuencial).
- Portal público de verificación de autenticidad de documentos.
- Firma masiva de documentos (batch signing).
- Registro de beneficiarios con datos cifrados en reposo.
- Notificaciones en tiempo real via WebSocket.
- Bloqueo automático de cuentas tras 10 intentos fallidos de login.
- Administrador espejo para recuperación de emergencia.
- Registro de auditoría inmutable (login, cambios de estado, emisión de certificados, verificaciones de documentos).
- Exportación de reportes en PDF con hash SHA-256 de integridad.
- Cookies de sesión firmadas con HMAC (httponly, samesite, 8 horas).
- Auto-registro de usuarios con aprobación manual del administrador.
- Alertas automáticas por vencimiento de certificados y cuentas.
- Despliegue con Docker y soporte para Render (PostgreSQL en producción).

## Requisitos

- Python 3.11 o superior
- pip
- (Opcional) Docker para despliegue con contenedor

**Dependencias principales:**
FastAPI, SQLAlchemy 2.0+, cryptography, itsdangerous, uvicorn, fpdf2,
python-multipart, pydantic-settings, psycopg (para PostgreSQL).

Todas las dependencias se instalan automáticamente con `pip install .`

## Instalación

1. Clonar el repositorio:

```bash
git clone https://github.com/tu-usuario/RetoCriptografia-Equipo2.git
cd RetoCriptografia-Equipo2
```

2. Crear un entorno virtual e instalar dependencias:

```bash
python -m venv venv
venv\Scripts\activate          # Windows
source venv/bin/activate       # Linux/Mac
pip install .
```

3. Copiar el archivo de variables de entorno y ajustar si es necesario:

```bash
copy .env.example .env         # Windows
cp .env.example .env           # Linux/Mac
```

## Configuración

El archivo `.env` contiene las variables de configuración. Las más relevantes:

| Variable | Descripción |
|---|---|
| `DATABASE_URL` | Cadena de conexión a la BD (default: sqlite local) |
| `SESSION_SECRET` | Secreto para firmar cookies de sesión |
| `CERTS_DIR` | Directorio de certificados (default: generated/certs) |
| `SEED_DEMO_DATA` | Cargar datos demo al iniciar (default: true) |
| `ENVIRONMENT` | development o production (default: development) |
| `DATABASE_ENCRYPTION_KEY` | Clave para cifrar datos en reposo en la BD |
| `BOOTSTRAP_ADMIN_EMAIL` | Correo del admin inicial (solo sin datos demo) |
| `BOOTSTRAP_ADMIN_PASSWORD` | Contraseña del admin inicial (solo sin datos demo) |

En producción se recomienda usar PostgreSQL, generar un `SESSION_SECRET`
aleatorio y definir una `DATABASE_ENCRYPTION_KEY` segura.

## Uso básico

Iniciar el servidor en modo desarrollo:

```bash
uvicorn app.main:app --reload
```

Abrir el navegador en http://127.0.0.1:8000

En modo demo se puede entrar como administrador con: `admin` / `admin`  
Otros usuarios demo: `operativo` / `demo1234`, `voluntario` / `demo1234`

**Con Docker:**

```bash
docker build -t gestor-identidades .
docker run -p 8000:8000 gestor-identidades
```

## Estructura del proyecto

```
RetoCriptografia-Equipo2/
  app/
    __init__.py
    config.py            # Configuración global (pydantic-settings, .env)
    crypto.py            # Cifrado de BD (Fernet, HMAC-SHA256, TypeDecorators)
    db.py                # Conexión y sesión de base de datos (SQLAlchemy)
    deps.py              # Dependencia de FastAPI para inyectar sesión de BD
    main.py              # Rutas, vistas HTML, lógica de sesión y endpoints
    models.py            # Modelos ORM (User, Role, Document, Beneficiario, etc.)
    schemas.py           # Esquemas Pydantic para respuestas de la API
    services.py          # Lógica de negocio: PKI, firma digital, login, CRUD
    static/              # Imágenes y recursos estáticos (logos, fondos)
  generated/
    certs/
      ca/                # Certificado y llave de la CA interna
      users/             # Material criptográfico por usuario
  sql/
    schema.sql           # Esquema SQL de referencia
  .env.example           # Plantilla de variables de entorno
  Dockerfile             # Imagen Docker para despliegue
  pyproject.toml         # Metadatos y dependencias del proyecto
  render.yaml            # Configuración de despliegue en Render
```

## Contribuciones

Si quieres colaborar con el proyecto:

1. Haz un fork del repositorio y clónalo en tu máquina.
2. Revisa este README para entender la estructura general del proyecto.
3. Lee los comentarios en el código fuente (`app/`) para entender la arquitectura. Cada archivo tiene comentarios que explican su propósito.
4. Los archivos clave son:
   - `app/services.py` → toda la lógica de negocio y criptografía.
   - `app/models.py` → modelos de datos y cifrado en reposo.
   - `app/crypto.py` → motor de cifrado de la base de datos.
   - `app/main.py` → rutas y renderizado de la interfaz.
5. Crea una rama con un nombre descriptivo: `git checkout -b feature/mi-cambio`
6. Realiza tus cambios y asegúrate de que el servidor arranca sin errores.
7. Haz commit y abre un Pull Request describiendo qué modificaste y por qué.

Antes de modificar la lógica criptográfica, revisa `app/services.py` para
entender el flujo de llaves, certificados y firma digital.

## Pruebas básicas

El proyecto no incluye un framework de pruebas automatizadas. Para verificar
que todo funciona correctamente:

1. Iniciar el servidor con: `uvicorn app.main:app --reload`
2. Entrar como admin (`admin` / `admin` en modo demo).
3. Crear un usuario con rol Coordinador, activarlo y descargar sus archivos.
4. Cerrar sesión e iniciar sesión como el Coordinador subiendo su llave privada, su certificado y su contraseña.
5. Verificar que el portal muestra "Identidad verificada con archivos de acceso".
6. Firmar un documento desde la sección "Firmar documentos" del portal.
7. Verificar el documento firmado desde el portal público `/verificar` usando el folio generado.
8. Modificar el archivo original y volver a verificarlo para confirmar que el sistema detecta la alteración.
9. Revocar al usuario desde el panel de admin y confirmar que ya no puede iniciar sesión.
10. Revisar la sección de auditoría para confirmar que todos los eventos quedaron registrados.

## Licencia

Este proyecto se distribuye bajo la licencia MIT.

## Contacto

**Equipo 2**

María Fernanda Montoya López - A01743214@tec.mx - Líder de equipo
