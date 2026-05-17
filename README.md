# Gestor de Identidades — Casa Monarca

Sistema web de gestión de identidades digitales desarrollado para Casa Monarca. Permite administrar usuarios con distintos niveles de acceso mediante criptografía de llave pública (PKI), certificados digitales X.509 y autenticación segura con PBKDF2.

## Características principales

- Autenticación de dos factores para roles privilegiados (llave privada + contraseña).
- Generación de pares de llaves RSA-2048 y certificados X.509 firmados por el administrador.
- Cifrado de llaves privadas con AES-256 en formato PKCS#8.
- Hashing de contraseñas con PBKDF2 (120,000 iteraciones, HMAC-SHA256).
- Cookies de sesión firmadas con HMAC (httponly, samesite).
- Cuatro roles con distintos niveles de privilegio: Administrador, Coordinador, Operativo y Voluntario.
- Revocación y reactivación de cuentas con reemisión de material criptográfico.
- Administrador espejo para recuperación de acceso.
- Registro de auditoría inmutable (login, cambios de estado, emisión de certificados).
- Exportación de reportes en PDF con hash SHA-256 de integridad.
- Bloqueo automático tras 10 intentos fallidos de login.
- Despliegue con Docker y soporte para Render.

## Requisitos

- Python 3.11 o superior
- pip
- (Opcional) Docker para despliegue con contenedor

### Dependencias principales

- FastAPI
- SQLAlchemy 2.0+
- cryptography
- itsdangerous
- uvicorn
- fpdf2
- python-multipart
- pydantic-settings
- psycopg (para PostgreSQL en producción)

## Instalación

1. Clonar el repositorio:

```bash
git clone https://github.com/<tu-usuario>/RetoCriptografia-Equipo2.git
cd RetoCriptografia-Equipo2
```

2. Crear un entorno virtual e instalar dependencias:

```bash
python -m venv venv
source venv/bin/activate   # En Windows: venv\Scripts\activate
pip install .
```

3. Copiar el archivo de variables de entorno y ajustar si es necesario:

```bash
cp .env.example .env
```

## Configuración

El archivo `.env` contiene las variables de configuración. Las más relevantes son:

| Variable | Descripción | Valor por defecto |
|---|---|---|
| `DATABASE_URL` | Cadena de conexión a la base de datos | `sqlite:///./identity_demo.db` |
| `SESSION_SECRET` | Secreto para firmar cookies de sesión | `cambia-esto-en-desarrollo` |
| `CERTS_DIR` | Directorio donde se guardan los certificados | `./generated/certs` |
| `SEED_DEMO_DATA` | Cargar datos de demostración al iniciar | `true` |
| `ENVIRONMENT` | `development` o `production` | `development` |

En producción se recomienda usar PostgreSQL y generar un `SESSION_SECRET` aleatorio.

## Uso básico

Iniciar el servidor en modo desarrollo:

```bash
uvicorn app.main:app --reload
```

Abrir el navegador en `http://127.0.0.1:8000`. En modo demo, se puede entrar como administrador con las credenciales `admin` / `admin`.

Con Docker:

```bash
docker build -t gestor-identidades .
docker run -p 8000:8000 gestor-identidades
```

## Estructura del proyecto

```
RetoCriptografia-Equipo2/
├── app/
│   ├── __init__.py
│   ├── config.py          # Variables de configuración (pydantic-settings)
│   ├── db.py              # Conexión y sesión de base de datos (SQLAlchemy)
│   ├── deps.py            # Dependencias de FastAPI (sesión, auth)
│   ├── main.py            # Rutas, vistas y lógica de la aplicación
│   ├── models.py          # Modelos ORM (User, Role, AuditLog, etc.)
│   ├── schemas.py         # Esquemas Pydantic de validación
│   ├── services.py        # Lógica de negocio y criptografía
│   └── static/            # Archivos estáticos (CSS, imágenes)
├── docs/                  # Documentación del proyecto
├── generated/
│   └── certs/             # Certificados y llaves generados
│       ├── ca/            # Certificado y llave de la CA (admin)
│       └── users/         # Material criptográfico por usuario
├── sql/
│   └── schema.sql         # Esquema SQL de referencia
├── .env.example           # Plantilla de variables de entorno
├── Dockerfile             # Imagen Docker para despliegue
├── pyproject.toml         # Metadatos y dependencias del proyecto
└── render.yaml            # Configuración de despliegue en Render
```

## Contribuciones

Si quieres colaborar con el proyecto:

1. Haz un fork del repositorio y clónalo en tu máquina.
2. Lee el archivo `COMO_FUNCIONA_EL_PROYECTO.md` para entender la arquitectura general.
3. Revisa la carpeta `docs/` para consultar la documentación técnica y criptográfica.
4. Crea una rama con un nombre descriptivo (`git checkout -b feature/mi-cambio`).
5. Realiza tus cambios y asegúrate de que el servidor arranca sin errores.
6. Haz commit y abre un Pull Request describiendo qué modificaste y por qué.

Antes de modificar la lógica criptográfica, revisa `app/services.py` y la documentación en `docs/` para entender el flujo de llaves y certificados.

## Pruebas básicas

El proyecto no incluye un framework de pruebas automatizadas por el momento. Para verificar que todo funciona correctamente:

1. Iniciar el servidor con `uvicorn app.main:app --reload`.
2. Entrar como admin (`admin` / `admin` en modo demo).
3. Crear un usuario con rol Coordinador, activarlo y descargar sus archivos.
4. Cerrar sesión e iniciar sesión como el usuario creado subiendo su llave privada y certificado.
5. Verificar que el portal muestra "Identidad verificada con archivos de acceso".
6. Revocar al usuario desde el panel de admin y confirmar que ya no puede iniciar sesión.
7. Revisar la sección de auditoría para confirmar que todos los eventos quedaron registrados.

## Licencia

Este proyecto se distribuye bajo la licencia MIT.

## Contacto

**Equipo 2**

María Fernanda Montoya López — A01743214@tec.mx - Lider de equipo
