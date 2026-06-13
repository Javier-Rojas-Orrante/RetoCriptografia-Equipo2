Gestor de Identidades - Casa Monarca
======================================

Descripcion
-----------
Sistema web de gestion de identidades y accesos digitales desarrollado para
Casa Monarca, Ayuda Humanitaria al Migrante A.B.P. Permite administrar
usuarios con distintos niveles de privilegio mediante criptografia de llave
publica (PKI), certificados digitales X.509, firma digital de documentos
y cifrado de informacion sensible en reposo.

Caracteristicas principales
---------------------------
- Cuatro roles con distintos niveles de acceso: Administrador, Coordinador,
  Operativo y Voluntario.
- Autenticacion con llave privada + certificado + contrasena para roles
  privilegiados (Administrador y Coordinador).
- Autenticacion con correo y contrasena para roles basicos (Operativo y
  Voluntario).
- Generacion de pares de llaves RSA-2048 y certificados X.509 firmados por
  el administrador (cadena de confianza interna).
- Cifrado de llaves privadas con AES-256 en formato PKCS#8.
- Hashing de contrasenas con PBKDF2-HMAC-SHA256 (120,000 iteraciones).
- Cifrado en reposo de toda la informacion sensible en la base de datos
  con Fernet (AES-128-CBC + HMAC).
- Busqueda ciega sobre datos cifrados mediante digests HMAC-SHA256
  (columnas lookup).
- Firma digital de documentos con RSA-PSS-SHA256 y verificacion publica.
- Soporte para documentos con multiples firmantes (co-firma secuencial).
- Portal publico de verificacion de autenticidad de documentos.
- Firma masiva de documentos (batch signing).
- Registro de beneficiarios con datos cifrados en reposo.
- Notificaciones en tiempo real via WebSocket.
- Bloqueo automatico de cuentas tras 10 intentos fallidos de login.
- Administrador espejo para recuperacion de emergencia.
- Registro de auditoria inmutable (login, cambios de estado, emision de
  certificados, verificaciones de documentos).
- Exportacion de reportes en PDF con hash SHA-256 de integridad.
- Cookies de sesion firmadas con HMAC (httponly, samesite, 8 horas).
- Auto-registro de usuarios con aprobacion manual del administrador.
- Alertas automaticas por vencimiento de certificados y cuentas.
- Despliegue con Docker y soporte para Render (PostgreSQL en produccion).

Requisitos
----------
- Python 3.11 o superior
- pip
- (Opcional) Docker para despliegue con contenedor

Dependencias principales:
  FastAPI, SQLAlchemy 2.0+, cryptography, itsdangerous, uvicorn, fpdf2,
  python-multipart, pydantic-settings, psycopg (para PostgreSQL).

Todas las dependencias se instalan automaticamente con pip install .

Instalacion
-----------
1. Clonar el repositorio:

   git clone https://github.com/tu-usuario/RetoCriptografia-Equipo2.git
   cd RetoCriptografia-Equipo2

2. Crear un entorno virtual e instalar dependencias:

   python -m venv venv
   venv\Scripts\activate          (Windows)
   source venv/bin/activate       (Linux/Mac)
   pip install .

3. Copiar el archivo de variables de entorno y ajustar si es necesario:

   copy .env.example .env         (Windows)
   cp .env.example .env           (Linux/Mac)

Configuracion
-------------
El archivo .env contiene las variables de configuracion. Las mas relevantes:

  DATABASE_URL          Cadena de conexion a la BD (default: sqlite local)
  SESSION_SECRET        Secreto para firmar cookies de sesion
  CERTS_DIR             Directorio de certificados (default: generated/certs)
  SEED_DEMO_DATA        Cargar datos demo al iniciar (default: true)
  ENVIRONMENT           development o production (default: development)
  DATABASE_ENCRYPTION_KEY  Clave para cifrar datos en reposo en la BD
  BOOTSTRAP_ADMIN_EMAIL    Correo del admin inicial (solo sin datos demo)
  BOOTSTRAP_ADMIN_PASSWORD Contrasena del admin inicial (solo sin datos demo)

En produccion se recomienda usar PostgreSQL, generar un SESSION_SECRET
aleatorio y definir una DATABASE_ENCRYPTION_KEY segura.

Uso basico
----------
Iniciar el servidor en modo desarrollo:

   uvicorn app.main:app --reload

Abrir el navegador en http://127.0.0.1:8000

En modo demo se puede entrar como administrador con: admin / admin
Otros usuarios demo: operativo / demo1234, voluntario / demo1234

Con Docker:

   docker build -t gestor-identidades .
   docker run -p 8000:8000 gestor-identidades

Estructura del proyecto
-----------------------
RetoCriptografia-Equipo2/
  app/
    __init__.py
    config.py            Configuracion global (pydantic-settings, .env)
    crypto.py            Cifrado de BD (Fernet, HMAC-SHA256, TypeDecorators)
    db.py                Conexion y sesion de base de datos (SQLAlchemy)
    deps.py              Dependencia de FastAPI para inyectar sesion de BD
    main.py              Rutas, vistas HTML, logica de sesion y endpoints
    models.py            Modelos ORM (User, Role, Document, Beneficiario, etc.)
    schemas.py           Esquemas Pydantic para respuestas de la API
    services.py          Logica de negocio: PKI, firma digital, login, CRUD
    static/              Imagenes y recursos estaticos (logos, fondos)
  generated/
    certs/
      ca/                Certificado y llave de la CA interna
      users/             Material criptografico por usuario
  sql/
    schema.sql           Esquema SQL de referencia
  .env.example           Plantilla de variables de entorno
  Dockerfile             Imagen Docker para despliegue
  pyproject.toml         Metadatos y dependencias del proyecto
  render.yaml            Configuracion de despliegue en Render

Contribuciones
--------------
Si quieres colaborar con el proyecto:

1. Haz un fork del repositorio y clonalo en tu maquina.
2. Revisa este README para entender la estructura general del proyecto.
3. Lee los comentarios en el codigo fuente (app/) para entender la
   arquitectura. Cada archivo tiene comentarios que explican su proposito.
4. Los archivos clave son:
   - app/services.py  -> toda la logica de negocio y criptografia.
   - app/models.py    -> modelos de datos y cifrado en reposo.
   - app/crypto.py    -> motor de cifrado de la base de datos.
   - app/main.py      -> rutas y renderizado de la interfaz.
5. Crea una rama con un nombre descriptivo (git checkout -b feature/mi-cambio).
6. Realiza tus cambios y asegurate de que el servidor arranca sin errores.
7. Haz commit y abre un Pull Request describiendo que modificaste y por que.

Antes de modificar la logica criptografica, revisa app/services.py para
entender el flujo de llaves, certificados y firma digital.

Pruebas basicas
---------------
El proyecto no incluye un framework de pruebas automatizadas. Para verificar
que todo funciona correctamente:

1. Iniciar el servidor con: uvicorn app.main:app --reload
2. Entrar como admin (admin / admin en modo demo).
3. Crear un usuario con rol Coordinador, activarlo y descargar sus archivos.
4. Cerrar sesion e iniciar sesion como el Coordinador subiendo su llave
   privada, su certificado y su contrasena.
5. Verificar que el portal muestra "Identidad verificada con archivos de
   acceso".
6. Firmar un documento desde la seccion "Firmar documentos" del portal.
7. Verificar el documento firmado desde el portal publico /verificar usando
   el folio generado.
8. Modificar el archivo original y volver a verificarlo para confirmar que
   el sistema detecta la alteracion.
9. Revocar al usuario desde el panel de admin y confirmar que ya no puede
   iniciar sesion.
10. Revisar la seccion de auditoria para confirmar que todos los eventos
    quedaron registrados.

Licencia
--------
Este proyecto se distribuye bajo la licencia MIT.

Contacto
--------
Equipo 2

Maria Fernanda Montoya Lopez - A01743214@tec.mx - Lider de equipo
