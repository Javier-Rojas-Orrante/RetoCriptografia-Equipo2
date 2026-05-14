# MANUAL DE USUARIO
# Gestor de Identidades — Casa Monarca
### Versión 1.0

---

## PORTADA

**Instituto Tecnológico y de Estudios Superiores de Monterrey**

*(Aquí debe colocarse el escudo oficial del Tecnológico de Monterrey centrado en la página)*

**Escuela de Ingeniería y Ciencias**
**Ingeniería en Ciencias de Datos y Matemáticas**

---

### Gestor de Identidades
**Manual de Usuario — Versión 1.0**

---

| Campo | Información |
|---|---|
| **Estudiantes** | [Nombre Completo 1] — Matrícula: AXXXXXXXX |
| | [Nombre Completo 2] — Matrícula: AXXXXXXXX |
| | [Nombre Completo 3] — Matrícula: AXXXXXXXX |
| | [Nombre Completo 4] — Matrícula: AXXXXXXXX |
| **Equipo** | Equipo [N] |
| **Grupo** | [Clave de grupo, p. ej. TC3059.1] |
| **Profesores** | [Nombre del Profesor 1] |
| | [Nombre del Profesor 2] |
| **Socio Formador** | Casa Monarca — Ayuda Humanitaria al Migrante, A.B.P. |
| **Lugar** | Monterrey, Nuevo León |
| **Fecha** | 30 de abril de 2023 |

---

## ÍNDICE DE CONTENIDOS

1. [Introducción](#1-introducción)
   - 1.1 Qué es la aplicación
   - 1.2 Para qué sirve
   - 1.3 A quién va dirigida
2. [Requerimientos del Sistema](#2-requerimientos-del-sistema)
   - 2.1 Hardware mínimo
   - 2.2 Software necesario
   - 2.3 Versiones compatibles
3. [Instalación](#3-instalación)
   - 3.1 Pasos de instalación
   - 3.2 Configuración de variables de entorno
   - 3.3 Consideraciones importantes
4. [Inicio de la Aplicación](#4-inicio-de-la-aplicación)
   - 4.1 Cómo acceder
   - 4.2 Inicio de sesión
   - 4.3 Configuración inicial del administrador
5. [Guía de Uso](#5-guía-de-uso)
   - 5.1 Solicitar acceso (usuario nuevo)
   - 5.2 Iniciar sesión
   - 5.3 Portal de usuario
   - 5.4 Registrar un beneficiario
   - 5.5 Panel de administración
   - 5.6 Crear un usuario
   - 5.7 Activar una cuenta
   - 5.8 Emitir certificados criptográficos
   - 5.9 Revocar un usuario
   - 5.10 Ver y gestionar notificaciones
   - 5.11 Revisar el registro de auditoría
   - 5.12 Solicitar recuperación de acceso
   - 5.13 Desbloquear una cuenta bloqueada
6. [Solución de Problemas](#6-solución-de-problemas)
7. [Preguntas Frecuentes](#7-preguntas-frecuentes)
8. [Referencias](#8-referencias)

---

## ÍNDICE DE TABLAS

| Tabla | Descripción |
|---|---|
| Tabla 1 | Roles del sistema y sus privilegios |
| Tabla 2 | Requerimientos de hardware mínimo |
| Tabla 3 | Software necesario |
| Tabla 4 | Variables de entorno del sistema |
| Tabla 5 | Errores comunes y soluciones |

---

## ÍNDICE DE FIGURAS

| Figura | Descripción |
|---|---|
| Figura 1 | Pantalla principal de inicio de sesión |
| Figura 2 | Formulario de inicio de sesión con archivos criptográficos |
| Figura 3 | Pantalla de solicitud de acceso (registro público) |
| Figura 4 | Mensaje de confirmación de solicitud enviada |
| Figura 5 | Portal de usuario — Vista general |
| Figura 6 | Sección de flujo criptográfico en el portal |
| Figura 7 | Formulario de registro de beneficiario |
| Figura 8 | Panel de administración (dashboard) — Vista general |
| Figura 9 | Barra lateral del panel de administración |
| Figura 10 | Sección "Alta de usuario" en el dashboard |
| Figura 11 | Fila expandida de gestión de usuario |
| Figura 12 | Panel "Cuenta" — Botón de activación |
| Figura 13 | Panel "Flujo criptográfico" con pasos de emisión |
| Figura 14 | Sección de notificaciones con badge |
| Figura 15 | Detalle de una notificación individual |
| Figura 16 | Registro de auditoría con IP y agente |
| Figura 17 | Formulario de recuperación de acceso en login |
| Figura 18 | Botón "Desbloquear cuenta" en panel de usuario |

---

## 1. INTRODUCCIÓN

### 1.1 Qué es la aplicación

El **Gestor de Identidades de Casa Monarca** es una aplicación web desarrollada para administrar de forma segura las cuentas y los permisos del personal de Casa Monarca — Ayuda Humanitaria al Migrante, A.B.P. El sistema permite crear usuarios, asignarles roles, emitir certificados digitales X.509, registrar beneficiarios y mantener un historial completo de auditoría de todas las acciones.

La aplicación combina dos métodos de autenticación:

- **Autenticación criptográfica** (para Administrador y Coordinador): el usuario inicia sesión con su llave privada (`private_key.pem`) y su certificado digital (`certificate.pem`), archivos que equivalen a una identificación digital firmada.
- **Autenticación por contraseña** (para Operativo y Voluntario): el usuario inicia sesión con su correo electrónico y una contraseña.

### 1.2 Para qué sirve

El sistema cubre las siguientes necesidades operativas de Casa Monarca:

- **Gestión de identidades**: crear, activar, revocar y modificar cuentas de personal.
- **Seguridad criptográfica**: emitir y validar certificados digitales X.509 para roles sensibles.
- **Registro de beneficiarios**: capturar y dar seguimiento a personas atendidas por el centro.
- **Auditoría**: registrar automáticamente cada acción del sistema (quién hizo qué, cuándo y desde qué IP).
- **Notificaciones**: alertar al administrador sobre cuentas bloqueadas, certificados próximos a vencer y solicitudes de recuperación de acceso.

### 1.3 A quién va dirigida

**Tabla 1. Roles del sistema y sus privilegios**

| Rol | Tipo de acceso | Capacidades principales |
|---|---|---|
| **Administrador** | Criptográfico (private_key + certificate) | Gestión completa de usuarios, certificados, auditoría, notificaciones y CRUD de beneficiarios |
| **Coordinador** | Criptográfico (private_key + certificate) | Ver su portal, crear y actualizar beneficiarios (sin eliminar) |
| **Operativo** | Contraseña | Ver su portal, registrar y consultar beneficiarios |
| **Voluntario** | Contraseña | Ver su portal, registrar beneficiarios (sin consultar) |

---

## 2. REQUERIMIENTOS DEL SISTEMA

### 2.1 Hardware mínimo

**Tabla 2. Requerimientos de hardware mínimo**

| Componente | Mínimo recomendado |
|---|---|
| Procesador | Dual-core 1.6 GHz |
| Memoria RAM | 2 GB |
| Almacenamiento | 500 MB libres |
| Conexión de red | 1 Mbps (para acceso remoto) |
| Resolución de pantalla | 1280 × 720 px |

> El servidor donde se despliega la aplicación requiere al menos **1 GB de RAM** y **1 GB de espacio en disco** para la base de datos.

### 2.2 Software necesario

**Tabla 3. Software necesario**

| Software | Uso | Dónde obtenerlo |
|---|---|---|
| Python 3.11 o superior | Ejecutar la aplicación | python.org |
| pip (incluido con Python) | Instalar dependencias | — |
| Navegador web moderno | Acceder a la interfaz | Chrome, Firefox, Edge, Safari |
| Git (opcional) | Clonar el repositorio | git-scm.com |
| Docker (opcional) | Despliegue en contenedor | docker.com |

### 2.3 Versiones compatibles

- **Python**: 3.11, 3.12
- **Sistemas operativos**: Windows 10/11, macOS 12+, Ubuntu 20.04+
- **Navegadores**: Chrome 110+, Firefox 110+, Edge 110+, Safari 16+
- **Base de datos**: SQLite (desarrollo local), PostgreSQL 14+ (producción)

---

## 3. INSTALACIÓN

### 3.1 Pasos de instalación

Los siguientes pasos permiten ejecutar la aplicación en un entorno local de desarrollo.

**Paso 1 — Obtener el código fuente**

Descarga o clona el repositorio en tu equipo:

```bash
git clone <url-del-repositorio>
cd RetoCriptografia-Equipo2
```

**Paso 2 — Crear y activar un entorno virtual (recomendado)**

En Windows:
```bash
python -m venv venv
venv\Scripts\activate
```

En macOS/Linux:
```bash
python -m venv venv
source venv/bin/activate
```

**Paso 3 — Instalar dependencias**

```bash
pip install -e .
```

Este comando instala todos los paquetes necesarios (FastAPI, SQLAlchemy, cryptography, itsdangerous, uvicorn, entre otros).

**Paso 4 — Configurar variables de entorno** *(ver sección 3.2)*

**Paso 5 — Iniciar el servidor**

```bash
uvicorn app.main:app --reload
```

*(Aquí debe colocarse una captura del terminal mostrando el mensaje `Uvicorn running on http://127.0.0.1:8000`)*

**Paso 6 — Abrir en el navegador**

Abre la siguiente dirección en tu navegador:

```
http://127.0.0.1:8000
```

### 3.2 Configuración de variables de entorno

**Tabla 4. Variables de entorno del sistema**

| Variable | Descripción | Valor en desarrollo | Valor en producción |
|---|---|---|---|
| `SEED_DEMO_DATA` | Carga usuarios de prueba al iniciar | `true` | `false` |
| `SESSION_SECRET` | Clave para firmar las cookies de sesión | Cualquier texto | Cadena aleatoria larga (min 32 chars) |
| `SESSION_COOKIE_SECURE` | Requiere HTTPS para las cookies | `false` | `true` |
| `BOOTSTRAP_ADMIN_EMAIL` | Correo del administrador inicial | — | correo real |
| `BOOTSTRAP_ADMIN_PASSWORD` | Contraseña del administrador inicial | — | contraseña segura |
| `DATABASE_URL` | Cadena de conexión a la base de datos | `sqlite:///./identity.db` | URL de PostgreSQL |

Para desarrollo, crea un archivo `.env` en la raíz del proyecto con estas variables o defínelas en tu terminal antes de iniciar el servidor.

### 3.3 Consideraciones importantes

- En modo desarrollo (`SEED_DEMO_DATA=true`), el sistema crea automáticamente usuarios de prueba con credenciales predefinidas. **No uses estas credenciales en producción.**
- La base de datos SQLite se crea automáticamente la primera vez que arranca el servidor. No requiere configuración adicional en desarrollo.
- En producción, se recomienda usar PostgreSQL y configurar un proxy HTTPS (por ejemplo, con Nginx o el servicio de Render).
- Los archivos `private_key.pem` y `certificate.pem` generados por el sistema **son de uso exclusivo del usuario**. Deben entregarse en persona y nunca enviarse por correo electrónico.

---

## 4. INICIO DE LA APLICACIÓN

### 4.1 Cómo acceder

Una vez que el servidor está en ejecución, abre un navegador web e ingresa la dirección del sistema:

- **Desarrollo local**: `http://127.0.0.1:8000`
- **Producción**: La URL proporcionada por el administrador de la organización.

El sistema mostrará automáticamente la pantalla de inicio de sesión.

### 4.2 Inicio de sesión

**Figura 1. Pantalla principal de inicio de sesión**
*(Aquí debe colocarse una captura de pantalla completa de la página de login. Se debe ver el panel izquierdo con el logo de Casa Monarca sobre la imagen de fondo, y el panel derecho con el formulario de inicio de sesión con los campos: "Correo o usuario", "private_key.pem", "certificate.pem", "Contraseña" y el botón "Entrar".)*

La pantalla de inicio de sesión tiene dos paneles:

- **Panel izquierdo**: muestra el nombre y logo de Casa Monarca con una imagen de fondo.
- **Panel derecho**: contiene el formulario de inicio de sesión.

**Figura 2. Formulario de inicio de sesión con archivos criptográficos**
*(Aquí debe colocarse una captura del panel derecho del login donde se vean claramente los cuatro campos del formulario: el campo de texto "Correo o usuario", los dos campos de carga de archivo ("private_key.pem" y "certificate.pem"), el campo de contraseña y el botón "Entrar" en color terracota.)*

Dependiendo de tu rol, el proceso de inicio de sesión es diferente:

**Para Administrador y Coordinador (acceso criptográfico):**
1. Ingresa tu correo electrónico en el campo **"Correo o usuario"**.
2. En el campo **"private_key.pem"**, selecciona tu archivo de llave privada.
3. En el campo **"certificate.pem"**, selecciona tu archivo de certificado digital.
4. Escribe la **contraseña** que protege tu llave privada.
5. Haz clic en **"Entrar"**.

**Para Operativo y Voluntario (acceso con contraseña):**
1. Ingresa tu correo electrónico o nombre de usuario en **"Correo o usuario"**.
2. Escribe tu contraseña en el campo **"Contraseña"**.
3. Haz clic en **"Entrar"**.
4. Los campos de archivo pueden dejarse vacíos.

> **Nota**: Si introduces una contraseña incorrecta 10 veces seguidas, tu cuenta se bloqueará automáticamente. Deberás contactar al administrador para desbloquearla.

### 4.3 Configuración inicial del administrador

Al desplegar el sistema por primera vez (con `SEED_DEMO_DATA=false`):

1. El administrador inicial puede entrar usando su correo y contraseña configurados en `BOOTSTRAP_ADMIN_EMAIL` y `BOOTSTRAP_ADMIN_PASSWORD`.
2. Una vez dentro del panel de administración, debe emitir su propio certificado digital desde la sección **"Flujo criptográfico"** de su perfil.
3. A partir de ese momento, el acceso será exclusivamente con `private_key.pem` y `certificate.pem`.

---

## 5. GUÍA DE USO

---

### 5.1 Solicitar acceso (usuario nuevo)

Este flujo es para personas que no tienen cuenta y desean solicitar acceso al sistema.

**Paso a paso:**

1. En la pantalla de login, haz clic en el botón **"Solicitar acceso"**.

**Figura 3. Pantalla de solicitud de acceso (registro público)**
*(Aquí debe colocarse una captura de la página /register completa. Se debe ver el formulario con los cuatro campos: "Nombre completo", "Correo electrónico", "Contraseña" y "Confirmar contraseña", además del botón "Enviar solicitud" y el enlace "← Volver al inicio de sesión".)*

2. Completa el formulario con:
   - **Nombre completo**: tu nombre como aparece en documentos oficiales.
   - **Correo electrónico**: el correo institucional que usarás para ingresar.
   - **Contraseña**: mínimo 6 caracteres.
   - **Confirmar contraseña**: repite la misma contraseña.
3. Haz clic en **"Enviar solicitud"**.

**Resultado esperado:**

**Figura 4. Mensaje de confirmación de solicitud enviada**
*(Aquí debe colocarse una captura de la pantalla de login después de enviar la solicitud, donde se vea el aviso verde con el texto "Solicitud de acceso enviada. Un administrador revisará tu cuenta y te notificará cuando esté activa.")*

El sistema te regresará a la pantalla de login con un aviso verde confirmando que tu solicitud fue recibida. Tu cuenta estará en estado **"pendiente"** hasta que un administrador la apruebe y te asigne una contraseña o credenciales definitivas.

---

### 5.2 Iniciar sesión

**Paso a paso (con contraseña):**

1. Ingresa a la dirección del sistema en tu navegador.
2. Escribe tu correo o nombre de usuario.
3. Escribe tu contraseña.
4. Haz clic en **"Entrar"**.
5. Si las credenciales son correctas, el sistema te llevará a tu **portal de usuario**.

**Paso a paso (con certificado criptográfico):**

1. Ingresa tu correo electrónico.
2. Selecciona tu archivo `private_key.pem` haciendo clic en el campo correspondiente.
3. Selecciona tu archivo `certificate.pem`.
4. Escribe la contraseña que protege tu llave privada.
5. Haz clic en **"Entrar"**.
6. El sistema te llevará al **panel de administración** (si eres Administrador) o a tu **portal de usuario** (si eres Coordinador).

**Resultado esperado:**

El sistema valida tu identidad y te redirige a la pantalla correspondiente a tu rol. Si hay algún error (contraseña incorrecta, archivo equivocado), aparece un mensaje en rojo indicando el problema.

---

### 5.3 Portal de usuario

El portal de usuario es la pantalla principal para los roles Coordinador, Operativo y Voluntario. El Administrador también puede acceder desde su panel.

**Figura 5. Portal de usuario — Vista general**
*(Aquí debe colocarse una captura del portal de usuario (/portal) donde se vea la barra superior, las tarjetas de información del usuario (nombre, rol, estado, permisos) y la sección de Beneficiarios debajo.)*

En el portal encontrarás:

- **Tu información**: nombre, correo, rol, estado de la cuenta y permisos asignados.
- **Flujo criptográfico** (solo para Administrador y Coordinador): resumen del estado de tus certificados digitales.
- **Sección de beneficiarios**: formulario y tabla de beneficiarios según tus permisos.

**Figura 6. Sección de flujo criptográfico en el portal**
*(Aquí debe colocarse una captura de la sección "Flujo criptográfico" visible para usuarios Administrador o Coordinador en el portal, mostrando los 4 pasos: Otorgar identidad, Firmar certificado, Entrar, y Verificar, con sus respectivos estados.)*

---

### 5.4 Registrar un beneficiario

Todos los roles pueden registrar beneficiarios, aunque con distintos niveles de acceso.

**Paso a paso:**

1. En el portal de usuario (o en el dashboard para Administradores), localiza la sección **"Beneficiarios"**.
2. Haz clic en **"Registrar beneficiario"** para abrir el formulario.

**Figura 7. Formulario de registro de beneficiario**
*(Aquí debe colocarse una captura del formulario expandible de registro de beneficiario, donde se vean los campos: "Nombre completo", "País de origen", "Área" (lista desplegable con opciones: ADMINISTRACIÓN, LEGAL, PSICOSOCIAL, HUMANITARIO, COMUNICACIÓN), "Notas" (campo de texto opcional) y el botón "Registrar".)*

3. Completa los campos:
   - **Nombre completo** del beneficiario (requerido).
   - **País de origen** (requerido).
   - **Área** de atención: Administración, Legal, Psicosocial, Humanitario o Comunicación.
   - **Notas** adicionales (opcional).
4. Haz clic en **"Registrar"**.

**Resultado esperado:**

El beneficiario queda registrado y aparece en la tabla con estado **"nuevo"**. Un mensaje verde confirma el registro exitoso. Los Coordinadores y Administradores pueden cambiar el estado a "en revisión", "canalizado" o "activo".

---

### 5.5 Panel de administración

El panel de administración (dashboard) es el área exclusiva del rol Administrador.

**Figura 8. Panel de administración (dashboard) — Vista general**
*(Aquí debe colocarse una captura completa del dashboard, donde se vean la barra lateral izquierda con el menú de navegación, las tarjetas de estadísticas en la parte superior (número de usuarios, roles y eventos de auditoría), y al menos una o dos secciones colapsables debajo.)*

**Figura 9. Barra lateral del panel de administración**
*(Aquí debe colocarse una captura de la barra lateral izquierda del dashboard donde se vean claramente los elementos: logo de Casa Monarca, nombre del administrador, sección "NAVEGACIÓN" con los enlaces "Portal de usuario" y "Panel de administración", enlace "Notificaciones" con el badge rojo de notificaciones no leídas, sección "ACCESOS RÁPIDOS" con "Nuevo usuario" y "Certificado firmante", y al fondo el enlace "Salir / cambiar usuario".)*

Desde el panel de administración puedes:

- Ver estadísticas generales (total de usuarios, roles, eventos de auditoría).
- Gestionar usuarios (crear, activar, revocar, cambiar rol).
- Emitir certificados digitales.
- Ver y atender notificaciones del sistema.
- Revisar el registro de auditoría.
- Gestionar el administrador de respaldo (espejo).

---

### 5.6 Crear un usuario

**Quién puede hacerlo:** solo el Administrador.

**Paso a paso:**

1. En el panel de administración, localiza la sección **"Alta de usuario"** y haz clic en ella para expandirla.

**Figura 10. Sección "Alta de usuario" en el dashboard**
*(Aquí debe colocarse una captura de la sección "Alta de usuario" expandida en el dashboard. Se deben ver los campos del formulario: "Nombre completo", "Correo electrónico", "Rol" (selector desplegable), "Fecha de expiración" (campo de fecha opcional), "Contraseña inicial / Clave criptográfica" y el botón "Crear usuario".)*

2. Completa el formulario:
   - **Nombre completo** del nuevo usuario.
   - **Correo electrónico** institucional.
   - **Rol**: selecciona entre Administrador, Coordinador, Operativo o Voluntario.
   - **Fecha de expiración** (opcional): fecha a partir de la cual el acceso se desactivará automáticamente.
   - **Contraseña inicial** (para roles sin criptografía) o **Clave del material criptográfico** (para Admin/Coordinador, protege la llave privada generada).
3. Haz clic en **"Crear usuario"**.

**Resultado esperado:**

El usuario queda creado en estado **"pendiente"**. Aparece un aviso verde: *"Usuario creado en estado pending. Debes activarlo para que pueda entrar."* El usuario no podrá iniciar sesión hasta que sea activado por el administrador.

---

### 5.7 Activar una cuenta

**Quién puede hacerlo:** solo el Administrador.

**Paso a paso:**

1. En el panel de administración, localiza al usuario que deseas activar en la lista de usuarios.
2. Haz clic en **"Gestionar"** para expandir su fila.

**Figura 11. Fila expandida de gestión de usuario**
*(Aquí debe colocarse una captura de una fila de usuario expandida en el dashboard, mostrando los cuatro paneles internos: "Cuenta", "Vigencia", "Rol" y "Flujo criptográfico". El panel "Cuenta" debe ser el que esté más visible, con el texto del estado actual y el formulario de activación con el campo de contraseña.)*

3. En el panel **"Cuenta"**, si el usuario está en estado "pendiente" o "revocado", verás el formulario de activación.

**Figura 12. Panel "Cuenta" — Botón de activación**
*(Aquí debe colocarse un primer plano del panel "Cuenta" dentro de la fila expandida, donde se vean el campo de contraseña etiquetado "Nueva contraseña de acceso" (o "Clave del nuevo material criptográfico" para roles con certificados) y el botón "Activar" en color terracota.)*

4. Ingresa la **contraseña** o **clave criptográfica** para el usuario.
5. Haz clic en **"Activar"**.

**Resultado esperado:**

El estado del usuario cambia a **"active"** (activo) y aparece un aviso verde de confirmación. El usuario ya puede iniciar sesión con las credenciales asignadas.

---

### 5.8 Emitir certificados criptográficos

Este proceso aplica únicamente para usuarios con roles **Administrador** o **Coordinador**, que utilizan autenticación criptográfica.

**Quién puede hacerlo:** el Administrador.

**Paso a paso:**

1. En el panel de administración, expande la fila del usuario que necesita certificados.
2. Localiza el panel **"Flujo criptográfico"**.

**Figura 13. Panel "Flujo criptográfico" con pasos de emisión**
*(Aquí debe colocarse una captura del panel "Flujo criptográfico" dentro de la fila expandida de un usuario Coordinador. Se deben ver los cuatro pasos: "Otorgar identidad", "Firmar certificado", "Entrar" y "Verificar", con sus estados. Debajo del panel debe ser visible el campo de contraseña con la etiqueta "Contraseña de private_key.pem y del respaldo .p12" y el botón "Emitir artefactos".)*

3. Si el usuario aún no tiene certificados, verás el botón **"Emitir artefactos"** (o **"Reemitir artefactos"** si ya tenía credenciales previas).
4. Ingresa una contraseña en el campo **"Contraseña de private_key.pem y del respaldo .p12"** — esta contraseña protegerá la llave privada del usuario.
5. Haz clic en **"Emitir artefactos"**.

**Resultado esperado:**

El sistema genera los siguientes archivos para el usuario:
- `private_key.pem` — Llave privada cifrada con la contraseña indicada.
- `certificate.pem` — Certificado digital X.509 firmado.
- `public_key.pem` — Llave pública.
- Archivo `.p12` — Respaldo cifrado del certificado.

Los archivos quedan disponibles para descarga desde el panel. El administrador debe **descargarlos y entregarlos en persona** al usuario. Nunca deben enviarse por correo electrónico ni por mensajería.

---

### 5.9 Revocar un usuario

La revocación desactiva el acceso del usuario de manera inmediata.

**Quién puede hacerlo:** solo el Administrador.

**Paso a paso:**

1. Expande la fila del usuario que deseas revocar en el panel de administración.
2. En el panel **"Cuenta"**, haz clic en el botón **"Revocar de emergencia"** (color rojo).
3. La acción se ejecuta de inmediato, sin confirmación adicional.

**Resultado esperado:**

El estado del usuario cambia a **"revoked"** (revocado). Si el usuario tenía una sesión activa, perderá acceso al intentar cualquier acción. Los certificados del usuario quedan invalidados. Para reactivar la cuenta, será necesario emitir nuevos artefactos criptográficos.

> **Advertencia**: Esta acción no tiene deshacer inmediato. Úsala únicamente en situaciones que requieran suspensión urgente del acceso.

---

### 5.10 Ver y gestionar notificaciones

El sistema genera notificaciones automáticas para alertar al administrador sobre eventos importantes.

**Quién puede verlas:** solo el Administrador.

**Cómo acceder:**

- Desde la barra lateral, haz clic en el enlace **"Notificaciones"**. Si hay notificaciones sin leer, verás un badge rojo con el número de pendientes.
- En el área principal, expande la sección **"Notificaciones"**.

**Figura 14. Sección de notificaciones con badge**
*(Aquí debe colocarse una captura de la barra lateral del dashboard donde se vea el enlace "Notificaciones" con un badge rojo que muestre un número (por ejemplo, "2"). El badge debe estar claramente visible junto al texto del enlace.)*

**Figura 15. Detalle de una notificación individual**
*(Aquí debe colocarse una captura de la sección "Notificaciones" expandida en el dashboard, mostrando al menos una notificación. Se deben ver el icono del tipo de notificación, el título en negrita, el mensaje descriptivo, la etiqueta del tipo (por ejemplo, "Recuperación" o "Cuenta bloqueada"), la fecha de creación y el botón "Marcar atendida".)*

**Tipos de notificaciones:**

| Ícono | Tipo | Qué significa |
|---|---|---|
| 🔑 | **Recuperación** | Un usuario solicitó recuperar su acceso desde la página de login |
| ⚠️ | **Expiración** | El certificado de un usuario vence en los próximos 30 días |
| 🔒 | **Cuenta bloqueada** | Un usuario fue bloqueado por demasiados intentos de login fallidos |

**Para marcar una notificación como atendida:**

1. Localiza la notificación en la lista.
2. Haz clic en el botón **"Marcar atendida"**.
3. La notificación aparecerá con opacidad reducida para indicar que fue procesada.

---

### 5.11 Revisar el registro de auditoría

El registro de auditoría muestra un historial de todas las acciones realizadas en el sistema.

**Quién puede verlo:** solo el Administrador.

**Paso a paso:**

1. En el panel de administración, localiza y expande la sección **"Auditoría reciente"**.

**Figura 16. Registro de auditoría con IP y agente de usuario**
*(Aquí debe colocarse una captura de la sección "Auditoría reciente" expandida en el dashboard, mostrando la lista de eventos. Cada evento debe ser visible con su tipo (en negrita), el resultado (success/failure), el ID del usuario objetivo, la dirección IP y los primeros caracteres del agente de usuario (navegador).)*

2. Cada registro muestra:
   - **Tipo de evento** (por ejemplo: `login_password_verified`, `user_created`, `account_unlocked`).
   - **Resultado**: `success` o `failure`.
   - **Usuario objetivo**: ID del usuario afectado.
   - **Dirección IP**: desde dónde se realizó la acción.
   - **Agente de usuario**: navegador o cliente que generó la acción.

---

### 5.12 Solicitar recuperación de acceso

Si un usuario no puede entrar porque olvidó su contraseña o perdió sus archivos de certificado, puede enviar una solicitud de recuperación directamente desde la pantalla de login.

**Paso a paso:**

1. En la pantalla de inicio de sesión, desplázate hacia abajo y haz clic en **"¿Olvidaste tu contraseña o perdiste tus certificados?"**.

**Figura 17. Formulario de recuperación de acceso en login**
*(Aquí debe colocarse una captura de la sección expandida "¿Olvidaste tu contraseña o perdiste tus certificados?" en la página de login. Se debe ver el texto explicativo, el campo "Correo registrado", el campo "Nombre completo" y el botón "Solicitar recuperación" con estilo de botón claro/ghost.)*

2. Ingresa tu **correo electrónico** registrado en el sistema.
3. Ingresa tu **nombre completo**.
4. Haz clic en **"Solicitar recuperación"**.

**Resultado esperado:**

El sistema muestra un mensaje neutral: *"Solicitud enviada. Un administrador revisará tu caso y te contactará para verificar tu identidad."*

Simultáneamente, el Administrador recibe una notificación de tipo "Recuperación" en su panel. El administrador verificará la identidad del solicitante **en persona** y, de ser correcta, le entregará nuevas credenciales directamente.

> **Importante**: Ningún material criptográfico ni contraseña se transmite por la red durante este proceso. La entrega siempre se realiza en persona.

---

### 5.13 Desbloquear una cuenta bloqueada

Si un usuario falla el inicio de sesión 10 veces consecutivas, su cuenta se bloquea automáticamente.

**Quién puede desbloquearlo:** solo el Administrador.

**Paso a paso:**

1. En el panel de administración, expande la fila del usuario bloqueado.
2. En el panel **"Cuenta"**, verás el mensaje *"Cuenta bloqueada por exceso de intentos de login fallidos"*.

**Figura 18. Botón "Desbloquear cuenta" en panel de usuario**
*(Aquí debe colocarse una captura del panel "Cuenta" de un usuario bloqueado, donde se vea claramente el texto de estado indicando que la cuenta está bloqueada y el botón "Desbloquear cuenta" en color ámbar/naranja.)*

3. Haz clic en el botón **"Desbloquear cuenta"** (color ámbar).

**Resultado esperado:**

El contador de intentos se reinicia y la cuenta queda desbloqueada. El sistema muestra el aviso *"La cuenta fue desbloqueada correctamente."* El usuario puede intentar iniciar sesión nuevamente.

---

## 6. SOLUCIÓN DE PROBLEMAS

**Tabla 5. Errores comunes y soluciones**

| Error o situación | Posible causa | Qué hacer |
|---|---|---|
| "Contraseña incorrecta" al iniciar sesión | Contraseña equivocada o usuario incorrecto | Verificar correo y contraseña. Si olvidaste la contraseña, usa el formulario de recuperación en el login |
| "Cuenta bloqueada" | Se ingresó la contraseña incorrecta 10 veces | Contactar al administrador para desbloquear la cuenta |
| "La cuenta aún no ha sido activada" | El administrador no ha aprobado la cuenta | Esperar a que el administrador active la cuenta |
| "La cuenta ha sido revocada" | Un administrador revocó el acceso | Contactar al administrador |
| "Debes adjuntar private_key.pem y certificate.pem juntos" | Se adjuntó solo uno de los dos archivos | Seleccionar ambos archivos al mismo tiempo |
| El archivo `private_key.pem` no abre o muestra error | Contraseña incorrecta para la llave privada | Asegurarse de usar la misma contraseña definida al emitir los artefactos |
| La página no carga | El servidor no está corriendo | Verificar que uvicorn esté activo en el terminal con `uvicorn app.main:app --reload` |
| Error 403 al acceder al dashboard | El usuario no tiene rol de Administrador activo | Solo los Administradores con estado "active" pueden acceder al dashboard |
| No aparecen certificados para descargar | Los artefactos no han sido emitidos aún | El administrador debe hacer clic en "Emitir artefactos" en el panel del usuario |

### Qué hacer si algo falla

1. **Recarga la página** con `F5` o `Ctrl+R`.
2. **Cierra sesión y vuelve a entrar** desde `/logout`.
3. **Verifica que el servidor esté activo** revisando el terminal donde corre uvicorn.
4. **Revisa la sección de Auditoría** en el dashboard para identificar qué evento generó el error.
5. Si el problema persiste, **contacta al administrador** del sistema.

### Contacto de soporte

Para reportar problemas técnicos o solicitar ayuda, comunicarse con el administrador designado de Casa Monarca o con el equipo de desarrollo a través de los canales internos de la organización.

---

## 7. PREGUNTAS FRECUENTES

**¿Puedo cambiar mi contraseña desde el sistema?**
No directamente. Si necesitas cambiar tu contraseña, debes solicitar al Administrador que te regenere las credenciales desde el panel de gestión de usuarios. Para roles criptográficos, el Administrador puede re-emitir los artefactos con una nueva contraseña.

**¿Qué son los archivos `private_key.pem` y `certificate.pem`?**
Son tus credenciales de identidad digital. El `private_key.pem` es tu llave privada (equivalente a un PIN secreto único) y el `certificate.pem` es tu identificación digital firmada por el Administrador. Juntos demuestran tu identidad de forma criptográficamente segura sin necesitar una contraseña de texto.

**¿Puedo iniciar sesión desde cualquier computadora?**
Sí, siempre que tengas tus archivos `private_key.pem` y `certificate.pem` disponibles. Guárdalos en un lugar seguro (USB cifrado, gestor de contraseñas con archivos, etc.).

**¿Qué pasa si pierdo mis archivos `private_key.pem` o `certificate.pem`?**
Debes solicitar recuperación usando el formulario de la pantalla de login. El Administrador verificará tu identidad en persona y generará nuevos artefactos para ti.

**¿Qué significa que mi cuenta está en estado "pending"?**
Significa que tu cuenta fue creada pero todavía no ha sido activada por el Administrador. Debes esperar a que el Administrador complete el proceso de activación.

**¿Cuánto tiempo dura mi sesión activa?**
La sesión se mantiene activa durante **8 horas**. Después de ese tiempo, el sistema te pedirá que vuelvas a iniciar sesión.

**¿Puedo ver la información de otros usuarios?**
No. Cada usuario solo puede ver su propia información en el portal. Solo el Administrador puede ver y gestionar la información de todos los usuarios.

**¿Qué es el "administrador espejo" o "respaldo"?**
Es una cuenta de Administrador de emergencia cuya función es restaurar el acceso al sistema en caso de que el Administrador principal no pueda ingresar. Su activación revoca automáticamente al Administrador principal.

**¿Cada cuánto vencen los certificados?**
El sistema alerta al Administrador cuando un certificado está a **30 días o menos** de vencer, mediante una notificación en el panel. El tiempo de vigencia es definido por el Administrador al emitir el certificado.

**¿Puedo usar el sistema desde el celular?**
Sí, la interfaz es responsiva y funciona en navegadores móviles. Sin embargo, adjuntar archivos `.pem` puede ser menos conveniente en dispositivos móviles, por lo que se recomienda usar una computadora para el inicio de sesión criptográfico.

---

## 8. REFERENCIAS

- FastAPI — Documentación oficial: https://fastapi.tiangolo.com
- Cryptography (librería Python): https://cryptography.io/en/latest/
- Certificados X.509 — RFC 5280: https://www.rfc-editor.org/rfc/rfc5280
- PKCS#12 — RFC 7292: https://www.rfc-editor.org/rfc/rfc7292
- OWASP — Guía de autenticación segura: https://owasp.org/www-project-authentication-cheat-sheet/

---

*Documento generado para uso interno de Casa Monarca — Ayuda Humanitaria al Migrante, A.B.P.*
*Instituto Tecnológico y de Estudios Superiores de Monterrey — Escuela de Ingeniería y Ciencias*
*Versión 1.0 — Monterrey, Nuevo León — 30 de abril de 2023*
