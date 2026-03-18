# 🤖 TstSiteApi

> **REST API backend** para la plataforma TstSite — construida con Node.js y Express, desplegada en la nube con CI/CD automático y diseñada con un modelo de seguridad en capas.

---

## 📌 Descripción

**TstSiteApi** es el backend de la plataforma TstSite, una aplicación multiplataforma (Web, Android, iOS, Desktop) basada en **Kotlin Multiplatform + Compose**. La API expone endpoints RESTful para autenticación, gestión de usuarios y catálogo, actuando como único punto de entrada de datos para todos los clientes.

---

## 🛠️ Stack Tecnológico

| Capa | Tecnología |
|------|-----------|
| **Runtime** | Node.js ≥ 18 |
| **Framework** | Express 5 |
| **Base de datos** | PostgreSQL (driver `pg`) |
| **Autenticación** | JWT (`jsonwebtoken`) |
| **Cifrado de payload** | AES-256-GCM + PBKDF2 / Fernet (AES-128-CBC + HMAC-SHA256) |
| **Seguridad HTTP** | Helmet, CORS estricto, Rate Limiting (`express-rate-limit`) |
| **Variables de entorno** | dotenv + cifrado Fernet en `.env` |
| **Logging** | Morgan |
| **Desarrollo** | Nodemon |

---

## 🏗️ Infraestructura

```
┌──────────────────────────────────────────────────────────┐
│                   Alwaysdata Cloud                       │
│                                                          │
│   ┌─────────────────┐      ┌──────────────────────────┐ │
│   │  Apache (Web)   │      │  Node.js (API)           │ │
│   │  TstSiteApp     │ ───► │  TstSiteApi              │ │
│   │  (WasmJS)       │      │  https://.../api         │ │
│   └─────────────────┘      └────────────┬─────────────┘ │
│                                          │               │
│                             ┌────────────▼─────────────┐ │
│                             │  PostgreSQL               │ │
│                             │  postgresql-tstsite.      │ │
│                             │  alwaysdata.net           │ │
│                             └──────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
```

- **Hosting:** Alwaysdata — plataforma cloud con soporte Node.js nativo y PostgreSQL gestionado.
- **Dominio API:** `https://tstsite.alwaysdata.net/api`
- **Acceso SSH/FTP** para despliegues y mantenimiento directo.
- **Entornos:** `DEV` (localhost) y `TST` (cloud), con configuración de host permutable por variable de entorno.

---

## 🔄 CI/CD — GitHub Actions

El pipeline de despliegue es **completamente automático** y orquesta tres repositorios a la vez:

```
TstSiteDB  ──┐
TstSiteApi  ─┼──► GitHub Actions ──► Alwaysdata (SSH + SCP + REST API)
TstSiteApp  ─┘
```

**Fases del pipeline:**

1. Checkout de los tres repositorios (`TstSiteDB`, `TstSiteApi`, `TstSiteApp`)
2. Compilación WASMJS con Gradle + JDK 21 (frontend Kotlin Multiplatform)
3. Reinicio preventivo de los sitios en Alwaysdata vía API REST
4. Migración de base de datos — ejecución de scripts SQL sobre PostgreSQL
5. VACUUM FULL + ANALYZE — optimización automática de todas las tablas
6. Optimización avanzada mediante procedimiento almacenado `pr_optimizador`
7. Despliegue de la API vía SCP + SSH (`rsync` con lista de exclusión)
8. `npm install --omit=dev` en servidor para entorno de producción limpio
9. Despliegue del frontend (WasmJS) en Apache
10. Limpieza de caché — Alwaysdata CDN + Node + NPM + GitHub Actions cache
11. Reinicio final coordinado de API y Web

> ⏰ El workflow se ejecuta **diariamente a las 06:00 (Madrid)** de forma programada, con opción de disparo manual (`workflow_dispatch`).

---

## 🔐 Seguridad

La API implementa un **modelo de defensa en profundidad** con múltiples capas independientes:

### 1. Cabeceras HTTP seguras — Helmet
- `Content-Security-Policy` (CSP) restrictivo
- `X-Frame-Options: DENY` — previene clickjacking
- `Strict-Transport-Security` (HSTS) — HTTPS forzado durante 1 año con `preload`
- `X-Content-Type-Options: noSniff`
- `X-XSS-Protection`

### 2. CORS estricto
Solo se admiten peticiones de orígenes explícitamente permitidos (lista blanca). Cualquier origen no autorizado recibe un error en el handshake CORS.

### 3. Rate Limiting
- **Global:** 100 peticiones / 15 min por IP
- **Login:** 10 intentos / 15 min por IP — protección contra fuerza bruta

### 4. Autenticación dual (JWT + API Key)

```
Petición ──► ¿Authorization: Bearer <token>?
                 └─ Sí ──► Validar JWT (algoritmo, issuer, audience, expiración, revocación)
                 └─ No ──► ¿x-api-key header?
                               └─ Sí ──► Comparación timing-safe (crypto.timingSafeEqual)
                               └─ No ──► 401 Unauthorized
```

Los tokens JWT incluyen: `sub`, `username`, `role`, `iat`, `exp`, `jti` (UUID único), `iss`, `aud`.
La **revocación en memoria** almacena los JTI de tokens invalidados (logout) en un `Set` y los verifica en cada petición.

### 5. Cifrado de payload end-to-end

Todos los cuerpos de petición y respuesta pueden viajar **cifrados**, independientemente de HTTPS:

- **Algoritmo:** AES-256-GCM (autenticado — detecta manipulaciones)
- **Derivación de clave:** HMAC-SHA256 sobre un `salt` aleatorio de 32 bytes
- **IV:** 12 bytes aleatorios criptográficamente seguros por cada mensaje
- **Autenticación:** `authTag` de 16 bytes incluido en el ciphertext
- **Formato:** `Base64( salt[32] + iv[12] + ciphertext + authTag[16] )`
- Compatible con las implementaciones cliente en **Android, iOS, WasmJS y JVM** (Kotlin Multiplatform)

### 6. Secretos cifrados en `.env`

Todas las variables sensibles (SECRET_KEY, API_KEY, credenciales de BD, JWT issuer/audience) están cifradas con **Fernet** (AES-128-CBC + HMAC-SHA256) en los archivos `.env`. El servidor las descifra en memoria al arrancar.

### 7. Comparación timing-safe
La validación de la API Key usa `crypto.timingSafeEqual` para prevenir **timing attacks**.

---

## 📁 Estructura del proyecto

```
TstSiteApi/
├── bin/
│   └── www                      # Entry point del servidor HTTP
├── cfg/
│   ├── config.js                # Configuración centralizada (carga y descifra .env)
│   └── db.js                    # Pool de conexiones PostgreSQL
├── middlewares/
│   ├── clientAuthMiddleware.js  # Autenticación dual JWT / API Key
│   └── tokenRequired.js         # Verificación JWT + revocación
├── routes/
│   ├── auth.js                  # /auth/login, /auth/validate, /auth/profile, /auth/logout
│   ├── users.js                 # /users — CRUD y búsqueda de usuarios
│   └── catalog.js               # /catalog — datos del catálogo
├── utils/
│   └── cryptoPayload.js         # Cifrado/descifrado AES-256-GCM de payloads
├── app.js                       # Composición de middlewares y rutas
└── package.json
```

---

## 🗺️ Endpoints principales

| Método | Ruta | Auth | Descripción |
|--------|------|------|-------------|
| `POST` | `/auth/login` | Público | Inicio de sesión — devuelve JWT |
| `POST` | `/auth/validate` | JWT | Validación de token activo |
| `GET` | `/auth/profile` | JWT | Perfil del usuario autenticado |
| `POST` | `/auth/logout` | JWT | Revocación del token |
| `GET` | `/users` | JWT/Key | Listado de usuarios |
| `POST` | `/users/search` | JWT/Key | Búsqueda parametrizada |
| `POST` | `/catalog` | JWT/Key | Obtención del catálogo |

---

## ⚙️ Variables de entorno

```env
# Node.js / Express
SECRET_KEY=ENC(...)          # Clave JWT y cifrado de payload (Fernet)
API_KEY=ENC(...)             # API Key de uso interno/admin
ALGORITHM=ENC(...)           # Algoritmo JWT (HS256)
JWT_MINUTES=30               # Expiración del token en minutos
JWT_ISSUER=ENC(...)
JWT_AUDIENCE=ENC(...)

# PostgreSQL
DB_HOST=...
DB_PORT=5432
DB_NAME=ENC(...)
DB_USER=ENC(...)
DB_PASSWORD=ENC(...)

# Cifrado de payload
ENCRYPTION_ENABLED=true
ALLOW_UNENCRYPTED=false      # false en producción
```

---

## 🚀 Arranque local

```bash
# Instalar dependencias
npm install

# Desarrollo con hot-reload
npm run dev

# Producción
npm start
```

La API estará disponible en `http://localhost:3000`.

---

## 🔗 Repositorios relacionados

| Repositorio | Descripción |
|-------------|-------------|
| `TstSiteApp` | Frontend Kotlin Multiplatform (Compose WasmJS / Android / iOS) |
| `TstSiteDB` | Scripts SQL y migraciones PostgreSQL |
| `TstSiteApi` | **Este repositorio** — Backend REST API |

---

## 📄 Licencia

MIT
