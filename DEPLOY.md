# Deploy a producción — Relay central con Supabase (Postgres) + Railway

Esta guía lleva el relay de "estado en memoria" a **persistente y always-on**,
sin cambiar la app ni el agente. El resultado: control remoto multi-sede que
sobrevive reinicios y escala a miles de sedes/usuarios.

Arquitectura:

```
  Agentes (sedes) ──HTTPS──▶  Relay FastAPI (Railway, always-on)  ──▶  Supabase Postgres
  App admin       ──HTTPS──▶        (este repo: central/)                (persistencia)
```

- **Supabase** = solo la base de datos (Postgres administrado).
- **Railway** = corre el proceso del relay 24/7 (Supabase NO ejecuta el relay).
- El relay usa Postgres **solo si existe la variable `DATABASE_URL`**; si no,
  sigue en memoria (útil para probar en local).

> 🔐 **Regla de seguridad (tuya):** las credenciales van en variables de entorno
> del host. **Nunca** en el repositorio, capturas ni chat. Este documento no
> contiene ningún secreto — tú los pegas en los paneles de Supabase/Railway.

---

## Parte 1 — Crear la base de datos en Supabase (lo haces tú)

1. Entra a https://supabase.com → **New project**.
   - Elige nombre, una **contraseña de base de datos fuerte** (guárdala en tu
     gestor de contraseñas) y la región más cercana a tus sedes.
2. Espera a que el proyecto termine de aprovisionar (1-2 min).
3. Obtén la **cadena de conexión** (`DATABASE_URL`):
   - **Project Settings → Database → Connection string → URI**.
   - Copia la de **"Connection pooling" (modo Transaction, puerto `6543`)** — es
     la recomendada para servicios web. Sustituye `[YOUR-PASSWORD]` por la
     contraseña del paso 1.
   - Queda con esta forma (ejemplo, NO son credenciales reales):
     ```
     postgresql://postgres.abcdefgh:TU_PASSWORD@aws-0-us-east-1.pooler.supabase.com:6543/postgres
     ```
4. (Opcional) Crear las tablas a mano: **SQL Editor → New query**, pega el
   contenido de [`schema.sql`](schema.sql) y ejecútalo. **No es obligatorio**: el
   relay crea las tablas solo al arrancar. Hazlo solo si prefieres revisar el DDL.

> El relay desactiva los *prepared statements* para ser compatible con el pooler
> de transacción de Supabase, así que la cadena del puerto `6543` funciona tal
> cual. Si prefieres conexión directa/sesión (puerto `5432`) también sirve.

---

## Parte 2 — Desplegar el relay en Railway (lo haces tú)

Railway corre el proceso siempre encendido (a diferencia de Render free, que
duerme).

1. Entra a https://railway.app → inicia sesión con GitHub.
2. **New Project → Deploy from GitHub repo** y elige el repo del relay
   (`edwin459/redprotec-central`). Railway detecta el `Dockerfile` de `central/`.
   - Si el relay vive en una subcarpeta, define **Root Directory = `central`** en
     *Settings → Service*.
3. **Variables** (Settings → Variables) — aquí van los secretos, no en el repo:
   - `DATABASE_URL` = la cadena de conexión de la Parte 1, paso 3.
   - `ONLINE_WINDOW_SECONDS` = `150` (opcional, es el valor por defecto).
4. Railway inyecta `PORT` automáticamente; el `Dockerfile` ya lo respeta.
5. **Deploy**. Cuando termine, en *Settings → Networking* genera un
   **dominio público** (`https://<algo>.up.railway.app`). Esa es la **URL del
   panel** que usarás en la app/agente.

Verifica que arrancó y ya usa Postgres:
```bash
curl https://<tu-relay>.up.railway.app/health
# {"status":"ok","version":"0.4.0","orgs":0,"sites":0}
```
`orgs`/`sites` en 0 es correcto en una base nueva. En cuanto un agente reporte,
suben — y ahora **persisten aunque reinicies el servicio** (esa es la prueba de
que Postgres está activo).

---

## Parte 3 — Apuntar agentes y app a la nueva URL

No cambia nada de código; solo la URL:

- **Agente / cada sede:** en la app → **Seguridad → Sedes → Conectar esta sede**.
  Pega la URL de Railway, el **token de organización** (tu secreto largo; genera
  uno con `openssl rand -hex 24`), un nombre de sede y activa *Reportar esta
  sede*. Repite en cada sede con el **mismo token** y **nombre distinto**.
- **App admin:** misma URL + mismo token de organización (rol dueño).

---

## Verificar la persistencia (la razón de todo esto)

1. Conecta 1-2 sedes; confírmalas en el panel.
2. En Railway, **reinicia** el servicio (Deployments → Restart).
3. Vuelve a abrir el panel: las sedes y su config **siguen ahí** sin esperar el
   próximo latido. Antes (en memoria) desaparecían hasta el siguiente heartbeat.

---

## Probar la paridad Postgres localmente (opcional, para el dev)

Los tests de `test_store.py` corren el MISMO set de casos contra memoria y, si
defines una base **desechable**, contra Postgres:

```bash
cd central
pip install -r requirements.txt
# usa una base de PRUEBAS (los tests hacen TRUNCATE de las tablas):
export RP_TEST_DATABASE_URL="postgresql://.../postgres_test"   # PowerShell: $env:RP_TEST_DATABASE_URL="..."
python -m unittest test_store -v
```
Sin `RP_TEST_DATABASE_URL`, los 13 casos de Postgres se saltan (y los 13 de
memoria corren igual).

---

## Notas

- **Costos/cuentas** son tuyos (Supabase + Railway). Ambos tienen plan de entrada
  bajo/gratis suficiente para arrancar; escalas cuando crezcas.
- **Migrar de Render/Fly a Railway** es solo mover la URL: el estado ahora vive en
  Supabase, no en el host.
- **Siguiente fase (opcional, cuando lo autorices):** WebSocket agente↔relay para
  comandos en tiempo real (hoy el agente sondea cada 60 s). No requiere cambiar el
  almacén — se monta encima de esta base.
