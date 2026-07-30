# RedProtec — Relay central Multi-sede (MVP)

Servicio al que cada agente (sede) manda un **resumen** y desde el que la app lee
todas las sedes.

**Almacén intercambiable** (`store.py`):
- **Sin `DATABASE_URL`** → estado en memoria (free tier); las sedes se
  re-registran solas en cada latido. Bueno para probar.
- **Con `DATABASE_URL`** → **Postgres (Supabase)**: el estado PERSISTE entre
  reinicios y deja de vivir en RAM → escala a miles de sedes/usuarios. Es el modo
  de producción. **Los endpoints y las respuestas son idénticos** en ambos modos.

Para el paso a producción (Supabase + host always-on) ver **[DEPLOY.md](DEPLOY.md)**.

## Qué expone
- `GET /health` — estado.
- `POST /v1/heartbeat` — el agente reporta su sede (header `Authorization: Bearer <org_token>`).
- `GET /v1/sites` — la app lee todas las sedes de la organización (mismo Bearer).

Aislamiento: cada `org_token` solo ve SUS sedes. Trátalo como una contraseña.

## Probar en local
```bash
pip install -r requirements.txt
uvicorn main:app --port 8080
# en otra terminal:
curl -s localhost:8080/health
```

## Desplegar GRATIS en Fly.io
Requisito: una cuenta en https://fly.io (el free allowance basta para probar).

1. Instala flyctl: https://fly.io/docs/flyctl/install/
   - Windows (PowerShell): `iwr https://fly.io/install.ps1 -useb | iex`
2. Inicia sesión: `fly auth login`
3. Desde esta carpeta `central/`:
   ```bash
   fly launch --no-deploy   # detecta el Dockerfile; elige un nombre único
   fly deploy
   ```
4. Al terminar te da una URL tipo `https://<tu-app>.fly.dev`. Esa es la **URL del panel**.
5. Verifica: `curl https://<tu-app>.fly.dev/health`

## Usarlo
- **Elige un token de organización** (un secreto largo, p. ej. genera uno con
  `openssl rand -hex 24`). Es el que agrupa tus sedes. NO lo compartas.
- En la app: **Seguridad → Sedes → Conectar esta sede**. Pega la URL del panel,
  el token, un nombre de sede y activa "Reportar esta sede".
- Repite en cada sede (cada PC con agente) con el **mismo token** y un **nombre
  distinto**. En <1 min aparecen todas en el panel.

## Privacidad
Solo viaja el **resumen** (nº de equipos, en línea, alertas, críticos). Nunca
IPs, MACs ni nombres de equipos individuales.

## Producción: Postgres persistente (Supabase) + host always-on
Ya implementado. Se define la variable de entorno `DATABASE_URL` con la cadena de
conexión de Postgres y el relay usa Postgres automáticamente (crea sus tablas
solo). Misma API: el agente y la app **no cambian** — apuntas a la nueva URL.

Guía paso a paso (crear el proyecto Supabase, obtener `DATABASE_URL`, desplegar en
Railway, verificar): **[DEPLOY.md](DEPLOY.md)**.

> Las credenciales van SIEMPRE en variables de entorno del host, **nunca** en el
> repositorio ni en texto plano.
