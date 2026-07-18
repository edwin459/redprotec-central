# RedProtec — Relay central Multi-sede (MVP)

Servicio mínimo al que cada agente (sede) manda un **resumen** y desde el que la
app lee todas las sedes. Sin base de datos (estado en memoria); las sedes se
re-registran solas en cada latido. Pensado para **free tier**.

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

## Migrar a pago (después)
Misma API. Solo se cambia el almacén (memoria → Postgres) y el host. El agente y
la app **no cambian** — apuntas la app/agente a la nueva URL y listo.
