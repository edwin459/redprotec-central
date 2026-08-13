"""RedProtec — Relay central de MULTI-SEDE.

Cada agente (sede) manda un "latido" con un RESUMEN y, si la organización activó
el modo, también un INVENTARIO (equipos con nombre/fabricante/IP/MAC/estado). La
app lee todas las sedes, entra al detalle de una y puede ENVIAR COMANDOS
(bloquear/confiar/desbloquear) que el agente recoge en su siguiente latido y
ejecuta localmente — así se administra a distancia aunque el agente esté detrás
de NAT.

Almacén intercambiable (ver store.py): si la variable de entorno DATABASE_URL
está definida, el estado se guarda en Postgres (Supabase) y sobrevive reinicios
— escala a miles de sedes/usuarios. Si NO, se usa el almacén EN MEMORIA de
siempre (fallback gratis: las sedes se re-registran solas en el próximo latido).
Multi-tenant por `org_token` (Authorization: Bearer). Cambiar de backend NO
cambia ninguna respuesta: los endpoints hablan solo con la interfaz `Store`.
"""

from __future__ import annotations

import asyncio
import http.client
import json
import logging
import os
import secrets
import socket
import threading
import time
import urllib.request
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from auth import verify_supabase_jwt
from ratelimit import FailureLockout, SlidingWindow, client_ip, int_env
from store import create_store

logger = logging.getLogger("redprotec.central")

# ── Watchdog de sedes: el relay es el ÚNICO que ve TODAS las sedes 24/7 y tiene
# internet propio. Cuando una sede deja de latir (se le cayó el internet o se
# apagó el agente), NADIE más puede avisarlo a tiempo — el push del agente no
# saldría porque su propia conexión está caída. El relay sí. Detecta la
# transición en-línea→sin-conexión y avisa al tema de la organización.
# 150s (2.5 min) equilibra rapidez y anti-falsas-alarmas: el agente late cada 60s,
# así que 150s tolera perder UN latido (120s) + margen antes de declarar caída. El
# vigía revisa cada 30s → detección típica ~2.5-3 min (antes ~5-6). Ajustable por
# entorno sin redeploy.
OFFLINE_ALERT_SECONDS = int(os.environ.get("OFFLINE_ALERT_SECONDS", "150"))
WATCHDOG_INTERVAL_SECONDS = int(os.environ.get("WATCHDOG_INTERVAL_SECONDS", "30"))
# On-call / Escalación: si nadie CONFIRMA (ack) un incidente de caída, el relay
# reenvía recordatorios cada vez más urgentes hasta MAX_ESCALATIONS. Así una
# caída no se "pierde" porque el primer aviso pasó desapercibido — lo que hace
# que un equipo de TI (o una familia) dependa del sistema.
ESCALATION_INTERVAL_SECONDS = int(os.environ.get("ESCALATION_INTERVAL_SECONDS", "300"))
MAX_ESCALATIONS = int(os.environ.get("MAX_ESCALATIONS", "3"))

# Observabilidad del watchdog (sin secretos): permite verificar en /stats que el
# bucle realmente corre en producción y por qué (o si) no está emitiendo. Un
# watchdog que "no avisa" es indistinguible de uno que "nunca corrió" sin esto.
_WDIAG: dict = {
    "started": False,       # el bucle arrancó (lifespan corrió)
    "ticks": 0,             # cuántos ciclos completó
    "last_tick_at": None,   # datetime del último tick OK
    "last_error": None,     # "Tipo: mensaje" del último fallo del tick
    "last_sites_seen": 0,   # sedes evaluadas en el último tick
    "last_max_age": None,   # mayor seconds_since_update visto (vs umbral)
    "last_emitted": 0,      # transiciones emitidas en el último tick
    # Decisión por sede RECIENTE (age<1h) del último tick: edad/estado previo/
    # evento. Sin nombres de sede ni org → no filtra datos. Solo para diagnóstico.
    "last_recent": [],
    "last_push": [],        # resultado de cada _push_ntfy del último tick con emisión
}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    _WDIAG["started"] = True
    task = asyncio.create_task(_watchdog_loop())
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


app = FastAPI(title="RedProtec Central Relay", version="0.9.18", lifespan=lifespan)

# ── P0.3: Rate limiting + bloqueo por fuerza bruta (en memoria, por IP) ──────
# Límite GLOBAL generoso (solo frena inundaciones) y BLOQUEO estricto por fallos
# de auth (401/403) para frenar fuerza bruta del ADMIN_TOKEN o de tokens.
_RL_GLOBAL = SlidingWindow(
    int_env("RL_GLOBAL_MAX", 600), int_env("RL_GLOBAL_WINDOW", 60))
_RL_LOCKOUT = FailureLockout(
    int_env("RL_FAIL_MAX", 15), int_env("RL_FAIL_WINDOW", 300),
    int_env("RL_LOCK_SECONDS", 600))
# Rutas exentas del límite (chequeos de salud del hosting).
_RL_EXEMPT = {"/health", "/"}


@app.middleware("http")
async def _rate_limit(request: Request, call_next):
    """Aplica límite global y bloqueo por fallos de auth ANTES de cada endpoint.
    Un 401/403 cuenta como fallo; un 2xx/3xx limpia el historial de esa IP."""
    if request.url.path in _RL_EXEMPT:
        return await call_next(request)
    ip = client_ip(
        request.headers, request.client.host if request.client else "")
    if _RL_LOCKOUT.is_locked(ip):
        return JSONResponse(
            status_code=429,
            content={"detail": "Demasiados intentos fallidos. Espera unos "
                               "minutos e inténtalo de nuevo."},
            headers={"Retry-After": str(_RL_LOCKOUT.lock)})
    if not _RL_GLOBAL.hit(ip):
        return JSONResponse(
            status_code=429,
            content={"detail": "Demasiadas peticiones. Baja el ritmo."},
            headers={"Retry-After": "30"})
    response = await call_next(request)
    if response.status_code in (401, 403):
        _RL_LOCKOUT.record_failure(ip)
    elif response.status_code < 400:
        _RL_LOCKOUT.record_success(ip)
    return response


ONLINE_WINDOW_SECONDS = int(os.environ.get("ONLINE_WINDOW_SECONDS", "150"))
# Comandos que el agente no recoge en este tiempo se descartan (evita que una
# orden vieja se ejecute cuando la sede vuelva días después).
COMMAND_TTL_SECONDS = int(os.environ.get("COMMAND_TTL_SECONDS", "600"))
# Auth-3 (freemium): días de prueba Pro al crear la cuenta. Un solo valor,
# cambiable por entorno (ej. TRIAL_DAYS=3) sin tocar código.
TRIAL_DAYS = int(os.environ.get("TRIAL_DAYS", "5"))
# Token de super-admin (tú, el dueño del negocio) para marcar cuentas Pro/Free a
# mano mientras no hay cobro automático. Vacío = el endpoint de admin queda cerrado.
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "").strip()
# DUEÑO(S) del proyecto: sus cuentas son Pro PERMANENTE (nunca pagan, control
# total), para que tú y tu equipo administren todo sin fricción. Lista de IDs de
# organización (el `sub` de Supabase = el campo `org` que muestra /v1/entitlement),
# separados por coma. Vacío = nadie es dueño (comportamiento normal). Se configura
# por entorno en el host; no es un secreto (son identificadores, no credenciales).
OWNER_ORGS = {x.strip() for x in os.environ.get("OWNER_ORG_IDS", "").split(",") if x.strip()}

# Prefijo de los tokens de AGENTE (los emite el relay al vincular una sede a una
# cuenta). Un token con este prefijo SIEMPRE debe resolver a una org; si no
# resuelve, está revocado o es desconocido y se RECHAZA (no se convierte en una
# org fantasma). Ver `principal()`.
AGENT_TOKEN_PREFIX = "rp_agent_"

_LOCK = threading.Lock()
# org_token -> site_id -> record{ site_name, summary, devices, updated_at }
_STORE: dict[str, dict[str, dict]] = {}
# org_token -> site_id -> list[command]
_COMMANDS: dict[str, dict[str, list[dict]]] = {}
# org_token -> { alert_topic }  (config de la organización)
_ORG_CONFIG: dict[str, dict] = {}
# org_token -> user_token -> { name, role, sites: list[str] | ["*"] }
# RBAC en la NUBE: el dueño (org_token = raíz) reparte accesos por-persona con
# rol + alcance de sedes. El relay es EN MEMORIA: la app admin re-sincroniza esta
# lista al abrir (PUT /v1/access), así se restaura si el host reinicia. Si se
# pierde, un token de usuario deja de resolver → falla CERRADO (seguro).
_ACCESS: dict[str, dict[str, dict]] = {}
# org_token -> site_id -> { state: "online"|"offline", since: datetime }
# Estado del watchdog de conexión por sede (en memoria). Tras un reinicio del
# relay se re-siembra solo en el primer tick (sin avisar), evitando spam. Usa su
# PROPIO lock: el `_LOCK` del store no es reentrante y el store lo toma solo,
# así que mezclarlos deadlockearía.
_SITE_WATCH: dict[str, dict[str, dict]] = {}
_WATCH_LOCK = threading.Lock()

# Almacén activo. Con DATABASE_URL → Postgres (Supabase, persistente). Sin ella →
# MemoryStore sobre LOS MISMOS dicts de arriba (fallback gratis + tests). Los
# endpoints usan `store.*`; los dicts quedan como respaldo en memoria y para que
# los tests que los tocan directamente sigan funcionando igual.
store = create_store(_STORE, _COMMANDS, _ORG_CONFIG, _ACCESS, _LOCK)


# ─────────────────────── Auth-3: entitlement / plan ───────────────────────
def _ensure_entitlement(org: str, now: datetime) -> dict:
    """Devuelve el registro de plan de la org; si no existe (cuenta nueva), le
    inicia una PRUEBA Pro de TRIAL_DAYS días. Fuente de verdad única del plan."""
    ent = store.get_entitlement(org)
    if ent is None:
        trial_end = now + timedelta(days=TRIAL_DAYS)
        store.set_entitlement(org, "trial", trial_end)
        return {"plan": "trial", "trial_ends_at": trial_end}
    return ent


def _compute_entitlement(org: str, now: datetime) -> dict:
    """Calcula el plan EFECTIVO y las capacidades que leen agente, móvil y relay
    (un mismo contrato). `trial` vigente = Pro; `trial` vencido = free."""
    is_owner = org in OWNER_ORGS
    if is_owner:
        # Dueño del proyecto: Pro permanente, sin prueba ni vencimiento. No se le
        # crea registro de entitlement (no depende del almacén).
        plan = effective = "pro"
        can_control = True
        trial_ends_at = None
        trial_days_left = 0
    else:
        ent = _ensure_entitlement(org, now)
        plan = ent.get("plan", "free")
        trial_ends_at = ent.get("trial_ends_at")
        if trial_ends_at is not None and trial_ends_at.tzinfo is None:
            trial_ends_at = trial_ends_at.replace(tzinfo=timezone.utc)

        if plan == "pro":
            effective = "pro"
        elif plan == "trial":
            effective = "pro" if (trial_ends_at and now < trial_ends_at) else "free"
        else:
            effective = "free"
        can_control = effective == "pro"

        trial_days_left = 0
        if plan == "trial" and trial_ends_at and now < trial_ends_at:
            trial_days_left = max(0, (trial_ends_at - now).days)

    result = {
        "plan": plan,               # lo que compró/tiene: free | trial | pro
        "effective": effective,     # lo que RIGE ahora: free | pro
        "can_control": can_control, # bloquear/confiar/desbloquear/guardián
        "max_sites": 9999 if is_owner else (5 if can_control else 1),
        "trial_ends_at": trial_ends_at.isoformat() if trial_ends_at else None,
        "trial_days_left": trial_days_left,
        "owner": is_owner,          # tu cuenta de dueño (Pro permanente)
    }
    # Auth-3C: **permiso firmado** — el mismo veredicto, firmado por el relay con
    # caducidad, para que el agente/móvil no puedan ser engañados por un proxy o
    # un plan compartido. Es aditivo: el cliente que aún no verifica lee los
    # campos planos; el que verifica exige esta firma para confiar en el plan.
    try:
        from signing import sign_entitlement
        result["token"] = sign_entitlement(store, org, {
            "plan": plan, "effective": effective, "can_control": can_control,
            "max_sites": result["max_sites"], "trial_days_left": trial_days_left,
        }, now=now)
    except Exception:  # noqa: BLE001 - si la firma falla, el plan igual se entrega
        pass
    return result

# ─────────────────────── RBAC: roles y capacidades ───────────────────────
# Espejo de mobile/lib/core/domain/access/roles.dart, recortado a las acciones
# que existen en la NUBE (ver / comandos por sede). "*" = todas las capacidades.
# view=ver sedes/inventario · block=bloquear/desbloquear · trust=confiar ·
# rename=renombrar/responsable · panic=pánico. El ALCANCE (qué sedes) se aplica
# aparte, por dispositivo/sede.
_ROLE_CAPS: dict[str, set[str]] = {
    "owner": {"*"},
    "orgAdmin": {"*"},
    "siteAdmin": {"*"},   # todo, pero LIMITADO por su alcance de sedes
    "security": {"view", "block", "trust", "rename", "panic"},
    "operator": {"view"},
    "helpdesk": {"view", "rename"},
    "family": {"view", "rename"},
    "auditor": {"view"},
    "guest": {"view"},
}
# Qué capacidad exige cada comando remoto.
_CMD_CAP: dict[str, str] = {
    "block": "block", "unblock": "block",
    "trust": "trust", "rename": "rename", "set_owner": "rename",
}
_VALID_ROLES = set(_ROLE_CAPS)


class Principal:
    """Quién llama: una persona con rol+alcance, o el dueño (raíz)."""

    __slots__ = ("org_token", "role", "sites", "is_master", "name")

    def __init__(self, org_token: str, role: str, sites: list[str],
                 is_master: bool, name: str | None = None):
        self.org_token = org_token
        self.role = role
        self.sites = sites            # ["*"] = todas
        self.is_master = is_master
        self.name = name

    def can(self, cap: str) -> bool:
        caps = _ROLE_CAPS.get(self.role, set())
        return "*" in caps or cap in caps

    def sees_site(self, site_id: str) -> bool:
        return self.sites == ["*"] or site_id in self.sites


class _IPv4HTTPSConnection(http.client.HTTPSConnection):
    """HTTPS forzando IPv4. Railway (y otros PaaS) suelen NO tener salida IPv6;
    como ntfy.sh publica AAAA, la resolución elegía IPv6 y el POST fallaba con
    'Network is unreachable' (Errno 101) de forma intermitente. Forzar IPv4 hace
    la entrega determinista sin depender del orden de getaddrinfo."""

    def connect(self):
        infos = socket.getaddrinfo(
            self.host, self.port, socket.AF_INET, socket.SOCK_STREAM
        )
        af, socktype, proto, _canon, sa = infos[0]
        sock = socket.socket(af, socktype, proto)
        if self.timeout is not None:
            sock.settimeout(self.timeout)
        if self.source_address:
            sock.bind(self.source_address)
        sock.connect(sa)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _IPv4HTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_IPv4HTTPSConnection, req, context=self._context)


_IPV4_OPENER = urllib.request.build_opener(_IPv4HTTPSHandler())


_PUSH_TIMEOUT = float(os.environ.get("PUSH_TIMEOUT_SECONDS", "15"))
_PUSH_ATTEMPTS = int(os.environ.get("PUSH_ATTEMPTS", "3"))


def _push_ntfy(topic: str | None, title: str, message: str, *, priority: str, tags: str) -> str:
    """Envía un push a ntfy. El relay es el ÚNICO que ve todas las sedes 24/7, así
    que es el lugar correcto para alertar al dueño de la org. Devuelve
    'ok:<status>' | 'no_topic' | 'ERR:<detalle>' (nunca lanza).

    Egress a ntfy.sh desde PaaS (Railway) es intermitente/lento: se fuerza IPv4
    (no hay ruta IPv6) y se reintenta con backoff. Si aun así falla, el watchdog
    NO marca la sede como avisada y reintenta en el próximo tick (entrega fiable)."""
    if not topic or not topic.strip():
        return "no_topic"
    t = topic.strip()
    url = t if t.startswith("http") else f"https://ntfy.sh/{t}"
    safe_title = title.encode("ascii", "ignore").decode().strip() or "RedProtec"
    last = "ERR:sin_intento"
    for attempt in range(max(1, _PUSH_ATTEMPTS)):
        try:
            req = urllib.request.Request(
                url,
                data=message.encode("utf-8"),
                method="POST",
                headers={"Title": safe_title, "Priority": priority, "Tags": tags},
            )
            # _IPV4_OPENER maneja http y https (https por IPv4 forzado).
            resp = _IPV4_OPENER.open(req, timeout=_PUSH_TIMEOUT)  # noqa: S310
            return f"ok:{getattr(resp, 'status', '?')}"
        except Exception as exc:  # noqa: BLE001
            last = f"ERR:{type(exc).__name__}:{str(exc)[:100]}"
            if attempt < _PUSH_ATTEMPTS - 1:
                time.sleep(1.0 * (attempt + 1))  # backoff 1s, 2s
    return last


def _push_telegram(bot_token: str, chat_id: str, title: str, body: str) -> str:
    """Envía un mensaje por Telegram (api.telegram.org, alcanzable desde Railway
    cuando ntfy.sh no lo es). Reutiliza el bot que el dueño ya configuró en el
    agente. Devuelve 'ok:<status>' | 'ERR:<detalle>' (nunca lanza)."""
    if not bot_token or not chat_id:
        return "no_telegram"
    text = f"*{_tg_escape(title)}*\n{_tg_escape(body)}"
    payload = json.dumps({
        "chat_id": chat_id, "text": text, "parse_mode": "MarkdownV2",
        "disable_web_page_preview": True,
    }).encode("utf-8")
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    last = "ERR:sin_intento"
    for attempt in range(max(1, _PUSH_ATTEMPTS)):
        try:
            req = urllib.request.Request(
                url, data=payload, method="POST",
                headers={"Content-Type": "application/json"},
            )
            resp = _IPV4_OPENER.open(req, timeout=_PUSH_TIMEOUT)  # noqa: S310
            return f"ok:{getattr(resp, 'status', '?')}"
        except Exception as exc:  # noqa: BLE001
            last = f"ERR:{type(exc).__name__}:{str(exc)[:100]}"
            if attempt < _PUSH_ATTEMPTS - 1:
                time.sleep(1.0 * (attempt + 1))
    return last


def _tg_escape(s: str) -> str:
    """Escapa los caracteres reservados de MarkdownV2 de Telegram."""
    for ch in r"_*[]()~`>#+-=|{}.!":
        s = s.replace(ch, "\\" + ch)
    return s


def _push_alert(cfg: dict, title: str, body: str, *, priority: str, tags: str) -> str:
    """Enruta una alerta del watchdog al canal disponible de la org: Telegram
    (preferido — Railway lo alcanza) y, si no, ntfy. Reutiliza la config existente."""
    bot = (cfg.get("tg_bot_token") or "").strip()
    chat = (cfg.get("tg_chat_id") or "").strip()
    if bot and chat:
        return _push_telegram(bot, chat, title, body)
    topic = (cfg.get("alert_topic") or "").strip()
    if topic:
        return _push_ntfy(topic, title, body, priority=priority, tags=tags)
    return "no_channel"


def _fmt_device(d: dict) -> str:
    """Ficha compacta y legible de un equipo para el cuerpo del push."""
    name = d.get("name") or d.get("mac") or "Equipo"
    vendor = (d.get("vendor") or "").strip() or "Desconocido"
    ip = (d.get("ip") or "").strip() or "—"
    mac = (d.get("mac") or "").strip() or "—"
    return (
        f"• Equipo: {name}\n"
        f"• Fabricante: {vendor}\n"
        f"• IP: {ip}\n"
        f"• MAC: {mac}"
    )


def _unknown_macs(devs: list[dict] | None) -> set[str]:
    return {
        (d.get("mac") or "").upper()
        for d in (devs or [])
        if d.get("trust") == "unknown" and d.get("mac")
    }


def _down_criticals(devs: list[dict] | None) -> dict[str, dict]:
    return {
        (d.get("mac") or "").upper(): d
        for d in (devs or [])
        if d.get("is_critical") and not d.get("online") and d.get("mac")
    }


# ─────────────────────── watchdog de conexión por sede ───────────────────────
def decide_site_transition(
    prev_state: str | None, seconds_since_update: float, offline_threshold: int
) -> tuple[str, str | None]:
    """Máquina de estados PURA del watchdog. Devuelve (nuevo_estado, evento) con
    evento ∈ {None, 'down', 'up'}.

    - Sin estado previo (relay recién arrancado) → siembra SIN avisar (evita spam
      de "se cayó" en cada reinicio del relay).
    - en-línea → sin-conexión = 'down'; sin-conexión → en-línea = 'up'.
    """
    offline = seconds_since_update > offline_threshold
    current = "offline" if offline else "online"
    if prev_state is None:
        return current, None
    if prev_state == "online" and offline:
        return "offline", "down"
    if prev_state == "offline" and not offline:
        return "online", "up"
    return prev_state, None


def _humanize_seconds(seconds: float) -> str:
    seconds = max(0.0, seconds)
    if seconds < 90:
        return f"{int(round(seconds))} seg"
    minutes = seconds / 60.0
    if minutes < 90:
        return f"{int(round(minutes))} min"
    hours = minutes / 60.0
    if hours < 36:
        return f"{int(round(hours))} h"
    return f"{int(round(hours / 24.0))} d"


def compose_site_down_message(site_name: str) -> tuple[str, str]:
    return (
        f"RedProtec — {site_name}: sin conexión",
        f"🔴 «{site_name}» dejó de reportar. Puede ser una caída de internet o que "
        f"el agente se apagó. Te avisamos apenas vuelva.",
    )


def compose_site_up_message(site_name: str, down_seconds: float) -> tuple[str, str]:
    dur = _humanize_seconds(down_seconds)
    return (
        f"RedProtec — {site_name}: de vuelta en línea",
        f"✅ «{site_name}» volvió a reportar. Estuvo sin conexión {dur}.",
    )


def decide_escalation(
    incident: dict | None, now: datetime, interval: int, max_esc: int
) -> bool:
    """PURA: ¿toca reenviar un recordatorio de escalado? True solo si el incidente
    sigue ABIERTO, NADIE lo confirmó, no se superó el máximo de escalados, y pasó
    el intervalo desde el último aviso."""
    if not incident or not incident.get("incident_open"):
        return False
    if incident.get("acked"):
        return False
    if int(incident.get("escalation_level", 0)) >= max_esc:
        return False
    last = incident.get("last_alert_at")
    if not isinstance(last, datetime):
        return False
    return (now - last).total_seconds() >= interval


def compute_uptime(events: list[dict], start: datetime, now: datetime) -> dict:
    """PURA: a partir de los eventos down/up de UNA sede en [start, now], calcula
    uptime %, downtime total, nº de incidentes y MTTR (media de duración de las
    caídas RESUELTAS). Si el primer evento es 'up', se asume que la sede venía
    caída desde antes de la ventana (cuenta como incidente en curso)."""
    window = (now - start).total_seconds()
    if window <= 0:
        return {"uptime_pct": 100.0, "downtime_seconds": 0,
                "incidents": 0, "mttr_seconds": 0}
    evs = sorted(events, key=lambda e: e["at"])
    downtime = 0.0
    incidents = 0
    resolved: list[float] = []
    down_start: datetime | None = None
    if evs and evs[0]["event"] == "up":
        down_start = start
        incidents += 1
    for e in evs:
        at = min(max(e["at"], start), now)
        if e["event"] == "down":
            if down_start is None:
                down_start = at
                incidents += 1
        elif e["event"] == "up" and down_start is not None:
            d = (at - down_start).total_seconds()
            downtime += d
            resolved.append(d)
            down_start = None
    if down_start is not None:  # sigue caída al final de la ventana
        downtime += (now - down_start).total_seconds()
    downtime = max(0.0, min(downtime, window))
    return {
        "uptime_pct": round(100.0 * (1 - downtime / window), 3),
        "downtime_seconds": int(downtime),
        "incidents": incidents,
        "mttr_seconds": round(sum(resolved) / len(resolved)) if resolved else 0,
    }


def compute_incidents(events: list[dict], start: datetime, now: datetime) -> list[dict]:
    """PURA: empareja cada down→up de UNA sede en [start, now] como un INCIDENTE
    con marcas de tiempo (cayó / volvió / duración). El que sigue caído queda
    `ongoing`. Ordenados del más reciente al más antiguo — para el informe por
    sede, como lo pediría un arquitecto de redes (cada caída, no solo el total)."""
    evs = sorted(events, key=lambda e: e["at"])
    out: list[dict] = []
    down_at: datetime | None = None
    if evs and evs[0]["event"] == "up":
        down_at = start  # venía caída desde antes de la ventana
    for e in evs:
        if e["event"] == "down":
            if down_at is None:
                down_at = e["at"]
        elif e["event"] == "up" and down_at is not None:
            out.append({"down_at": down_at, "up_at": e["at"], "ongoing": False,
                        "duration_seconds": int((e["at"] - down_at).total_seconds())})
            down_at = None
    if down_at is not None:
        out.append({"down_at": down_at, "up_at": None, "ongoing": True,
                    "duration_seconds": int((now - down_at).total_seconds())})
    out.sort(key=lambda i: i["down_at"], reverse=True)
    return out


def compose_site_escalation_message(
    site_name: str, down_seconds: float, level: int
) -> tuple[str, str]:
    dur = _humanize_seconds(down_seconds)
    return (
        f"RedProtec — {site_name}: SIGUE CAÍDA (recordatorio {level})",
        f"⚠️ «{site_name}» lleva {dur} sin conexión y nadie ha confirmado el aviso. "
        f"Abre RedProtec → Incidentes y pulsa «Enterado» para detener los "
        f"recordatorios, o atiende la caída.",
    )


def _watchdog_tick(now: datetime) -> list[tuple[str, str, str]]:
    """Revisa TODAS las sedes y avisa las transiciones de conexión. Devuelve la
    lista de (org, site_id, evento) emitidos (para pruebas). Los pushes se envían
    fuera de todo candado (I/O de red)."""
    # Fase 1: leer del store (el store toma su PROPIO lock; no anidar con el
    # nuestro para no deadlockear).
    sites = [
        (org, site_id, rec) for org, site_id, rec in store.iter_sites_all()
    ]

    # Acciones pendientes de notificar: (org, site_id, event, new_state, since,
    # title, body, prio, tags). El estado NO se confirma hasta que el push SALE;
    # si falla, se reintenta en el próximo tick → una caída nunca se pierde por un
    # hipo de red (egress intermitente a ntfy.sh).
    pending: list[dict] = []
    emitted: list[tuple[str, str, str]] = []
    max_age: float | None = None
    recent: list[dict] = []

    # Fase 2: decidir transiciones. Los cambios (down/up) quedan PENDIENTES; solo
    # se persiste de una vez lo que no notifica (siembra / sin cambio).
    with _WATCH_LOCK:
        for org, site_id, rec in sites:
            updated = rec.get("updated_at")
            if updated is None:
                continue
            if updated.tzinfo is None:
                updated = updated.replace(tzinfo=timezone.utc)
            delta = (now - updated).total_seconds()
            max_age = delta if max_age is None else max(max_age, delta)

            org_watch = _SITE_WATCH.setdefault(org, {})
            prev = org_watch.get(site_id)
            prev_state = prev.get("state") if prev else None
            new_state, event = decide_site_transition(
                prev_state, delta, OFFLINE_ALERT_SECONDS
            )
            if delta < 3600:  # solo sedes recientes (dx, sin nombres)
                recent.append({"age": int(delta), "prev": prev_state,
                               "new": new_state, "event": event})

            if event == "down":
                title, body = compose_site_down_message(rec.get("site_name") or site_id)
                # Abre un INCIDENTE: down_at, sin confirmar, nivel 0.
                store_state = {
                    "state": "offline", "since": now,
                    "incident_open": True, "down_at": now,
                    "acked": False, "escalation_level": 0,
                    "last_alert_at": now,
                }
                pending.append({"org": org, "site_id": site_id, "event": event,
                                "store_state": store_state,
                                "title": title, "body": body,
                                "prio": "high", "tags": "rotating_light"})
                emitted.append((org, site_id, event))
            elif event == "up":
                down_since = (prev or {}).get("since")
                down_secs = (
                    (now - down_since).total_seconds()
                    if isinstance(down_since, datetime)
                    else 0.0
                )
                title, body = compose_site_up_message(
                    rec.get("site_name") or site_id, down_secs
                )
                # Cierra el incidente.
                store_state = {"state": "online", "since": now,
                               "incident_open": False}
                pending.append({"org": org, "site_id": site_id, "event": event,
                                "store_state": store_state,
                                "title": title, "body": body,
                                "prio": "default", "tags": "white_check_mark"})
                emitted.append((org, site_id, event))
            elif new_state == "offline" and decide_escalation(
                    prev, now, ESCALATION_INTERVAL_SECONDS, MAX_ESCALATIONS):
                # Sigue caída y NADIE confirmó → recordatorio de escalado.
                level = int((prev or {}).get("escalation_level", 0)) + 1
                down_at = (prev or {}).get("down_at", now)
                down_secs = (
                    (now - down_at).total_seconds()
                    if isinstance(down_at, datetime) else 0.0
                )
                title, body = compose_site_escalation_message(
                    rec.get("site_name") or site_id, down_secs, level)
                store_state = {**(prev or {}), "state": "offline",
                               "escalation_level": level, "last_alert_at": now}
                pending.append({"org": org, "site_id": site_id, "event": "escalate",
                                "store_state": store_state,
                                "title": title, "body": body,
                                "prio": "high", "tags": "warning"})
                emitted.append((org, site_id, "escalate"))
            else:
                # Sembrado inicial o sin cambio: persistir de una vez (no notifica),
                # PRESERVANDO los campos del incidente si los hubiera.
                org_watch[site_id] = {
                    **(prev or {}),
                    "state": new_state,
                    "since": (prev or {}).get("since", now),
                }

    # Observabilidad: registrar lo que vio este tick (antes de la I/O de red).
    _WDIAG["last_sites_seen"] = len(sites)
    _WDIAG["last_max_age"] = round(max_age) if max_age is not None else None
    _WDIAG["last_emitted"] = len(emitted)
    _WDIAG["last_recent"] = recent

    # Fase 3: enviar los pushes (FUERA del candado) y confirmar SOLO los que salen.
    push_diag: list[str] = []
    for act in pending:
        cfg = store.get_org_config(act["org"])
        result = _push_alert(cfg, act["title"], act["body"],
                             priority=act["prio"], tags=act["tags"])
        # Sin canal configurado: confirmar igual (no reintentar en bucle una org
        # sin destino). Con canal: confirmar solo si el envío salió.
        act["confirm"] = result == "no_channel" or str(result).startswith("ok")
        push_diag.append(result)
    if push_diag:
        _WDIAG["last_push"] = push_diag

    # Fase 4: confirmar el estado de las acciones cuyo push SÍ salió (o sin tema).
    # Las fallidas se dejan sin confirmar → el próximo tick las reintenta.
    to_record: list[tuple[str, str, str]] = []
    with _WATCH_LOCK:
        for act in pending:
            if not act.get("confirm"):
                continue
            org_watch = _SITE_WATCH.setdefault(act["org"], {})
            # Si el usuario CONFIRMÓ entre la decisión y el commit, respeta el ack
            # (no re-escales sobre un incidente ya atendido).
            if act["event"] == "escalate":
                cur = org_watch.get(act["site_id"])
                if cur and cur.get("acked"):
                    continue
            org_watch[act["site_id"]] = act["store_state"]
            if act["event"] in ("down", "up"):
                to_record.append((act["org"], act["site_id"], act["event"]))
    # Historial SLA (best-effort, FUERA del lock): registra caídas/recuperaciones
    # confirmadas. Nunca debe tumbar el watchdog si el store falla.
    for org_, sid_, ev_ in to_record:
        try:
            store.record_site_event(org_, sid_, ev_, now)
        except Exception:  # noqa: BLE001
            pass
    return emitted


# ─────────────────── Playbooks (automatización: si-X-haz-Y) ───────────────────
# Motor AISLADO del watchdog (se evalúa aparte, envuelto en try/except) para no
# arriesgar la fiabilidad de la detección/entrega de caídas, ya validada.
PB_COOLDOWN_SECONDS = int(os.environ.get("PB_COOLDOWN_SECONDS", "1800"))  # 30 min
_COND_LABEL = {
    "intruders": "hay equipos desconocidos",
    "critical_down": "un activo crítico está caído",
    "site_down": "la sede está sin conexión",
}
_ACTION_LABEL = {"notify": "avisar", "block_unknowns": "bloquear desconocidos"}
_PB_CONDITIONS = set(_COND_LABEL)
_PB_ACTIONS = set(_ACTION_LABEL)


def _pb_rules(org: str) -> list[dict]:
    raw = store.kv_get(f"playbooks::{org}")
    return json.loads(raw) if raw else []


def _pb_set_rules(org: str, rules: list[dict]) -> None:
    store.kv_set(f"playbooks::{org}", json.dumps(rules))


def _pb_pending(org: str) -> list[dict]:
    raw = store.kv_get(f"pb_pending::{org}")
    return json.loads(raw) if raw else []


def _pb_set_pending(org: str, items: list[dict]) -> None:
    store.kv_set(f"pb_pending::{org}", json.dumps(items))


def _pb_condition_met(cond: str, summ: dict, online: bool) -> bool:
    if cond == "intruders":
        return int(summ.get("alerts", 0) or 0) > 0
    if cond == "critical_down":
        return int(summ.get("criticals_down", 0) or 0) > 0
    if cond == "site_down":
        return not online
    return False


def _pb_execute(org: str, site_id: str, rec: dict, action: str, detail: str) -> str:
    """Ejecuta la acción de un playbook. Reutiliza el canal de alertas y la cola
    de comandos existentes. Devuelve un resumen de lo hecho (para la bitácora)."""
    if action == "notify":
        cfg = store.get_org_config(org)
        _push_alert(cfg, f"RedProtec — Automatización: {rec.get('site_name') or site_id}",
                    f"🤖 {detail}", priority="high", tags="robot")
        return "avisado"
    if action == "block_unknowns":
        if not rec.get("remote_admin"):
            return "sede sin administración remota"
        n = 0
        for d in (rec.get("devices") or []):
            if d.get("trust") == "unknown" and d.get("mac"):
                store.enqueue_command(org, site_id, {
                    "id": uuid.uuid4().hex[:12], "action": "block",
                    "mac": d["mac"], "value": None, "created_at": _now()})
                n += 1
        return f"{n} desconocido(s) bloqueado(s)"
    return "sin acción"


def _evaluate_playbooks(now: datetime) -> list[tuple[str, str, str]]:
    """Evalúa las reglas de cada organización contra el estado actual de sus
    sedes. `auto` ejecuta y audita; `suggest` deja una recomendación pendiente.
    Cooldown por (regla, sede) para no repetir. Devuelve (org, rule_id, mode)
    disparados (para pruebas)."""
    fired: list[tuple[str, str, str]] = []
    # Agrupa sedes por org una sola vez.
    by_org: dict[str, list[tuple[str, dict]]] = {}
    for org, site_id, rec in store.iter_sites_all():
        by_org.setdefault(org, []).append((site_id, rec))
    for org, sites in by_org.items():
        rules = _pb_rules(org)
        if not rules:
            continue
        raw_cd = store.kv_get(f"pb_cd::{org}")
        cds = json.loads(raw_cd) if raw_cd else {}
        changed = False
        pending_dirty = False
        pending = _pb_pending(org)
        for site_id, rec in sites:
            summ = rec.get("summary") or {}
            updated = rec.get("updated_at")
            online = updated is not None and (
                now - updated).total_seconds() <= ONLINE_WINDOW_SECONDS
            for r in rules:
                if not r.get("enabled", True):
                    continue
                if not _pb_condition_met(r.get("condition"), summ, online):
                    continue
                key = f"{r.get('id')}:{site_id}"
                last = cds.get(key)
                if last:
                    try:
                        if (now - datetime.fromisoformat(last)).total_seconds() < PB_COOLDOWN_SECONDS:
                            continue
                    except Exception:  # noqa: BLE001
                        pass
                name = r.get("name") or _COND_LABEL.get(r.get("condition"), "regla")
                detail = (f"«{name}»: {_COND_LABEL.get(r.get('condition'), r.get('condition'))} "
                          f"en {rec.get('site_name') or site_id} → "
                          f"{_ACTION_LABEL.get(r.get('action'), r.get('action'))}")
                if r.get("mode") == "auto":
                    res = _pb_execute(org, site_id, rec, r.get("action"), detail)
                    try:
                        store.record_audit(org, "Automatización",
                                           f"playbook_auto:{r.get('action')}",
                                           site_id, f"{detail} ({res})", now)
                    except Exception:  # noqa: BLE001
                        pass
                else:  # suggest → recomendación pendiente (dedup por regla+sede)
                    if not any(it.get("rule_id") == r.get("id")
                               and it.get("site_id") == site_id for it in pending):
                        pending.append({
                            "id": uuid.uuid4().hex[:10], "rule_id": r.get("id"),
                            "rule_name": name, "site_id": site_id,
                            "site_name": rec.get("site_name") or site_id,
                            "action": r.get("action"), "detail": detail,
                            "created_at": now.isoformat(),
                        })
                        pending_dirty = True
                cds[key] = now.isoformat()
                changed = True
                fired.append((org, str(r.get("id")), r.get("mode", "suggest")))
        if pending_dirty:
            _pb_set_pending(org, pending)
        if changed:
            store.kv_set(f"pb_cd::{org}", json.dumps(cds))
    return fired


async def _watchdog_loop() -> None:
    """Bucle de fondo: cada WATCHDOG_INTERVAL_SECONDS revisa las sedes. Nunca
    lanza: un fallo del tick no debe tumbar el relay."""
    while True:
        try:
            await asyncio.to_thread(_watchdog_tick, _now())
            _WDIAG["ticks"] += 1
            _WDIAG["last_tick_at"] = _now().isoformat()
            _WDIAG["last_error"] = None
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            _WDIAG["last_error"] = f"{type(exc).__name__}: {str(exc)[:200]}"
            logger.exception("Fallo en el watchdog de sedes")
        # Playbooks: AISLADO del tick (su fallo nunca afecta la detección/entrega).
        try:
            await asyncio.to_thread(_evaluate_playbooks, _now())
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.exception("Fallo evaluando playbooks: %s", exc)
        await asyncio.sleep(WATCHDOG_INTERVAL_SECONDS)


# ─────────────────────────── modelos ───────────────────────────
class SiteSummary(BaseModel):
    devices_total: int = 0
    devices_online: int = 0
    alerts: int = 0
    criticals_total: int = 0
    criticals_down: int = 0
    protection_mode: str = "unknown"
    network_name: str | None = None


class DeviceEntry(BaseModel):
    """Un equipo de la sede (solo se envía en modo inventario completo)."""

    mac: str
    name: str = ""
    vendor: str | None = None
    ip: str | None = None
    online: bool = False
    trust: str = "unknown"  # trusted | unknown | blocked
    is_critical: bool = False
    owner: str | None = None  # responsable del equipo en la sede
    # Consumo real en vivo (bytes/seg) y área/departamento del equipo. Viajan
    # para el mapa "Centro de mando" (consumo por equipo) y agrupación por área.
    # Sin estos campos, model_dump() los descartaría y nunca llegarían a la app.
    bytes_per_sec: float | None = None
    area: str | None = None


class Heartbeat(BaseModel):
    site_id: str = Field(min_length=1, max_length=128)
    site_name: str = Field(min_length=1, max_length=120)
    summary: SiteSummary = SiteSummary()
    # Opcional: inventario completo (modo empresa). Si viene, reemplaza el previo.
    devices: list[DeviceEntry] | None = None
    remote_admin: bool = False  # la sede permite comandos remotos


class CommandIn(BaseModel):
    action: str = Field(pattern="^(block|trust|unblock|rename|set_owner)$")
    mac: str = Field(min_length=1, max_length=64)
    value: str | None = Field(default=None, max_length=120)  # nombre/responsable


class SiteOut(BaseModel):
    site_id: str
    site_name: str
    online: bool
    updated_at: str
    seconds_since_update: int
    remote_admin: bool
    has_inventory: bool
    summary: SiteSummary


class SiteDetailOut(SiteOut):
    devices: list[DeviceEntry]


# ─────────────────────────── util ───────────────────────────
def _now() -> datetime:
    return datetime.now(timezone.utc)


def require_org_token(authorization: str | None = Header(default=None)) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Falta el token de organización")
    token = authorization[7:].strip()
    if len(token) < 8:
        raise HTTPException(status_code=401, detail="Token inválido")
    return token


def _resolve_principal(token: str) -> Principal:
    """Convierte un Bearer en un Principal.

    Si el token está registrado como acceso de USUARIO (en `_ACCESS`), devuelve su
    rol+alcance (acotado). Si NO, se trata como token MAESTRO de organización =
    raíz (compat hacia atrás: los agentes y el dueño siguen usando el org_token).
    Un token de usuario nunca puede escalar: si `_ACCESS` se perdió (reinicio del
    relay), resolvería a un "org" vacío sin sedes → no ve ni controla nada.
    """
    found = store.resolve_user(token)
    if found:
        org_tok, u = found
        return Principal(
            org_tok, u.get("role", "guest"),
            list(u.get("sites") or ["*"]), False, u.get("name"),
        )
    return Principal(token, "owner", ["*"], True, "Administrador")


def principal(authorization: str | None = Header(default=None)) -> Principal:
    token = require_org_token(authorization)
    # SaaS (Auth-1): si el Bearer es un login válido de Supabase, la identidad es
    # el usuario (claim `sub`) → dueño de SU PROPIA organización, aislada. Si no
    # (token opaco o Supabase no configurado), se usa el modelo de siempre.
    claims = verify_supabase_jwt(token)
    if claims and claims.get("sub"):
        return Principal(
            str(claims["sub"]), "owner", ["*"], True,
            claims.get("email") or claims.get("name") or "Cuenta",
        )
    # Auth-2: token de AGENTE (lo emite el relay al vincular una sede a una
    # cuenta). Resuelve al `org_token` de la cuenta → el agente reporta como
    # dueño de ESA organización, sin exponer credenciales adivinables.
    agent_org = store.resolve_agent_token(token)
    if agent_org:
        return Principal(agent_org, "owner", ["*"], True, "Agente")
    # Endurecimiento: un token de AGENTE que ya NO resuelve (revocado o desconocido)
    # se RECHAZA. Antes caía a `_resolve_principal`, que lo trataba como su propia
    # org maestra → aparecía una "sede fantasma" online y la sede real de la cuenta
    # quedaba congelada (sin conexión). Ahora el agente recibe 401 y debe volver a
    # vincular la sede a la cuenta (emite un token válido). Los tokens de org
    # MANUALES (sin este prefijo) siguen funcionando como antes.
    if token.startswith(AGENT_TOKEN_PREFIX):
        raise HTTPException(
            status_code=401,
            detail="Token de agente revocado o desconocido. Vuelve a vincular la "
                   "sede a tu cuenta desde la app (Mi cuenta → Vincular esta sede).")
    return _resolve_principal(token)


def require_master(p: Principal = Depends(principal)) -> Principal:
    """Solo el dueño/raíz (org_token maestro): latidos del agente, config de la
    organización y reparto de accesos. Un usuario acotado recibe 403."""
    if not p.is_master:
        raise HTTPException(status_code=403, detail="Requiere el token de administrador de la organización")
    return p


def _site_out(site_id: str, rec: dict, now: datetime) -> dict:
    delta = int((now - rec["updated_at"]).total_seconds())
    return {
        "site_id": site_id,
        "site_name": rec["site_name"],
        "online": delta <= ONLINE_WINDOW_SECONDS,
        "updated_at": rec["updated_at"].isoformat(),
        "seconds_since_update": delta,
        "remote_admin": rec.get("remote_admin", False),
        "has_inventory": bool(rec.get("devices")),
        "summary": rec["summary"],
    }


# ─────────────────────────── endpoints ───────────────────────────
@app.get("/health")
def health() -> dict:
    """Liveness. NO consulta la base a propósito: el healthcheck del host debe
    pasar en cuanto el proceso arranca, sin esperar a que Postgres esté listo
    (un arranque en frío lento hacía fallar el deploy). Los contadores van en
    ``/stats``."""
    return {"status": "ok", "version": app.version}


# ─────────────────── Descarga del Agente (enlace estable) ───────────────────
# La app y el sitio apuntan a {relay}/download; el destino real (GitHub Releases,
# etc.) se cambia por entorno sin tocar clientes. AGENT_VERSION opcional para el
# aviso de actualización.
AGENT_DOWNLOAD_URL = os.environ.get("AGENT_DOWNLOAD_URL", "").strip()
AGENT_VERSION = os.environ.get("AGENT_VERSION", "").strip()


@app.get("/download")
def download_agent() -> RedirectResponse:
    """Redirige al instalador del Agente (Windows). 404 si aún no se configuró."""
    if not AGENT_DOWNLOAD_URL:
        raise HTTPException(status_code=404, detail="download_not_configured")
    return RedirectResponse(AGENT_DOWNLOAD_URL, status_code=302)


@app.get("/download/info")
def download_info() -> dict:
    """Metadatos de la descarga (para el botón/aviso de actualización del cliente)."""
    return {
        "available": bool(AGENT_DOWNLOAD_URL),
        "version": AGENT_VERSION or None,
        "url": AGENT_DOWNLOAD_URL or None,
    }


@app.get("/v1/netcheck")
def netcheck(p: Principal = Depends(require_master)) -> dict:
    """Diagnóstico de EGRESS: qué destinos alcanza el relay (para elegir el canal
    de alertas). El push a ntfy.sh desde el PaaS resultó bloqueado/lento; esto
    prueba alternativas (Telegram, etc.) desde el propio contenedor. Solo dueño."""
    targets = {
        "ntfy_ipv4": ("https://ntfy.sh/", True),
        "ntfy_default": ("https://ntfy.sh/", False),
        "telegram": ("https://api.telegram.org/", True),
        "google204": ("https://www.google.com/generate_204", True),
        "cloudflare": ("https://cloudflare.com/cdn-cgi/trace", True),
    }
    out: dict = {}
    for name, (url, ipv4) in targets.items():
        opener = _IPV4_OPENER if (ipv4 and url.startswith("https://")) else urllib.request
        t0 = time.time()
        try:
            req = urllib.request.Request(url, method="GET")
            resp = opener.open(req, timeout=8)  # noqa: S310
            out[name] = {"ok": True, "status": getattr(resp, "status", "?"),
                         "ms": int((time.time() - t0) * 1000)}
        except Exception as exc:  # noqa: BLE001
            out[name] = {"ok": False, "err": f"{type(exc).__name__}:{str(exc)[:80]}",
                         "ms": int((time.time() - t0) * 1000)}
    return {"egress": out}


@app.get("/stats")
def stats() -> dict:
    """Contadores (best-effort). Si la base aún no responde, devuelve nulls sin
    romper — no es un endpoint de liveness."""
    wd = {
        "started": _WDIAG["started"],
        "ticks": _WDIAG["ticks"],
        "last_tick_at": _WDIAG["last_tick_at"],
        "last_error": _WDIAG["last_error"],
        "last_sites_seen": _WDIAG["last_sites_seen"],
        "last_max_age": _WDIAG["last_max_age"],
        "last_emitted": _WDIAG["last_emitted"],
        "last_recent": _WDIAG["last_recent"],
        "last_push": _WDIAG["last_push"],
        "interval_s": WATCHDOG_INTERVAL_SECONDS,
        "threshold_s": OFFLINE_ALERT_SECONDS,
    }
    try:
        orgs, sites = store.stats()
        return {"status": "ok", "orgs": orgs, "sites": sites, "watchdog": wd}
    except Exception:  # noqa: BLE001
        return {"status": "db_unavailable", "orgs": None, "sites": None,
                "watchdog": wd}


@app.post("/v1/heartbeat")
def heartbeat(hb: Heartbeat, p: Principal = Depends(require_master)) -> dict:
    """El agente reporta su sede y recoge comandos pendientes en la respuesta.
    Solo el token MAESTRO (el agente lo tiene): un acceso de usuario no puede
    inyectar sedes falsas."""
    org_token = p.org_token
    now = _now()
    alert_topic = None
    alerts: list[tuple[str, str, str, str]] = []  # (title, msg, priority, tags)

    prev = store.get_site(org_token, hb.site_id)
    new_summary = hb.summary.model_dump()
    new_devices = (
        [d.model_dump() for d in hb.devices] if hb.devices is not None else None
    )
    prev_devices = (prev or {}).get("devices")

    # ── Alertas por sede: avisar al dueño en las TRANSICIONES a peor ──
    # Si hay inventario, se IDENTIFICA el equipo culpable (nombre/IP/MAC);
    # si no, se cae a un mensaje genérico por conteo.
    if prev is not None:
        ps = prev["summary"]
        when = now.strftime("%d/%m %H:%M UTC")

        if new_summary["alerts"] > ps.get("alerts", 0):
            inv = new_devices if new_devices is not None else prev_devices
            culprit_macs = _unknown_macs(new_devices) - _unknown_macs(prev_devices)
            culprits = [
                d for d in (inv or [])
                if (d.get("mac") or "").upper() in culprit_macs
            ]
            if culprits:
                if len(culprits) == 1:
                    body = (
                        f"🚨 Equipo sin identificar en «{hb.site_name}»\n\n"
                        f"{_fmt_device(culprits[0])}\n"
                        f"• Detectado: {when}\n\n"
                        f"Ábrelo en el panel para bloquearlo o marcarlo confiable."
                    )
                else:
                    listado = "\n".join(
                        f"• {d.get('name') or d.get('mac')} "
                        f"({d.get('ip') or '—'} · {d.get('mac')})"
                        for d in culprits[:6]
                    )
                    body = (
                        f"🚨 {len(culprits)} equipos sin identificar en "
                        f"«{hb.site_name}»\n\n{listado}\n\nRevísalos en el panel."
                    )
            else:
                body = (
                    f"🚨 Apareció un equipo desconocido en «{hb.site_name}».\n"
                    f"Activa «Inventario completo» en esa sede para ver "
                    f"nombre, IP y MAC aquí."
                )
            alerts.append((
                f"RedProtec — {hb.site_name}: equipo desconocido",
                body, "high", "warning",
            ))

        if new_summary["criticals_down"] > ps.get("criticals_down", 0):
            prev_down = _down_criticals(prev_devices)
            cur_down = _down_criticals(new_devices)
            newly_down = [
                cur_down[m] for m in (set(cur_down) - set(prev_down))
            ] if new_devices is not None else []
            if newly_down:
                d = newly_down[0]
                extra = (
                    f"\n(y {len(newly_down) - 1} más)" if len(newly_down) > 1 else ""
                )
                body = (
                    f"🔴 Activo crítico sin responder en «{hb.site_name}»\n\n"
                    f"{_fmt_device(d)}\n"
                    f"• Estado: sin responder desde {when}{extra}\n\n"
                    f"Revisa la sede: el equipo dejó de estar en línea."
                )
            else:
                body = (
                    f"🔴 Un activo crítico dejó de responder en «{hb.site_name}».\n"
                    f"Activa «Inventario completo» en esa sede para ver el detalle."
                )
            alerts.append((
                f"RedProtec — {hb.site_name}: activo crítico caído",
                body, "high", "rotating_light",
            ))

    store.upsert_site(
        org_token, hb.site_id, hb.site_name, new_summary,
        new_devices if new_devices is not None else prev_devices,
        hb.remote_admin, now,
    )
    if alerts:
        alert_topic = store.get_org_config(org_token).get("alert_topic")

    pending: list[dict] = []
    if hb.remote_admin:
        pending = store.pending_commands(
            org_token, hb.site_id, COMMAND_TTL_SECONDS, now)

    # Enviar pushes fuera de cualquier candado (I/O de red).
    for title, msg, prio, tags in alerts:
        _push_ntfy(alert_topic, title, msg, priority=prio, tags=tags)

    # El agente recibe su plan en cada latido → gatea el control con el MISMO
    # contrato que el móvil (agente y app hablan un solo idioma sobre Free/Pro).
    return {
        "ok": True,
        "commands": pending,
        "entitlement": _compute_entitlement(org_token, now),
    }


@app.get("/v1/sites")
def list_sites(p: Principal = Depends(principal)) -> dict:
    """Sedes visibles para quien llama — filtradas a su ALCANCE (un gerente de
    sede solo ve la suya; el dueño/auditor global las ve todas)."""
    now = _now()
    out: list[dict] = []
    for site_id, rec in store.list_sites(p.org_token):
        if not p.sees_site(site_id):
            continue
        out.append(_site_out(site_id, rec, now))

    def _severity(s: dict) -> tuple:
        return (
            0 if not s["online"] else 1,
            0 if s["summary"]["criticals_down"] > 0 else 1,
            0 if s["summary"]["alerts"] > 0 else 1,
            s["site_name"].lower(),
        )

    out.sort(key=_severity)
    return {"sites": out, "role": p.role, "is_admin": p.is_master}


@app.get("/v1/sites/{site_id}")
def site_detail(site_id: str, p: Principal = Depends(principal)) -> dict:
    now = _now()
    if not p.sees_site(site_id):
        raise HTTPException(status_code=403, detail="Esta sede está fuera de tu alcance")
    rec = store.get_site(p.org_token, site_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Sede no encontrada")
    base = _site_out(site_id, rec, now)
    base["devices"] = rec.get("devices") or []
    base["role"] = p.role
    base["can_command"] = p.sees_site(site_id) and (
        p.can("block") or p.can("trust") or p.can("rename")
    )
    return base


@app.delete("/v1/sites/{site_id}")
def delete_site(site_id: str, p: Principal = Depends(require_master)) -> dict:
    """Da de baja una sede: la quita del panel (y su cola de comandos). Solo el
    dueño/raíz. También limpia el estado del watchdog para que una sede eliminada
    no genere un aviso de "sin conexión" tardío."""
    existed = store.remove_site(p.org_token, site_id)
    with _WATCH_LOCK:
        _SITE_WATCH.get(p.org_token, {}).pop(site_id, None)
    if not existed:
        raise HTTPException(status_code=404, detail="Sede no encontrada")
    return {"ok": True}


@app.post("/v1/sites/{site_id}/commands")
def enqueue_command(
    site_id: str, cmd: CommandIn, p: Principal = Depends(principal)
) -> dict:
    """La app encola un comando; el agente lo recoge en su próximo latido.
    Exige la CAPACIDAD del rol para esa acción Y que la sede esté en su alcance."""
    now = _now()
    cap = _CMD_CAP.get(cmd.action, cmd.action)
    if not p.sees_site(site_id):
        raise HTTPException(status_code=403, detail="Esta sede está fuera de tu alcance")
    if not p.can(cap):
        raise HTTPException(
            status_code=403,
            detail=f"Tu rol ({p.role}) no puede ejecutar «{cmd.action}» a distancia",
        )
    # Auth-3 (freemium): controlar (bloquear/confiar/…) exige plan Pro. Refuerzo
    # SERVER-SIDE → no se puede saltar desde el móvil. Ver = gratis; proteger = Pro.
    if not _compute_entitlement(p.org_token, now)["can_control"]:
        raise HTTPException(status_code=402, detail="upgrade_required")
    rec = store.get_site(p.org_token, site_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Sede no encontrada")
    if not rec.get("remote_admin"):
        raise HTTPException(
            status_code=403,
            detail="Esta sede no permite administración remota",
        )
    command = {
        "id": uuid.uuid4().hex[:12],
        "action": cmd.action,
        "mac": cmd.mac,
        "value": cmd.value,
        "created_at": now,
    }
    store.enqueue_command(p.org_token, site_id, command)
    _audit(p, f"command:{cmd.action}", f"{site_id}/{cmd.mac}",
           f"Comando remoto «{cmd.action}»"
           + (f" = {cmd.value}" if cmd.value else ""))
    return {"ok": True, "command_id": command["id"]}


@app.post("/v1/commands/{command_id}/ack")
def ack_command(
    command_id: str,
    site_id: str = Header(default="", alias="X-Site-Id"),
    p: Principal = Depends(require_master),
) -> dict:
    """El agente confirma que ejecutó un comando; se retira de la cola."""
    store.ack_command(p.org_token, site_id, command_id)
    return {"ok": True}


# ─────────────────────── config de la organización ───────────────────────
class OrgConfigIn(BaseModel):
    alert_topic: str | None = None  # tema ntfy para alertas por sede


class AlertChannelIn(BaseModel):
    """Canal de alertas del watchdog en la nube. El agente lo reporta desde su
    integración de Telegram (o el dueño lo fija a mano). El bot_token es secreto:
    nunca se devuelve por la API."""
    telegram_bot_token: str | None = None
    telegram_chat_id: str | None = None


@app.get("/v1/org/config")
def get_org_config(p: Principal = Depends(require_master)) -> dict:
    cfg = store.get_org_config(p.org_token)
    return {
        "alert_topic": cfg.get("alert_topic"),
        # El token nunca se revela; solo si HAY un canal Telegram configurado.
        "telegram_set": bool((cfg.get("tg_bot_token") or "").strip()
                             and (cfg.get("tg_chat_id") or "").strip()),
        "telegram_chat_id": cfg.get("tg_chat_id"),
    }


@app.post("/v1/org/config")
def set_org_config(cfg: OrgConfigIn, p: Principal = Depends(require_master)) -> dict:
    store.set_alert_topic(p.org_token, (cfg.alert_topic or "").strip() or None)
    return {"ok": True}


@app.post("/v1/org/test-alert")
def test_alert(p: Principal = Depends(require_master)) -> dict:
    """Envía una alerta de PRUEBA por el canal configurado de la org (Telegram o
    ntfy) y devuelve el resultado del envío. Sirve para que el dueño verifique
    'de una' que las alertas del watchdog en la nube le llegan."""
    try:
        cfg = store.get_org_config(p.org_token)
        channel = ("telegram" if (cfg.get("tg_bot_token") and cfg.get("tg_chat_id"))
                   else "ntfy" if cfg.get("alert_topic") else "none")
        result = _push_alert(
            cfg,
            "RedProtec: prueba de alertas",
            "✅ Si ves este mensaje, el vigía en la nube puede avisarte. "
            "Te llegará así si una sede pierde internet.",
            priority="default", tags="white_check_mark",
        )
        return {"channel": channel, "result": result,
                "ok": str(result).startswith("ok")}
    except Exception as exc:  # noqa: BLE001 - no exponer un 500 opaco al cliente
        return {"channel": "error", "result": f"{type(exc).__name__}: {exc}",
                "ok": False}


@app.post("/v1/org/alert-channel")
def set_alert_channel(body: AlertChannelIn, p: Principal = Depends(require_master)) -> dict:
    """Fija el canal Telegram del watchdog para la org. Lo llama el agente (con el
    bot que el dueño ya configuró) o el panel. Vacío = lo borra."""
    store.set_alert_channel(
        p.org_token,
        telegram_bot_token=(body.telegram_bot_token or "").strip() or None,
        telegram_chat_id=(body.telegram_chat_id or "").strip() or None,
    )
    return {"ok": True}


# ─────────────────────── inteligencia cruzada ───────────────────────
@app.get("/v1/insights")
def insights(p: Principal = Depends(principal)) -> dict:
    """**Intruso itinerante**: equipos NO confiables (unknown) cuya misma MAC
    aparece en 2+ sedes. Solo posible con visión multi-sede — el diferenciador.
    Requiere que esas sedes tengan inventario completo activado. Filtra a las
    sedes del ALCANCE de quien llama (un intruso solo cuenta en sus sedes)."""
    now = _now()
    # mac -> { name, sites:set, trust }
    seen: dict[str, dict] = {}
    for site_id, rec in store.list_sites(p.org_token):
        if not p.sees_site(site_id):
            continue
        for d in (rec.get("devices") or []):
            if d.get("trust") != "unknown":
                continue
            mac = d.get("mac", "").upper()
            if not mac:
                continue
            entry = seen.setdefault(mac, {"name": d.get("name") or mac, "sites": set()})
            entry["sites"].add(rec["site_name"])

    roaming = [
        {"mac": mac, "name": e["name"], "sites": sorted(e["sites"]), "site_count": len(e["sites"])}
        for mac, e in seen.items()
        if len(e["sites"]) >= 2
    ]
    roaming.sort(key=lambda r: -r["site_count"])
    return {"roaming_unknowns": roaming, "generated_at": now.isoformat()}


def _is_private_mac(mac: str) -> bool:
    """MAC localmente administrada (privada/aleatoria): 2º nibble ∈ {2,6,A,E}.
    Señal de un equipo que oculta su identidad (evasivo)."""
    h = mac.replace(":", "").replace("-", "").upper()
    return len(h) >= 2 and h[1] in {"2", "6", "A", "E"}


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@app.get("/v1/threats")
def fleet_threats(p: Principal = Depends(principal)) -> dict:
    """**Centro de Amenazas de Flota** (diferenciador multi-sede): correlaciona el
    inventario de TODAS las sedes del alcance de quien llama y clasifica amenazas
    que solo se ven con visión de flota — sin duplicar motores, reusa lo que las
    sedes ya reportan (trust/mac/vendor):

    - `known_bad_roaming` (crítica): un equipo BLOQUEADO en una sede aparece en
      otra(s) → el mismo intruso saltando de sede.
    - `roaming_unknown` (alta): un desconocido con la misma MAC en 2+ sedes.
    - `evasive_unknown` (media): desconocido con MAC privada/aleatoria (se oculta).
    - `blocked` (baja): bloqueo activo (informativo).
    """
    now = _now()
    # mac -> agregado entre sedes.
    agg: dict[str, dict] = {}
    sites_seen: set[str] = set()
    for site_id, rec in store.list_sites(p.org_token):
        if not p.sees_site(site_id):
            continue
        sites_seen.add(site_id)
        for d in (rec.get("devices") or []):
            mac = (d.get("mac") or "").upper()
            if not mac:
                continue
            e = agg.setdefault(mac, {
                "name": d.get("name") or mac, "vendor": d.get("vendor"),
                "sites": [], "trusts": set(),
            })
            if not e.get("vendor") and d.get("vendor"):
                e["vendor"] = d.get("vendor")
            trust = d.get("trust") or "unknown"
            e["sites"].append({
                "site_id": site_id, "site_name": rec["site_name"],
                "trust": trust, "online": bool(d.get("online")),
            })
            e["trusts"].add(trust)

    threats: list[dict] = []
    for mac, e in agg.items():
        site_names = sorted({s["site_name"] for s in e["sites"]})
        n_sites = len(site_names)
        trusts = e["trusts"]
        blocked = "blocked" in trusts
        unknown = "unknown" in trusts
        # Presente (no bloqueado) en alguna sede además de estar bloqueado en otra.
        present_elsewhere = any(s["trust"] != "blocked" for s in e["sites"])

        if blocked and present_elsewhere and n_sites >= 2:
            sev, typ = "critical", "known_bad_roaming"
            title = "Equipo vetado apareció en otra sede"
            detail = (f"«{e['name']}» está BLOQUEADO en una sede pero aparece en "
                      f"{n_sites} sedes. Es el mismo equipo saltando de sede.")
            reco = "Bloquéalo en todas las sedes donde aparece."
        elif unknown and n_sites >= 2:
            sev, typ = "high", "roaming_unknown"
            title = "Intruso itinerante"
            detail = (f"«{e['name']}» (desconocido) aparece en {n_sites} sedes con "
                      f"la misma identidad. Un mismo desconocido en varias sedes "
                      f"es sospechoso.")
            reco = "Identifícalo (¿es tuyo?) o bloquéalo en la flota."
        elif unknown and _is_private_mac(mac):
            sev, typ = "medium", "evasive_unknown"
            title = "Desconocido evasivo (MAC privada)"
            detail = (f"«{e['name']}» usa MAC privada/aleatoria y no está "
                      f"identificado: dificulta el rastreo.")
            reco = "Verifica de quién es; si no lo reconoces, bloquéalo."
        elif blocked:
            sev, typ = "low", "blocked"
            title = "Bloqueo activo"
            detail = f"«{e['name']}» está bloqueado en {n_sites} sede(s)."
            reco = "Sin acción: vigilancia."
        else:
            continue

        threats.append({
            "id": mac,
            "type": typ,
            "severity": sev,
            "mac": mac,
            "name": e["name"],
            "vendor": e.get("vendor"),
            "sites": e["sites"],
            "site_names": site_names,
            "site_count": n_sites,
            "title": title,
            "detail": detail,
            "recommendation": reco,
        })

    threats.sort(key=lambda t: (_SEV_RANK.get(t["severity"], 9), -t["site_count"]))
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0,
               "total": len(threats), "sites": len(sites_seen)}
    for t in threats:
        summary[t["severity"]] = summary.get(t["severity"], 0) + 1
    return {"threats": threats, "summary": summary, "generated_at": now.isoformat()}


_GRADE_BANDS = [(90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F")]


def _grade(score: int) -> str:
    for th, g in _GRADE_BANDS:
        if score >= th:
            return g
    return "F"


@app.get("/v1/compliance")
def compliance(p: Principal = Depends(principal)) -> dict:
    """**Postura de Cumplimiento** (diferenciador empresa): calcula una nota de
    seguridad A–F por sede a partir de lo que ya reporta (intrusos sin gestionar,
    activos críticos caídos, protección activa, visibilidad, conectividad) y una
    nota de flota. Reutiliza `_site_out`; no persiste nada. Ideal para auditoría."""
    now = _now()
    sites: list[dict] = []
    for site_id, rec in store.list_sites(p.org_token):
        if not p.sees_site(site_id):
            continue
        so = _site_out(site_id, rec, now)
        s = so["summary"]
        score = 100
        findings: list[dict] = []
        if not so["online"]:
            score -= 25
            findings.append({"severity": "high",
                             "text": "La sede no está reportando (agente caído o sin internet)."})
        alerts = int(s.get("alerts", 0))
        if alerts > 0:
            score -= min(30, alerts * 6)
            findings.append({"severity": "high" if alerts >= 3 else "medium",
                             "text": f"{alerts} equipo(s) desconocido(s) sin gestionar."})
        cd = int(s.get("criticals_down", 0))
        if cd > 0:
            score -= min(30, cd * 15)
            findings.append({"severity": "critical",
                             "text": f"{cd} activo(s) crítico(s) fuera de línea."})
        if s.get("protection_mode") != "guardian":
            score -= 15
            findings.append({"severity": "medium",
                             "text": "Protección activa (Guardián) no confirmada."})
        if not so["has_inventory"]:
            score -= 12
            findings.append({"severity": "low",
                             "text": "Sin inventario completo: visibilidad limitada."})
        if so["remote_admin"]:
            score = min(100, score + 5)  # puede responder remotamente
        score = max(0, min(100, score))
        if not findings:
            findings.append({"severity": "ok", "text": "Sin hallazgos: sede en buen estado."})
        sites.append({
            "site_id": site_id, "site_name": rec["site_name"],
            "online": so["online"], "score": score, "grade": _grade(score),
            "findings": findings,
            "devices_total": int(s.get("devices_total", 0)),
            "criticals_total": int(s.get("criticals_total", 0)),
        })
    sites.sort(key=lambda x: (x["score"], x["site_name"].lower()))  # peor primero
    overall = round(sum(x["score"] for x in sites) / len(sites)) if sites else 0
    return {
        "sites": sites,
        "overall": {"score": overall, "grade": _grade(overall) if sites else "—",
                    "sites": len(sites)},
        "generated_at": now.isoformat(),
    }


@app.get("/v1/availability")
def availability(p: Principal = Depends(principal)) -> dict:
    """**Tablero de Disponibilidad** (diferenciador NOC): estado EN VIVO de las
    sedes y de sus activos críticos (arriba/abajo, hace cuánto reportó). Reúne el
    watchdog + activos críticos que ya existen. Base para SLA/MTTR."""
    now = _now()
    sites: list[dict] = []
    total_crit = up_crit = online_sites = 0
    for site_id, rec in store.list_sites(p.org_token):
        if not p.sees_site(site_id):
            continue
        so = _site_out(site_id, rec, now)
        s = so["summary"]
        ct = int(s.get("criticals_total", 0))
        cd = int(s.get("criticals_down", 0))
        cu = max(0, ct - cd)
        total_crit += ct
        up_crit += cu
        if so["online"]:
            online_sites += 1
        sites.append({
            "site_id": site_id, "site_name": rec["site_name"],
            "online": so["online"],
            "seconds_since_update": so["seconds_since_update"],
            "criticals_total": ct, "criticals_down": cd, "criticals_up": cu,
            "devices_online": int(s.get("devices_online", 0)),
            "devices_total": int(s.get("devices_total", 0)),
        })
    sites.sort(key=lambda x: (0 if not x["online"] else 1,
                              -x["criticals_down"], x["site_name"].lower()))
    n = len(sites)
    return {
        "sites": sites,
        "summary": {
            "sites": n, "sites_online": online_sites,
            "criticals_total": total_crit, "criticals_up": up_crit,
            "criticals_down": total_crit - up_crit,
            "availability_pct": round(100 * up_crit / total_crit) if total_crit else 100,
        },
        "generated_at": now.isoformat(),
    }


@app.get("/v1/sla")
def sla(days: int = 30, p: Principal = Depends(principal)) -> dict:
    """**SLA histórico**: uptime %, incidentes y MTTR por sede en los últimos
    `days` días, a partir del historial de caídas/recuperaciones persistido. Es la
    prueba AUDITABLE de disponibilidad — algo que Fing no da."""
    days = max(1, min(int(days), 365))
    now = _now()
    start = now - timedelta(days=days)
    by_site: dict[str, list] = {}
    for e in store.site_events(p.org_token, start):
        by_site.setdefault(e["site_id"], []).append(e)
    out: list[dict] = []
    for site_id, rec in store.list_sites(p.org_token):
        if not p.sees_site(site_id):
            continue
        evs = by_site.get(site_id, [])
        u = compute_uptime(evs, start, now)
        incs = compute_incidents(evs, start, now)[:200]
        detail = [{
            "down_at": i["down_at"].isoformat(),
            "up_at": i["up_at"].isoformat() if i["up_at"] else None,
            "duration_seconds": i["duration_seconds"],
            "ongoing": i["ongoing"],
        } for i in incs]
        out.append({"site_id": site_id, "site_name": rec["site_name"],
                    **u, "incidents_detail": detail})
    out.sort(key=lambda x: (x["uptime_pct"], x["site_name"].lower()))  # peor primero
    if out:
        overall = round(sum(x["uptime_pct"] for x in out) / len(out), 3)
        total_incidents = sum(x["incidents"] for x in out)
    else:
        overall, total_incidents = 100.0, 0
    return {
        "sites": out, "days": days,
        "overall": {"uptime_pct": overall, "incidents": total_incidents,
                    "sites": len(out)},
        "generated_at": now.isoformat(),
    }


@app.get("/v1/incidents")
def incidents(p: Principal = Depends(principal)) -> dict:
    """**On-call:** incidentes ABIERTOS (sedes caídas) del alcance de quien llama,
    con si están CONFIRMADOS y su nivel de escalado. La app los muestra para poder
    pulsar «Enterado» y detener los recordatorios."""
    now = _now()
    with _WATCH_LOCK:
        org_watch = {k: dict(v) for k, v in _SITE_WATCH.get(p.org_token, {}).items()}
    out: list[dict] = []
    for site_id, st in org_watch.items():
        if not p.sees_site(site_id) or not st.get("incident_open"):
            continue
        rec = store.get_site(p.org_token, site_id)
        down_at = st.get("down_at")
        down_secs = (
            (now - down_at).total_seconds() if isinstance(down_at, datetime) else 0.0
        )
        out.append({
            "site_id": site_id,
            "site_name": (rec or {}).get("site_name") or site_id,
            "down_since": down_at.isoformat() if isinstance(down_at, datetime) else None,
            "down_seconds": int(down_secs),
            "acked": bool(st.get("acked")),
            "escalation_level": int(st.get("escalation_level", 0)),
        })
    # Sin confirmar primero, luego los más antiguos.
    out.sort(key=lambda x: (x["acked"], -x["down_seconds"]))
    return {"incidents": out, "generated_at": now.isoformat()}


@app.post("/v1/incidents/{site_id}/ack")
def ack_incident(site_id: str, p: Principal = Depends(principal)) -> dict:
    """Confirma («Enterado») un incidente: detiene los recordatorios de escalado.
    Cualquiera con alcance a la sede puede confirmar (está de guardia)."""
    if not p.sees_site(site_id):
        raise HTTPException(status_code=403, detail="Sede fuera de tu alcance")
    with _WATCH_LOCK:
        st = _SITE_WATCH.get(p.org_token, {}).get(site_id)
        if not st or not st.get("incident_open"):
            raise HTTPException(status_code=404, detail="No hay incidente abierto en esa sede")
        st["acked"] = True
    _audit(p, "incident_ack", site_id, "Confirmó el incidente («Enterado»)")
    return {"ok": True}


def _audit(p: Principal, action: str, target: str, detail: str = "") -> None:
    """Registra una acción sensible en la bitácora (best-effort, nunca rompe el
    flujo). El actor es el nombre/rol de quien la ejecutó."""
    try:
        actor = getattr(p, "label", "") or p.role or "?"
        store.record_audit(p.org_token, actor, action, target, detail, _now())
    except Exception:  # noqa: BLE001
        pass


@app.get("/v1/audit")
def audit(limit: int = 100, p: Principal = Depends(principal)) -> dict:
    """**Bitácora de auditoría** (quién hizo qué): las últimas acciones sensibles
    de la organización (comandos remotos, confirmaciones, cambios de acceso). Para
    forense y cumplimiento — algo que Fing no da."""
    limit = max(1, min(int(limit), 500))
    rows = store.list_audit(p.org_token, limit)
    out = [{
        "actor": r["actor"], "action": r["action"], "target": r["target"],
        "detail": r["detail"],
        "at": r["at"].isoformat() if hasattr(r["at"], "isoformat") else str(r["at"]),
    } for r in rows]
    return {"entries": out, "generated_at": _now().isoformat()}


class PlaybookRule(BaseModel):
    id: str = Field(default="", max_length=32)
    name: str = Field(default="", max_length=80)
    condition: str
    action: str
    mode: str = "suggest"   # suggest | auto
    enabled: bool = True


class PlaybooksIn(BaseModel):
    rules: list[PlaybookRule] = Field(default_factory=list)


@app.get("/v1/playbooks")
def get_playbooks(p: Principal = Depends(require_master)) -> dict:
    """Reglas de automatización de la organización (solo el dueño las gestiona)."""
    return {"rules": _pb_rules(p.org_token),
            "conditions": sorted(_PB_CONDITIONS), "actions": sorted(_PB_ACTIONS)}


@app.put("/v1/playbooks")
def set_playbooks(body: PlaybooksIn, p: Principal = Depends(require_master)) -> dict:
    """**Reemplaza** las reglas (la app es la fuente de verdad). Valida condición/
    acción/modo y asigna id a las nuevas. Idempotente."""
    out: list[dict] = []
    for r in body.rules:
        if r.condition not in _PB_CONDITIONS:
            raise HTTPException(status_code=400, detail=f"Condición inválida: {r.condition}")
        if r.action not in _PB_ACTIONS:
            raise HTTPException(status_code=400, detail=f"Acción inválida: {r.action}")
        if r.mode not in ("suggest", "auto"):
            raise HTTPException(status_code=400, detail=f"Modo inválido: {r.mode}")
        out.append({
            "id": r.id or uuid.uuid4().hex[:10], "name": r.name,
            "condition": r.condition, "action": r.action,
            "mode": r.mode, "enabled": bool(r.enabled),
        })
    _pb_set_rules(p.org_token, out)
    _audit(p, "playbooks_update", "automatización", f"Guardó {len(out)} regla(s)")
    return {"ok": True, "rules": out}


@app.get("/v1/playbooks/pending")
def playbooks_pending(p: Principal = Depends(principal)) -> dict:
    """Recomendaciones PENDIENTES (reglas en modo «sugerir» que se dispararon) del
    alcance de quien llama, para aprobarlas o descartarlas."""
    items = [it for it in _pb_pending(p.org_token) if p.sees_site(it.get("site_id"))]
    return {"pending": items, "generated_at": _now().isoformat()}


@app.post("/v1/playbooks/pending/{item_id}/approve")
def approve_pending(item_id: str, p: Principal = Depends(principal)) -> dict:
    """Aprueba una recomendación → EJECUTA su acción ahora y la quita de pendientes."""
    items = _pb_pending(p.org_token)
    target = next((it for it in items if it.get("id") == item_id), None)
    if not target:
        raise HTTPException(status_code=404, detail="Recomendación no encontrada")
    if not p.sees_site(target.get("site_id")):
        raise HTTPException(status_code=403, detail="Sede fuera de tu alcance")
    rec = store.get_site(p.org_token, target["site_id"])
    res = _pb_execute(p.org_token, target["site_id"], rec or {},
                      target.get("action"), target.get("detail", "")) if rec else "sede no encontrada"
    _audit(p, f"playbook_approve:{target.get('action')}", target.get("site_id"),
           f"{target.get('detail','')} ({res})")
    _pb_set_pending(p.org_token, [it for it in items if it.get("id") != item_id])
    return {"ok": True, "result": res}


@app.post("/v1/playbooks/pending/{item_id}/dismiss")
def dismiss_pending(item_id: str, p: Principal = Depends(principal)) -> dict:
    """Descarta una recomendación sin ejecutarla."""
    items = _pb_pending(p.org_token)
    if not any(it.get("id") == item_id for it in items):
        raise HTTPException(status_code=404, detail="Recomendación no encontrada")
    _pb_set_pending(p.org_token, [it for it in items if it.get("id") != item_id])
    return {"ok": True}


@app.get("/v1/inventory")
def global_inventory(p: Principal = Depends(principal)) -> dict:
    """Inventario CONSOLIDADO: equipos de las sedes del ALCANCE de quien llama
    (para buscar/exportar). Requiere inventario por sede."""
    out: list[dict] = []
    for site_id, rec in store.list_sites(p.org_token):
        if not p.sees_site(site_id):
            continue
        for d in (rec.get("devices") or []):
            out.append({**d, "site_id": site_id, "site_name": rec["site_name"]})
    out.sort(key=lambda d: (d["site_name"].lower(), 0 if d.get("online") else 1, (d.get("name") or "").lower()))
    return {"devices": out, "total": len(out)}


# ─────────────────────── RBAC: reparto de accesos (solo dueño) ───────────────────────
class AccessUser(BaseModel):
    token: str = Field(min_length=8, max_length=200)
    name: str = Field(default="", max_length=120)
    role: str = "guest"
    sites: list[str] = Field(default_factory=lambda: ["*"])  # ["*"] = todas


class AccessListIn(BaseModel):
    users: list[AccessUser] = Field(default_factory=list)


def _access_out(token: str, u: dict) -> dict:
    return {
        "token": token,
        "name": u.get("name") or "",
        "role": u.get("role") or "guest",
        "sites": list(u.get("sites") or ["*"]),
    }


@app.get("/v1/access")
def list_access(p: Principal = Depends(require_master)) -> dict:
    """Lista los accesos por-persona de la organización (solo el dueño)."""
    users = store.list_access(p.org_token)
    return {"users": [_access_out(t, u) for t, u in users.items()]}


@app.put("/v1/access")
def set_access(body: AccessListIn, p: Principal = Depends(require_master)) -> dict:
    """**Reemplaza** la lista completa de accesos de la organización (solo el
    dueño). La app admin es la fuente de verdad y re-sincroniza al abrir, así el
    relay (en memoria) se restaura tras un reinicio. Idempotente."""
    for u in body.users:
        if u.role not in _VALID_ROLES:
            raise HTTPException(status_code=400, detail=f"Rol inválido: {u.role}")
        # No-escalada: nadie reparte 'owner' por aquí (queda reservado al maestro).
        if u.role == "owner":
            raise HTTPException(status_code=400, detail="No se puede conceder el rol de dueño")
    store.set_access(
        p.org_token,
        [{"token": u.token, "name": u.name, "role": u.role,
          "sites": list(u.sites or ["*"])} for u in body.users],
    )
    _audit(p, "access_update", "rbac",
           f"Actualizó accesos ({len(body.users)} persona(s))")
    return {"ok": True, "count": len(body.users)}


# ─────────────────── Auth-2: vincular una sede a una cuenta ───────────────────
class AgentTokenIn(BaseModel):
    label: str = Field(default="", max_length=120)  # nombre de la sede/PC


@app.post("/v1/agent-tokens")
def create_agent_token(
    body: AgentTokenIn | None = None, p: Principal = Depends(require_master)
) -> dict:
    """Emite un token de AGENTE ligado a la organización de quien llama (su
    cuenta). La app lo pide con la sesión iniciada y lo guarda en el agente para
    que esa sede reporte a la cuenta. Solo el dueño/cuenta (token maestro)."""
    token = AGENT_TOKEN_PREFIX + secrets.token_urlsafe(24)
    label = (body.label if body else "") or "Sede"
    store.create_agent_token(p.org_token, token, label, _now())
    return {"ok": True, "token": token, "label": label}


@app.get("/v1/agent-tokens")
def list_agent_tokens(p: Principal = Depends(require_master)) -> dict:
    """Lista las sedes vinculadas a la cuenta (sin revelar el token completo)."""
    out = []
    for t in store.list_agent_tokens(p.org_token):
        tok = t.get("token", "")
        created = t.get("created_at")
        out.append({
            "token_hint": (tok[-6:] if tok else ""),
            "label": t.get("label", ""),
            "created_at": created.isoformat() if hasattr(created, "isoformat") else created,
        })
    return {"agents": out}


@app.delete("/v1/agent-tokens/{token}")
def revoke_agent_token(token: str, p: Principal = Depends(require_master)) -> dict:
    """Revoca (desvincula) un token de agente de la cuenta."""
    store.revoke_agent_token(p.org_token, token)
    return {"ok": True}


# ─────────────────────── Auth-3: entitlement / plan ───────────────────────
@app.get("/v1/entitlement")
def get_entitlement(p: Principal = Depends(principal)) -> dict:
    """Plan efectivo de quien llama (cuenta, agente o dueño). Lo consumen la app
    y el agente con el MISMO contrato. A una cuenta nueva le inicia la prueba Pro."""
    ent = _compute_entitlement(p.org_token, _now())
    ent["org"] = p.org_token  # el móvil lo muestra para soporte / admin manual
    # MSP: ¿esta cuenta es un SOCIO? La app le muestra la Consola de Socio SOLO si
    # esto es true (a los usuarios normales nunca les aparece).
    ent["is_partner"] = _is_partner(p.org_token)
    ent["partner_clients"] = len(_partner_clients(p.org_token)) if ent["is_partner"] else 0
    # ¿Esta cuenta (cliente) está gestionada por un socio? (se vinculó con un
    # código). La app se lo muestra y le permite revocar el acceso.
    ent["managed_by_partner"] = bool(store.kv_get(f"managed_by::{p.org_token}"))
    return ent


@app.get("/v1/entitlement/pubkey")
def entitlement_pubkey() -> dict:
    """Llave PÚBLICA (Ed25519, PEM) con la que el agente y el móvil verifican el
    **permiso firmado**. Pública a propósito: no permite falsificar, solo
    verificar. Sin auth (el cliente la fija en su primer contacto)."""
    from signing import public_key_pem
    return {"alg": "EdDSA", "public_key": public_key_pem(store)}


class AdminEntitlementIn(BaseModel):
    org_token: str = Field(min_length=1, max_length=200)
    plan: str = Field(pattern="^(free|trial|pro)$")
    trial_days: int | None = Field(default=None, ge=0, le=3650)


def require_admin(authorization: str | None = Header(default=None)) -> bool:
    """Super-admin (el dueño del negocio) por `ADMIN_TOKEN`. Sin la variable
    configurada, el endpoint queda cerrado (nadie puede marcarse Pro solo)."""
    if not ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Admin deshabilitado")
    if not authorization or authorization.strip() != f"Bearer {ADMIN_TOKEN}":
        raise HTTPException(status_code=403, detail="Requiere token de super-admin")
    return True


# ─────────────────── MSP: Consola de socio (multi-cliente) ───────────────────
# Modelo PROFESIONAL basado en CUENTA (no en tokens demo): un socio (MSP) es una
# cuenta normal MARCADA como socio por el dueño. Al iniciar sesión, la app detecta
# `is_partner` y le muestra su consola automáticamente. El socio PROVISIONA a sus
# clientes: crea una organización-cliente aislada y obtiene un token de agente
# para instalar en la sede del cliente. Cada cliente reporta a SU propia org.
def _is_partner(org: str) -> bool:
    return store.kv_get(f"is_partner::{org}") == "1"


def _partner_clients(org: str) -> list[dict]:
    """[{org, name}] de las organizaciones-cliente que gestiona el socio."""
    raw = store.kv_get(f"partner_clients::{org}")
    return json.loads(raw) if raw else []


def _set_partner_clients(org: str, items: list[dict]) -> None:
    store.kv_set(f"partner_clients::{org}", json.dumps(items))


def require_partner_account(p: Principal = Depends(principal)) -> Principal:
    """La cuenta que llama debe estar marcada como SOCIO (MSP). Sin token que pegar:
    la identidad es su sesión."""
    if not _is_partner(p.org_token):
        raise HTTPException(status_code=403,
                            detail="Tu cuenta no es una cuenta de socio (MSP)")
    return p


class PartnerClientIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)


class PartnerInviteIn(BaseModel):
    name: str = Field(default="", max_length=120)


class PartnerJoinIn(BaseModel):
    code: str = Field(min_length=4, max_length=40)


class PartnerFlagIn(BaseModel):
    """El dueño promueve/quita a una cuenta como socio (MSP)."""
    org: str = Field(min_length=1, max_length=200)
    is_partner: bool = True


def _plan_readonly(org: str, now: datetime) -> str:
    """Plan efectivo SIN mutar el almacén (para vistas de solo lectura del panel).
    A diferencia de `_compute_entitlement`, NO crea la prueba a una cuenta nueva."""
    if org in OWNER_ORGS:
        return "pro"
    ent = store.get_entitlement(org)
    if ent is None:
        return "trial"  # cuenta que aún no consultó su plan → prueba por defecto
    plan = ent.get("plan", "free")
    trial_ends_at = ent.get("trial_ends_at")
    if trial_ends_at is not None and getattr(trial_ends_at, "tzinfo", None) is None:
        trial_ends_at = trial_ends_at.replace(tzinfo=timezone.utc)
    if plan == "pro":
        return "pro"
    if plan == "trial":
        return "pro" if (trial_ends_at and now < trial_ends_at) else "free"
    return "free"


def _aggregate_fleet(now: datetime, only_orgs: set[str] | None = None) -> dict:
    """Agrega TODAS las sedes por cuenta (org) → salud por cuenta. Si `only_orgs`
    se pasa, limita a esas organizaciones (base tanto del panel del DUEÑO como de
    la Consola de SOCIO/MSP, que ven el mismo agregado sobre distinto alcance)."""
    orgs: dict[str, dict] = {}
    for org, _site_id, rec in store.iter_sites_all():
        if only_orgs is not None and org not in only_orgs:
            continue
        summ = rec.get("summary") or {}
        updated = rec.get("updated_at")
        online = updated is not None and (
            now - updated).total_seconds() <= ONLINE_WINDOW_SECONDS
        o = orgs.setdefault(org, {
            "org": org, "sites": 0, "sites_online": 0, "devices": 0,
            "alerts": 0, "criticals_down": 0, "last_seen": None,
        })
        o["sites"] += 1
        o["sites_online"] += 1 if online else 0
        o["devices"] += int(summ.get("devices_total", 0) or 0)
        o["alerts"] += int(summ.get("alerts", 0) or 0)
        o["criticals_down"] += int(summ.get("criticals_down", 0) or 0)
        if updated is not None and (o["last_seen"] is None or updated > o["last_seen"]):
            o["last_seen"] = updated
    # Cuentas asignadas SIN sedes reportando aún (aparecen offline, no invisibles).
    if only_orgs is not None:
        for org in only_orgs:
            orgs.setdefault(org, {
                "org": org, "sites": 0, "sites_online": 0, "devices": 0,
                "alerts": 0, "criticals_down": 0, "last_seen": None,
            })

    fleet: list[dict] = []
    dist = {"free": 0, "trial": 0, "pro": 0}
    for org, o in orgs.items():
        plan = _plan_readonly(org, now)
        dist[plan] = dist.get(plan, 0) + 1
        any_online = o["sites_online"] > 0
        last = o["last_seen"]
        fleet.append({
            **o,
            "plan": plan,
            "online": any_online,
            "needs_attention": (not any_online) or o["criticals_down"] > 0 or o["alerts"] > 0,
            "last_seen": last.isoformat() if last else None,
            "seconds_since_seen": int((now - last).total_seconds()) if last else None,
            "is_partner": _is_partner(org),  # ¿esta cuenta es socio? (para el botón)
        })
    fleet.sort(key=lambda f: (
        0 if not f["online"] else 1,
        0 if f["criticals_down"] else 1,
        0 if f["alerts"] else 1,
        -f["devices"],
    ))
    totals = {
        "accounts": len(orgs),
        "accounts_online": sum(1 for f in fleet if f["online"]),
        "accounts_attention": sum(1 for f in fleet if f["needs_attention"]),
        "sites": sum(o["sites"] for o in orgs.values()),
        "devices": sum(o["devices"] for o in orgs.values()),
        "alerts": sum(o["alerts"] for o in orgs.values()),
        "plans": dist,
    }
    return {"fleet": fleet, "totals": totals, "generated_at": now.isoformat()}


@app.get("/v1/admin/fleet")
def admin_fleet(_: bool = Depends(require_admin)) -> dict:
    """**Panel de FLOTA del dueño** (solo super-admin). Vista de TODAS las cuentas
    con AGREGADOS por cuenta: sedes, equipos, alertas, plan, y si el agente está
    en línea — para dar soporte y ver problemas de raíz. NO expone el inventario
    (equipos/MACs) de la red de ningún cliente: soporte sin vigilar."""
    return _aggregate_fleet(_now())


@app.post("/v1/admin/partner-flag")
def admin_partner_flag(body: PartnerFlagIn, _: bool = Depends(require_admin)) -> dict:
    """**MSP:** el dueño PROMUEVE (o quita) una cuenta como socio. `org` es el
    org_token de la cuenta (lo ve la cuenta en 'Mi cuenta' / lo entrega el panel
    de flota). Sin tokens demo: la identidad del socio es su propia sesión."""
    store.kv_set(f"is_partner::{body.org}", "1" if body.is_partner else "0")
    return {"ok": True, "org": body.org, "is_partner": body.is_partner}


@app.delete("/v1/admin/org/{org_token}")
def admin_purge_org(org_token: str, _: bool = Depends(require_admin)) -> dict:
    """**Limpieza (super-admin):** purga TODOS los datos de una org del panel — sus
    sedes y las claves asociadas (config, vigilancia, socio). Sirve para eliminar
    orgs FANTASMA: p. ej. un token de agente revocado que estuvo reportando como su
    propia org. No afecta cuentas reales salvo que se les pase su org a propósito."""
    removed = 0
    for site_id, _rec in list(store.list_sites(org_token)):
        if store.remove_site(org_token, site_id):
            removed += 1
    # Claves asociadas (best-effort): que no quede rastro del fantasma.
    for key in (f"managed_by::{org_token}", f"is_partner::{org_token}",
                f"partner_clients::{org_token}"):
        store.kv_set(key, "")
    try:
        store.set_alert_topic(org_token, None)
    except Exception:
        pass
    _SITE_WATCH.pop(org_token, None)
    return {"ok": True, "org": org_token, "sites_removed": removed}


@app.post("/v1/partner/clients")
def partner_create_client(
    body: PartnerClientIn, p: Principal = Depends(require_partner_account)
) -> dict:
    """El socio PROVISIONA un cliente: crea una organización-cliente AISLADA y
    devuelve un **token de agente** para instalar en la sede de ese cliente. Cada
    cliente reporta a su propia org → datos separados."""
    client_org = "client_" + secrets.token_urlsafe(16)
    agent_token = AGENT_TOKEN_PREFIX + secrets.token_urlsafe(24)
    store.create_agent_token(client_org, agent_token, body.name.strip(), _now())
    items = _partner_clients(p.org_token)
    items.append({"org": client_org, "name": body.name.strip()})
    _set_partner_clients(p.org_token, items)
    return {"ok": True, "client_org": client_org,
            "agent_token": agent_token, "name": body.name.strip()}


@app.get("/v1/partner/clients")
def partner_clients(p: Principal = Depends(require_partner_account)) -> dict:
    """**Consola de socio (MSP):** salud agregada de las organizaciones-cliente
    del socio (las que él provisionó), en un solo panel. Reutiliza la agregación
    de flota. NO expone inventario/MACs de ningún cliente."""
    items = _partner_clients(p.org_token)
    names = {it.get("org"): it.get("name", "") for it in items}
    agg = _aggregate_fleet(_now(), only_orgs=set(names.keys()))
    for f in agg["fleet"]:
        f["client_name"] = names.get(f["org"], "")
    return {**agg, "partner_name": p.name or "Socio"}


@app.delete("/v1/partner/clients/{client_org}")
def partner_remove_client(
    client_org: str, p: Principal = Depends(require_partner_account)
) -> dict:
    """El socio deja de gestionar un cliente: lo quita de su cartera, REVOCA los
    tokens de agente del cliente (deja de reportar) y borra sus sedes del panel.
    Solo puede eliminar clientes que él mismo provisionó."""
    items = _partner_clients(p.org_token)
    if not any(it.get("org") == client_org for it in items):
        raise HTTPException(status_code=404, detail="Cliente no está en tu cartera")
    _set_partner_clients(
        p.org_token, [it for it in items if it.get("org") != client_org])
    # Revoca los tokens de agente del cliente → sus agentes dejan de reportar.
    for t in store.list_agent_tokens(client_org):
        tok = t.get("token")
        if tok:
            store.revoke_agent_token(client_org, tok)
    # Limpia sus sedes del panel + el estado del watchdog de esa org.
    for site_id, _rec in store.list_sites(client_org):
        store.remove_site(client_org, site_id)
    with _WATCH_LOCK:
        _SITE_WATCH.pop(client_org, None)
    return {"ok": True}


@app.post("/v1/partner/invite")
def partner_invite(
    body: PartnerInviteIn, p: Principal = Depends(require_partner_account)
) -> dict:
    """El socio genera un **código de invitación** para un cliente. Se lo envía; el
    cliente lo pega en SU app (`/v1/partner/join`) y así vincula su red al socio —
    con su propia cuenta y su consentimiento. No hace falta ir a la sede."""
    code = "RP-" + secrets.token_hex(4).upper()  # p.ej. RP-1A2B3C4D
    store.kv_set(f"pinvite::{code}", json.dumps(
        {"partner_org": p.org_token, "partner_name": p.name or "Socio",
         "name": body.name.strip()}))
    return {"ok": True, "code": code, "name": body.name.strip()}


@app.post("/v1/partner/join")
def partner_join(body: PartnerJoinIn, p: Principal = Depends(principal)) -> dict:
    """El CLIENTE pega el código en su app → vincula SU organización (su red) al
    socio que lo invitó, dándole acceso. Código de un solo uso."""
    code = body.code.strip().upper()
    raw = store.kv_get(f"pinvite::{code}")
    if not raw:
        raise HTTPException(status_code=404, detail="Código no válido o ya usado")
    inv = json.loads(raw)
    partner_org = inv.get("partner_org")
    name = inv.get("name") or "Cliente"
    if partner_org == p.org_token:
        raise HTTPException(status_code=400, detail="No puedes vincularte a ti mismo")
    items = _partner_clients(partner_org)
    if not any(it.get("org") == p.org_token for it in items):
        items.append({"org": p.org_token, "name": name})
        _set_partner_clients(partner_org, items)
    # El cliente sabe quién lo gestiona (transparencia); consume el código.
    store.kv_set(f"managed_by::{p.org_token}", partner_org)
    store.kv_set(f"pinvite::{code}", "")  # un solo uso
    return {"ok": True, "partner_name": inv.get("partner_name") or "tu proveedor"}


@app.post("/v1/partner/leave")
def partner_leave(p: Principal = Depends(principal)) -> dict:
    """El CLIENTE revoca el acceso de su proveedor: se saca de la cartera del socio
    y limpia la relación. (El cliente manda sobre su propia red.)"""
    partner_org = store.kv_get(f"managed_by::{p.org_token}")
    if partner_org:
        items = _partner_clients(partner_org)
        _set_partner_clients(
            partner_org, [it for it in items if it.get("org") != p.org_token])
        store.kv_set(f"managed_by::{p.org_token}", "")
    return {"ok": True}


@app.put("/v1/admin/entitlement")
def admin_set_entitlement(
    body: AdminEntitlementIn, _: bool = Depends(require_admin)
) -> dict:
    """Marca el plan de una organización a mano (mientras no hay cobro
    automático). Solo el super-admin (ADMIN_TOKEN). `pro` = control ilimitado;
    `trial` = Pro por `trial_days` (o TRIAL_DAYS); `free` = solo ver."""
    now = _now()
    trial_end = None
    if body.plan == "trial":
        days = body.trial_days if body.trial_days is not None else TRIAL_DAYS
        trial_end = now + timedelta(days=days)
    store.set_entitlement(body.org_token, body.plan, trial_end)
    return {"ok": True, "entitlement": _compute_entitlement(body.org_token, now)}


# ─────────────────── Auth-3C: Google Play Billing ───────────────────
RTDN_SECRET = os.environ.get("RTDN_SECRET", "").strip()


class PlayVerifyIn(BaseModel):
    purchase_token: str = Field(min_length=8, max_length=4096)
    product_id: str = Field(default="", max_length=200)


@app.get("/v1/billing/play/config")
def play_billing_config() -> dict:
    """¿El cobro por Google Play está activo en el relay? (sin secretos). El móvil
    lo usa para mostrar u ocultar el botón de compra."""
    from billing_play import is_configured
    return {"enabled": is_configured()}


@app.post("/v1/billing/play/verify")
def play_verify(body: PlayVerifyIn, p: Principal = Depends(principal)) -> dict:
    """El móvil (Play) manda su `purchaseToken`; el relay lo VERIFICA con Google y,
    si la suscripción está activa, marca esta cuenta como Pro. Server-side: el
    cliente no puede autoconcederse Pro."""
    from billing_play import is_configured, verify_subscription
    if not is_configured():
        raise HTTPException(status_code=503, detail="billing_not_configured")
    result = verify_subscription(body.purchase_token)
    if result is None:
        raise HTTPException(status_code=502, detail="verification_failed")
    now = _now()
    if result.get("active"):
        # Guarda el vínculo token→org para que las RTDN futuras sepan a quién
        # aplicar la renovación/cancelación.
        try:
            store.kv_set(f"play_sub:{body.purchase_token}", p.org_token)
        except Exception:  # noqa: BLE001
            pass
        store.set_entitlement(p.org_token, "pro", None)
    return {
        "ok": bool(result.get("active")),
        "state": result.get("state"),
        "entitlement": _compute_entitlement(p.org_token, now),
    }


@app.post("/v1/billing/play/rtdn")
def play_rtdn(payload: dict, secret: str = "") -> dict:
    """Notificación en tiempo real de Google (Pub/Sub). Re-verifica la suscripción
    y actualiza el plan de la cuenta ligada al token. Siempre responde 200 para
    que Pub/Sub confirme (evita reintentos infinitos)."""
    from billing_play import decode_rtdn, verify_subscription
    # Si se configuró un secreto compartido, exígelo (query ?secret=...).
    if RTDN_SECRET and secret != RTDN_SECRET:
        raise HTTPException(status_code=403, detail="bad_secret")
    note = decode_rtdn(payload) or {}
    sub = note.get("subscriptionNotification") or {}
    token = sub.get("purchaseToken")
    if not token:
        return {"ok": True, "ignored": "no_token"}
    org = None
    try:
        org = store.kv_get(f"play_sub:{token}")
    except Exception:  # noqa: BLE001
        org = None
    if not org:
        return {"ok": True, "ignored": "unknown_token"}
    result = verify_subscription(token)
    if result is None:
        return {"ok": True, "ignored": "verify_unavailable"}
    store.set_entitlement(org, "pro" if result.get("active") else "free", None)
    return {"ok": True, "active": bool(result.get("active"))}
