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

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from auth import verify_supabase_jwt
from store import create_store

logger = logging.getLogger("redprotec.central")

# ── Watchdog de sedes: el relay es el ÚNICO que ve TODAS las sedes 24/7 y tiene
# internet propio. Cuando una sede deja de latir (se le cayó el internet o se
# apagó el agente), NADIE más puede avisarlo a tiempo — el push del agente no
# saldría porque su propia conexión está caída. El relay sí. Detecta la
# transición en-línea→sin-conexión y avisa al tema de la organización.
OFFLINE_ALERT_SECONDS = int(os.environ.get("OFFLINE_ALERT_SECONDS", "210"))
WATCHDOG_INTERVAL_SECONDS = int(os.environ.get("WATCHDOG_INTERVAL_SECONDS", "60"))
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


app = FastAPI(title="RedProtec Central Relay", version="0.9.6", lifespan=lifespan)

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
    return emitted


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
    token = "rp_agent_" + secrets.token_urlsafe(24)
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


@app.get("/v1/admin/fleet")
def admin_fleet(_: bool = Depends(require_admin)) -> dict:
    """**Panel de FLOTA del dueño** (solo super-admin). Vista de TODAS las cuentas
    con AGREGADOS por cuenta: sedes, equipos, alertas, plan, y si el agente está
    en línea — para dar soporte y ver problemas de raíz. NO expone el inventario
    (equipos/MACs) de la red de ningún cliente: soporte sin vigilar. La salud por
    cuenta permite priorizar (sin conexión / críticos caídos / alertas)."""
    now = _now()
    orgs: dict[str, dict] = {}
    for org, _site_id, rec in store.iter_sites_all():
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
        })
    # Peor salud primero: sin conexión → críticos caídos → alertas → más equipos.
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
