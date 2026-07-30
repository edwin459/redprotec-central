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

import os
import threading
import urllib.request
import uuid
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from auth import verify_supabase_jwt
from store import create_store

app = FastAPI(title="RedProtec Central Relay", version="0.4.0")

ONLINE_WINDOW_SECONDS = int(os.environ.get("ONLINE_WINDOW_SECONDS", "150"))
# Comandos que el agente no recoge en este tiempo se descartan (evita que una
# orden vieja se ejecute cuando la sede vuelva días después).
COMMAND_TTL_SECONDS = int(os.environ.get("COMMAND_TTL_SECONDS", "600"))

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

# Almacén activo. Con DATABASE_URL → Postgres (Supabase, persistente). Sin ella →
# MemoryStore sobre LOS MISMOS dicts de arriba (fallback gratis + tests). Los
# endpoints usan `store.*`; los dicts quedan como respaldo en memoria y para que
# los tests que los tocan directamente sigan funcionando igual.
store = create_store(_STORE, _COMMANDS, _ORG_CONFIG, _ACCESS, _LOCK)

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


def _push_ntfy(topic: str | None, title: str, message: str, *, priority: str, tags: str) -> None:
    """Envía un push a ntfy (best-effort). El relay es el ÚNICO que ve todas las
    sedes 24/7, así que es el lugar correcto para alertar al dueño de la org."""
    if not topic or not topic.strip():
        return
    t = topic.strip()
    url = t if t.startswith("http") else f"https://ntfy.sh/{t}"
    safe_title = title.encode("ascii", "ignore").decode().strip() or "RedProtec"
    try:
        req = urllib.request.Request(
            url,
            data=message.encode("utf-8"),
            method="POST",
            headers={"Title": safe_title, "Priority": priority, "Tags": tags},
        )
        urllib.request.urlopen(req, timeout=8)  # noqa: S310
    except Exception:
        pass


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


@app.get("/stats")
def stats() -> dict:
    """Contadores (best-effort). Si la base aún no responde, devuelve nulls sin
    romper — no es un endpoint de liveness."""
    try:
        orgs, sites = store.stats()
        return {"status": "ok", "orgs": orgs, "sites": sites}
    except Exception:  # noqa: BLE001
        return {"status": "db_unavailable", "orgs": None, "sites": None}


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

    return {"ok": True, "commands": pending}


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


@app.get("/v1/org/config")
def get_org_config(p: Principal = Depends(require_master)) -> dict:
    cfg = store.get_org_config(p.org_token)
    return {"alert_topic": cfg.get("alert_topic")}


@app.post("/v1/org/config")
def set_org_config(cfg: OrgConfigIn, p: Principal = Depends(require_master)) -> dict:
    store.set_alert_topic(p.org_token, (cfg.alert_topic or "").strip() or None)
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
