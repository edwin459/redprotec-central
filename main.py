"""RedProtec — Relay central de MULTI-SEDE.

Cada agente (sede) manda un "latido" con un RESUMEN y, si la organización activó
el modo, también un INVENTARIO (equipos con nombre/fabricante/IP/MAC/estado). La
app lee todas las sedes, entra al detalle de una y puede ENVIAR COMANDOS
(bloquear/confiar/desbloquear) que el agente recoge en su siguiente latido y
ejecuta localmente — así se administra a distancia aunque el agente esté detrás
de NAT.

Diseño para free tier: estado EN MEMORIA (sin base de datos). Si el host
reinicia, las sedes se re-registran solas en el siguiente latido. Multi-tenant
por `org_token` (Authorization: Bearer). Migración a pago = cambiar el almacén.
"""

from __future__ import annotations

import os
import threading
import urllib.request
import uuid
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="RedProtec Central Relay", version="0.3.0")

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
    with _LOCK:
        orgs = len(_STORE)
        sites = sum(len(v) for v in _STORE.values())
    return {"status": "ok", "version": app.version, "orgs": orgs, "sites": sites}


@app.post("/v1/heartbeat")
def heartbeat(hb: Heartbeat, org_token: str = Depends(require_org_token)) -> dict:
    """El agente reporta su sede y recoge comandos pendientes en la respuesta."""
    now = _now()
    alert_topic = None
    alerts: list[tuple[str, str, str, str]] = []  # (title, msg, priority, tags)
    with _LOCK:
        org = _STORE.setdefault(org_token, {})
        prev = org.get(hb.site_id)
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

        org[hb.site_id] = {
            "site_name": hb.site_name,
            "summary": new_summary,
            "devices": new_devices if new_devices is not None else prev_devices,
            "remote_admin": hb.remote_admin,
            "updated_at": now,
        }
        if alerts:
            alert_topic = _ORG_CONFIG.get(org_token, {}).get("alert_topic")

        pending: list[dict] = []
        if hb.remote_admin:
            q = _COMMANDS.get(org_token, {}).get(hb.site_id, [])
            fresh = [c for c in q if (now - c["created_at"]).total_seconds() <= COMMAND_TTL_SECONDS]
            _COMMANDS.setdefault(org_token, {})[hb.site_id] = fresh
            pending = [
                {"id": c["id"], "action": c["action"], "mac": c["mac"], "value": c.get("value")}
                for c in fresh
            ]

    # Enviar pushes fuera del lock (I/O de red).
    for title, msg, prio, tags in alerts:
        _push_ntfy(alert_topic, title, msg, priority=prio, tags=tags)

    return {"ok": True, "commands": pending}


@app.get("/v1/sites")
def list_sites(org_token: str = Depends(require_org_token)) -> dict:
    now = _now()
    out: list[dict] = []
    with _LOCK:
        org = _STORE.get(org_token, {})
        for site_id, rec in org.items():
            out.append(_site_out(site_id, rec, now))

    def _severity(s: dict) -> tuple:
        return (
            0 if not s["online"] else 1,
            0 if s["summary"]["criticals_down"] > 0 else 1,
            0 if s["summary"]["alerts"] > 0 else 1,
            s["site_name"].lower(),
        )

    out.sort(key=_severity)
    return {"sites": out}


@app.get("/v1/sites/{site_id}")
def site_detail(site_id: str, org_token: str = Depends(require_org_token)) -> dict:
    now = _now()
    with _LOCK:
        rec = _STORE.get(org_token, {}).get(site_id)
        if not rec:
            raise HTTPException(status_code=404, detail="Sede no encontrada")
        base = _site_out(site_id, rec, now)
        base["devices"] = rec.get("devices") or []
    return base


@app.post("/v1/sites/{site_id}/commands")
def enqueue_command(
    site_id: str, cmd: CommandIn, org_token: str = Depends(require_org_token)
) -> dict:
    """La app encola un comando; el agente lo recoge en su próximo latido."""
    now = _now()
    with _LOCK:
        rec = _STORE.get(org_token, {}).get(site_id)
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
        _COMMANDS.setdefault(org_token, {}).setdefault(site_id, []).append(command)
    return {"ok": True, "command_id": command["id"]}


@app.post("/v1/commands/{command_id}/ack")
def ack_command(
    command_id: str,
    site_id: str = Header(default="", alias="X-Site-Id"),
    org_token: str = Depends(require_org_token),
) -> dict:
    """El agente confirma que ejecutó un comando; se retira de la cola."""
    with _LOCK:
        q = _COMMANDS.get(org_token, {}).get(site_id, [])
        _COMMANDS.setdefault(org_token, {})[site_id] = [
            c for c in q if c["id"] != command_id
        ]
    return {"ok": True}


# ─────────────────────── config de la organización ───────────────────────
class OrgConfigIn(BaseModel):
    alert_topic: str | None = None  # tema ntfy para alertas por sede


@app.get("/v1/org/config")
def get_org_config(org_token: str = Depends(require_org_token)) -> dict:
    with _LOCK:
        cfg = dict(_ORG_CONFIG.get(org_token, {}))
    return {"alert_topic": cfg.get("alert_topic")}


@app.post("/v1/org/config")
def set_org_config(cfg: OrgConfigIn, org_token: str = Depends(require_org_token)) -> dict:
    with _LOCK:
        store = _ORG_CONFIG.setdefault(org_token, {})
        store["alert_topic"] = (cfg.alert_topic or "").strip() or None
    return {"ok": True}


# ─────────────────────── inteligencia cruzada ───────────────────────
@app.get("/v1/insights")
def insights(org_token: str = Depends(require_org_token)) -> dict:
    """**Intruso itinerante**: equipos NO confiables (unknown) cuya misma MAC
    aparece en 2+ sedes. Solo posible con visión multi-sede — el diferenciador.
    Requiere que esas sedes tengan inventario completo activado."""
    now = _now()
    # mac -> { name, sites:set, trust }
    seen: dict[str, dict] = {}
    with _LOCK:
        org = _STORE.get(org_token, {})
        for site_id, rec in org.items():
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
def global_inventory(org_token: str = Depends(require_org_token)) -> dict:
    """Inventario CONSOLIDADO: todos los equipos de todas las sedes (para buscar
    un equipo across la organización / exportar). Requiere inventario por sede."""
    out: list[dict] = []
    with _LOCK:
        org = _STORE.get(org_token, {})
        for site_id, rec in org.items():
            for d in (rec.get("devices") or []):
                out.append({**d, "site_id": site_id, "site_name": rec["site_name"]})
    out.sort(key=lambda d: (d["site_name"].lower(), 0 if d.get("online") else 1, (d.get("name") or "").lower()))
    return {"devices": out, "total": len(out)}
