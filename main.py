"""RedProtec — Relay central de MULTI-SEDE (MVP).

Punto único al que cada agente (sede) manda un "latido" con un RESUMEN (nunca
IPs/MACs individuales) y desde el que la app lee todas las sedes de una
organización.

Diseño para free tier:
  - Sin base de datos: estado EN MEMORIA. Si el host reinicia, las sedes se
    vuelven a registrar solas en el siguiente latido (~30-60 s). Simple y barato.
  - Multi-tenant por `org_token`: cada organización solo ve SUS sedes. El token
    es un secreto compartido (Authorization: Bearer <org_token>) — auth mínima
    pero real; se endurece al pasar a pago.
  - "En línea" de una sede = latido recibido dentro de ONLINE_WINDOW.

Migración a pago: misma API; solo se cambia el almacén (memoria → Postgres) y el
host. El agente y la app no cambian.
"""

from __future__ import annotations

import os
import threading
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="RedProtec Central Relay", version="0.1.0")

# Una sede se considera EN LÍNEA si mandó latido en los últimos N segundos.
ONLINE_WINDOW_SECONDS = int(os.environ.get("ONLINE_WINDOW_SECONDS", "150"))

# Almacén en memoria: org_token -> { site_id -> record }. Protegido por lock.
_LOCK = threading.Lock()
_STORE: dict[str, dict[str, dict]] = {}


class SiteSummary(BaseModel):
    """RESUMEN de una sede — sin datos sensibles por equipo."""

    devices_total: int = 0
    devices_online: int = 0
    alerts: int = 0            # desconocidos / intrusos
    criticals_total: int = 0
    criticals_down: int = 0
    protection_mode: str = "unknown"  # guardian | explore | offline
    network_name: str | None = None


class Heartbeat(BaseModel):
    site_id: str = Field(min_length=1, max_length=128)
    site_name: str = Field(min_length=1, max_length=120)
    summary: SiteSummary = SiteSummary()


class SiteOut(BaseModel):
    site_id: str
    site_name: str
    online: bool
    updated_at: str
    seconds_since_update: int
    summary: SiteSummary


def _now() -> datetime:
    return datetime.now(timezone.utc)


def require_org_token(authorization: str | None = Header(default=None)) -> str:
    """Extrae el org_token del header Authorization: Bearer <token>."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Falta el token de organización")
    token = authorization[7:].strip()
    if len(token) < 8:
        raise HTTPException(status_code=401, detail="Token inválido")
    return token


@app.get("/health")
def health() -> dict:
    with _LOCK:
        orgs = len(_STORE)
        sites = sum(len(v) for v in _STORE.values())
    return {"status": "ok", "orgs": orgs, "sites": sites}


@app.post("/v1/heartbeat")
def heartbeat(hb: Heartbeat, org_token: str = Depends(require_org_token)) -> dict:
    """El agente reporta el estado de SU sede. Upsert por (org_token, site_id)."""
    with _LOCK:
        org = _STORE.setdefault(org_token, {})
        org[hb.site_id] = {
            "site_name": hb.site_name,
            "summary": hb.summary.model_dump(),
            "updated_at": _now(),
        }
    return {"ok": True}


@app.get("/v1/sites")
def list_sites(org_token: str = Depends(require_org_token)) -> dict:
    """La app lee TODAS las sedes de la organización, ordenadas: problemas
    primero (caídas / con críticos abajo / con alertas), luego por nombre."""
    now = _now()
    out: list[SiteOut] = []
    with _LOCK:
        org = _STORE.get(org_token, {})
        for site_id, rec in org.items():
            delta = int((now - rec["updated_at"]).total_seconds())
            summary = SiteSummary(**rec["summary"])
            out.append(
                SiteOut(
                    site_id=site_id,
                    site_name=rec["site_name"],
                    online=delta <= ONLINE_WINDOW_SECONDS,
                    updated_at=rec["updated_at"].isoformat(),
                    seconds_since_update=delta,
                    summary=summary,
                )
            )

    def _severity(s: SiteOut) -> tuple:
        # Menor = más arriba. Sede caída, con críticos abajo o con alertas manda.
        return (
            0 if not s.online else 1,
            0 if s.summary.criticals_down > 0 else 1,
            0 if s.summary.alerts > 0 else 1,
            s.site_name.lower(),
        )

    out.sort(key=_severity)
    return {"sites": [s.model_dump() for s in out]}
