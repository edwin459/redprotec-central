"""Túnel inverso relay↔agente — acceso remoto SIN ngrok.

Problema que resuelve: cuando el teléfono sale de la WiFi de casa (datos móviles u
otra red) ya no alcanza al agente (detrás de NAT, sin IP pública). Antes se usaba
ngrok, pero se abandonó → el acceso remoto quedó muerto.

Idea: el relay ya está SIEMPRE encendido (Railway) y el agente ya le habla por el
latido. Aquí el agente abre además un WebSocket SALIENTE persistente al relay. La
app, cuando está fuera de casa, envía sus peticiones al relay; el relay las
reenvía por ese WebSocket al agente, que las ejecuta contra su API local y
responde de vuelta. Así TODAS las pestañas funcionan igual en casa o con datos,
sin túneles por-agente ni puertos abiertos, y escala a miles de agentes.

Este módulo es PURO (sin FastAPI): solo el registro de conexiones y la
correlación petición↔respuesta. Los endpoints (WebSocket del agente + proxy de la
app) viven en main.py, que ya tiene `principal`/`store`.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import secrets
import uuid

logger = logging.getLogger("redprotec.central.tunnel")

# Cabeceras "salto a salto" que NO deben reenviarse (las gestiona cada conexión).
# Se filtran en AMBOS sentidos para no arrastrar longitudes/codificados obsoletos.
HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length",
    "x-tunnel-key",
})

# Techo del cuerpo que se transporta por el túnel (petición y respuesta). Un PDF de
# reporte cabe de sobra; evita que un cuerpo gigante sature un frame de WebSocket.
MAX_BODY_BYTES = 12 * 1024 * 1024


class TunnelConn:
    """Una conexión de agente viva. Serializa los envíos por el WS y correla cada
    respuesta con su petición por `id`."""

    __slots__ = ("ws", "org", "agent_id", "resolve_token", "pending", "_send_lock",
                 "alive")

    def __init__(self, ws, org: str, agent_id: str, resolve_token: str):
        self.ws = ws
        self.org = org
        self.agent_id = agent_id
        self.resolve_token = resolve_token
        self.pending: dict[str, asyncio.Future] = {}
        self._send_lock = asyncio.Lock()
        self.alive = True

    def match_key(self, provided: str | None) -> bool:
        """Compara en tiempo constante la clave de túnel que trae la app contra el
        `resolve_token` que el agente registró (ambos vienen del emparejamiento QR).
        Sin `resolve_token` registrado → se rechaza (falla cerrado)."""
        if not self.resolve_token or not provided:
            return False
        return secrets.compare_digest(str(provided), str(self.resolve_token))

    async def send_json(self, data: dict) -> None:
        async with self._send_lock:
            await self.ws.send_text(json.dumps(data))

    def resolve_response(self, data: dict) -> None:
        fut = self.pending.get(data.get("id"))
        if fut is not None and not fut.done():
            fut.set_result(data)

    def fail_all(self, exc: Exception) -> None:
        for fut in list(self.pending.values()):
            if not fut.done():
                fut.set_exception(exc)
        self.pending.clear()


class TunnelHub:
    """Registro de agentes conectados, indexado por `agent_id` (la identidad
    estable del agente = el `site_id` del latido)."""

    def __init__(self) -> None:
        self._conns: dict[str, TunnelConn] = {}

    def register(self, conn: TunnelConn) -> None:
        # Si ya había una conexión previa para el mismo agente (reconexión tras un
        # corte), se descarta la vieja: la nueva es la fuente de verdad.
        old = self._conns.get(conn.agent_id)
        if old is not None and old is not conn:
            old.alive = False
            old.fail_all(ConnectionError("reemplazada por una conexión nueva"))
        self._conns[conn.agent_id] = conn
        logger.info("Túnel registrado: agente=%s org=%s (total=%d)",
                    conn.agent_id, conn.org, len(self._conns))

    def unregister(self, conn: TunnelConn) -> None:
        current = self._conns.get(conn.agent_id)
        if current is conn:
            self._conns.pop(conn.agent_id, None)
            logger.info("Túnel cerrado: agente=%s (total=%d)",
                        conn.agent_id, len(self._conns))

    def get(self, agent_id: str) -> TunnelConn | None:
        return self._conns.get(agent_id)

    def count(self) -> int:
        return len(self._conns)

    async def request(
        self,
        conn: TunnelConn,
        *,
        method: str,
        path: str,
        query: str,
        headers: dict[str, str],
        body: bytes,
        timeout: float = 30.0,
    ) -> dict:
        """Envía UNA petición al agente por el túnel y espera su respuesta.

        Devuelve el frame `resp` crudo: {status, headers, body_b64}. Lanza
        asyncio.TimeoutError si el agente no responde a tiempo, o ConnectionError
        si la conexión murió mientras se esperaba.
        """
        if not conn.alive:
            raise ConnectionError("el túnel del agente no está activo")
        rid = uuid.uuid4().hex
        loop = asyncio.get_event_loop()
        fut: asyncio.Future = loop.create_future()
        conn.pending[rid] = fut
        frame = {
            "type": "req",
            "id": rid,
            "method": method,
            "path": path,
            "query": query,
            "headers": headers,
            "body_b64": base64.b64encode(body).decode("ascii") if body else "",
        }
        try:
            await conn.send_json(frame)
            return await asyncio.wait_for(fut, timeout)
        finally:
            conn.pending.pop(rid, None)


def filter_request_headers(headers: dict[str, str]) -> dict[str, str]:
    """Cabeceras de la app que SÍ se reenvían al agente (se descartan las de salto
    a salto y la clave de túnel, que es solo para el relay)."""
    return {k: v for k, v in headers.items() if k.lower() not in HOP_BY_HOP}


def filter_response_headers(headers: dict[str, str]) -> dict[str, str]:
    """Cabeceras de la respuesta del agente que se devuelven a la app (Starlette
    recalcula Content-Length/Transfer-Encoding)."""
    return {k: v for k, v in headers.items() if k.lower() not in HOP_BY_HOP}
