"""Tests del túnel inverso relay↔agente (acceso remoto sin ngrok).

Lógica pura del hub (registro + correlación petición/respuesta) y el gate de
seguridad del proxy. Sin red real: se simula el WebSocket del agente con un doble.
"""
from __future__ import annotations

import asyncio
import base64
import json
import unittest

import main
from tunnel import TunnelConn, TunnelHub


class FakeWS:
    """Doble del WebSocket del agente: captura lo que el relay le envía."""

    def __init__(self):
        self.sent: list[str] = []
        self.closed_code: int | None = None

    async def send_text(self, s: str) -> None:
        self.sent.append(s)

    async def close(self, code: int = 1000) -> None:
        self.closed_code = code


def _make_request(method, path, *, headers=None, body=b"", query="", client="9.9.9.9"):
    from starlette.requests import Request

    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "raw_path": path.encode(),
        "query_string": query.encode(),
        "headers": [
            (k.lower().encode(), v.encode()) for k, v in (headers or {}).items()
        ],
        "client": (client, 12345),
        "server": ("testserver", 80),
        "scheme": "https",
    }

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(scope, receive)


class TunnelHubTests(unittest.TestCase):
    def test_request_response_roundtrip(self):
        async def scenario():
            hub = TunnelHub()
            ws = FakeWS()
            conn = TunnelConn(ws, "org-1", "agentX", "rtok-123")
            hub.register(conn)
            self.assertIs(hub.get("agentX"), conn)

            task = asyncio.create_task(hub.request(
                conn, method="GET", path="/api/v1/health",
                query="active_only=false", headers={"authorization": "Bearer x"},
                body=b"",
            ))
            # Deja que el hub envíe el frame `req`.
            for _ in range(5):
                await asyncio.sleep(0)
                if ws.sent:
                    break
            self.assertTrue(ws.sent, "el hub no envió la petición al agente")
            frame = json.loads(ws.sent[0])
            self.assertEqual(frame["type"], "req")
            self.assertEqual(frame["method"], "GET")
            self.assertEqual(frame["path"], "/api/v1/health")
            self.assertEqual(frame["query"], "active_only=false")

            # El agente responde.
            conn.resolve_response({
                "type": "resp", "id": frame["id"], "status": 200,
                "headers": {"content-type": "application/json"},
                "body_b64": base64.b64encode(b'{"ok":true}').decode(),
            })
            resp = await task
            self.assertEqual(resp["status"], 200)
            self.assertEqual(base64.b64decode(resp["body_b64"]), b'{"ok":true}')
            # El pending se limpió.
            self.assertEqual(conn.pending, {})

        asyncio.run(scenario())

    def test_request_timeout(self):
        async def scenario():
            hub = TunnelHub()
            conn = TunnelConn(FakeWS(), "org-1", "agentX", "rtok")
            hub.register(conn)
            with self.assertRaises(asyncio.TimeoutError):
                await hub.request(
                    conn, method="GET", path="/x", query="", headers={},
                    body=b"", timeout=0.05,
                )
            # Aunque expire, no debe dejar el pending colgado.
            self.assertEqual(conn.pending, {})

        asyncio.run(scenario())

    def test_disconnect_fails_pending(self):
        async def scenario():
            hub = TunnelHub()
            conn = TunnelConn(FakeWS(), "org-1", "agentX", "rtok")
            hub.register(conn)
            task = asyncio.create_task(hub.request(
                conn, method="GET", path="/x", query="", headers={},
                body=b"", timeout=5,
            ))
            for _ in range(5):
                await asyncio.sleep(0)
            # Simula caída de la conexión.
            conn.fail_all(ConnectionError("cerrada"))
            with self.assertRaises(ConnectionError):
                await task

        asyncio.run(scenario())

    def test_key_match_constant_time(self):
        conn = TunnelConn(FakeWS(), "org-1", "agentX", "secreto-largo")
        self.assertTrue(conn.match_key("secreto-largo"))
        self.assertFalse(conn.match_key("otro"))
        self.assertFalse(conn.match_key(None))
        self.assertFalse(conn.match_key(""))
        # Sin resolve_token registrado → falla cerrado.
        conn_no = TunnelConn(FakeWS(), "org-1", "agentY", "")
        self.assertFalse(conn_no.match_key(""))
        self.assertFalse(conn_no.match_key("cualquiera"))

    def test_reconnect_replaces_old(self):
        async def scenario():
            hub = TunnelHub()
            old = TunnelConn(FakeWS(), "org-1", "agentX", "rtok")
            hub.register(old)
            # Una petición viva en la conexión vieja.
            task = asyncio.create_task(hub.request(
                old, method="GET", path="/x", query="", headers={},
                body=b"", timeout=5,
            ))
            for _ in range(5):
                await asyncio.sleep(0)
            new = TunnelConn(FakeWS(), "org-1", "agentX", "rtok")
            hub.register(new)  # reconexión: reemplaza
            self.assertIs(hub.get("agentX"), new)
            self.assertFalse(old.alive)
            # La petición vieja se falla (no queda colgada para siempre).
            with self.assertRaises(ConnectionError):
                await task

        asyncio.run(scenario())


class AgentProxyEndpointTests(unittest.TestCase):
    def setUp(self):
        # Sin túneles registrados de arranque.
        for aid in list(main.tunnel_hub._conns.keys()):
            main.tunnel_hub._conns.pop(aid, None)

    def test_proxy_503_when_agent_not_connected(self):
        req = _make_request("GET", "/v1/agent/nope/api/v1/health",
                            headers={"x-tunnel-key": "whatever"})
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            asyncio.run(main.agent_proxy("nope", "api/v1/health", req))
        self.assertEqual(ctx.exception.status_code, 503)

    def test_proxy_401_on_bad_tunnel_key(self):
        conn = TunnelConn(FakeWS(), "org-1", "agentZ", "clave-buena")
        main.tunnel_hub.register(conn)
        try:
            req = _make_request("GET", "/v1/agent/agentZ/api/v1/health",
                                headers={"x-tunnel-key": "clave-mala"})
            from fastapi import HTTPException
            with self.assertRaises(HTTPException) as ctx:
                asyncio.run(main.agent_proxy("agentZ", "api/v1/health", req))
            self.assertEqual(ctx.exception.status_code, 401)
        finally:
            main.tunnel_hub.unregister(conn)

    def test_proxy_roundtrip_forwards_and_marks_forwarded(self):
        """Con un túnel vivo, el proxy reenvía la petición y devuelve la respuesta
        del agente; además inyecta X-Forwarded-For (para que el agente NO trate la
        petición reproducida en 127.0.0.1 como 'loopback raíz')."""
        async def scenario():
            ws = FakeWS()
            conn = TunnelConn(ws, "org-1", "agentR", "clave")
            main.tunnel_hub.register(conn)
            try:
                req = _make_request(
                    "GET", "/v1/agent/agentR/api/v1/devices",
                    headers={"x-tunnel-key": "clave",
                             "authorization": "Bearer pairing"},
                    query="active_only=false", client="181.1.2.3",
                )
                task = asyncio.create_task(
                    main.agent_proxy("agentR", "api/v1/devices", req))
                for _ in range(5):
                    await asyncio.sleep(0)
                    if ws.sent:
                        break
                frame = json.loads(ws.sent[0])
                self.assertEqual(frame["path"], "/api/v1/devices")
                self.assertEqual(frame["query"], "active_only=false")
                fwd = {k.lower(): v for k, v in frame["headers"].items()}
                self.assertEqual(fwd.get("x-forwarded-for"), "181.1.2.3")
                self.assertEqual(fwd.get("x-tunnel-proxy"), "1")
                # La clave de túnel NO viaja al agente.
                self.assertNotIn("x-tunnel-key", fwd)
                # El Authorization del teléfono SÍ viaja (autorización por rol).
                self.assertEqual(fwd.get("authorization"), "Bearer pairing")

                conn.resolve_response({
                    "type": "resp", "id": frame["id"], "status": 200,
                    "headers": {"content-type": "application/json"},
                    "body_b64": base64.b64encode(b'{"total":0}').decode(),
                })
                resp = await task
                self.assertEqual(resp.status_code, 200)
                self.assertEqual(bytes(resp.body), b'{"total":0}')
            finally:
                main.tunnel_hub.unregister(conn)

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
