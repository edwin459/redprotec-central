"""Watchdog de conexión por sede (relay multi-sede).

El relay es el único que ve todas las sedes 24/7 con internet propio, así que es
el lugar correcto para avisar una caída de internet/agente EN EL MOMENTO (el push
del agente no saldría: su conexión está caída). Cubre la máquina de estados PURA y
el tick contra el almacén en memoria, con `_push_ntfy` interceptado (sin red).
"""

import unittest
from datetime import timedelta

import main


class DecideSiteTransitionTest(unittest.TestCase):
    def _d(self, prev, secs, thr=210):
        return main.decide_site_transition(prev, secs, thr)

    def test_first_seen_is_baseline_no_alert(self):
        self.assertEqual(self._d(None, 5), ("online", None))
        self.assertEqual(self._d(None, 9999), ("offline", None))  # siembra, sin avisar

    def test_online_to_offline_emits_down(self):
        self.assertEqual(self._d("online", 5), ("online", None))
        self.assertEqual(self._d("online", 999), ("offline", "down"))

    def test_offline_to_online_emits_up(self):
        self.assertEqual(self._d("offline", 5), ("online", "up"))
        self.assertEqual(self._d("offline", 999), ("offline", None))

    def test_threshold_is_strict(self):
        self.assertEqual(self._d("online", 210, 210)[1], None)     # justo en el borde
        self.assertEqual(self._d("online", 211, 210)[1], "down")


class ComposeTest(unittest.TestCase):
    def test_down_message(self):
        title, body = main.compose_site_down_message("Bogotá")
        self.assertIn("Bogotá", title)
        self.assertIn("sin conexión", title)

    def test_up_message_has_duration(self):
        _t, body = main.compose_site_up_message("Bogotá", 17 * 60)
        self.assertIn("17 min", body)


class WatchdogTickTest(unittest.TestCase):
    def setUp(self):
        main._STORE.clear()
        main._ORG_CONFIG.clear()
        main._SITE_WATCH.clear()
        self.org = "org-token-watchdog-1"
        self.pushes: list[tuple] = []
        self._orig_push = main._push_ntfy

        def _fake_push(topic, title, message, *, priority, tags):
            self.pushes.append((topic, title, message, priority, tags))
            return "ok:200"  # push exitoso → el watchdog confirma el estado

        main._push_ntfy = _fake_push
        main._ORG_CONFIG[self.org] = {"alert_topic": "mytopic"}

    def tearDown(self):
        main._push_ntfy = self._orig_push
        main._STORE.clear()
        main._ORG_CONFIG.clear()
        main._SITE_WATCH.clear()

    def _seed_site(self, site_id, updated_at):
        main._STORE.setdefault(self.org, {})[site_id] = {
            "site_name": site_id.title(),
            "summary": main.SiteSummary().model_dump(),
            "devices": [],
            "remote_admin": False,
            "updated_at": updated_at,
        }

    def test_baseline_first_tick_is_silent(self):
        # Sede caída desde antes de arrancar el relay: el primer tick NO avisa.
        self._seed_site("bogota", main._now() - timedelta(hours=1))
        emitted = main._watchdog_tick(main._now())
        self.assertEqual(emitted, [])
        self.assertEqual(self.pushes, [])

    def test_online_then_down_alerts_once(self):
        now = main._now()
        # Primer tick: en línea (baseline).
        self._seed_site("bogota", now)
        main._watchdog_tick(now)
        self.assertEqual(self.pushes, [])
        # Sin nuevos latidos: pasa el umbral → 'down'.
        later = now + timedelta(seconds=main.OFFLINE_ALERT_SECONDS + 30)
        emitted = main._watchdog_tick(later)
        self.assertEqual([e[2] for e in emitted], ["down"])
        self.assertEqual(len(self.pushes), 1)
        self.assertIn("sin conexión", self.pushes[0][1])
        # Sigue caída: NO re-avisa.
        emitted2 = main._watchdog_tick(later + timedelta(seconds=60))
        self.assertEqual(emitted2, [])
        self.assertEqual(len(self.pushes), 1)

    def test_recovery_alerts_up_with_duration(self):
        now = main._now()
        self._seed_site("bogota", now)
        main._watchdog_tick(now)
        down_at = now + timedelta(seconds=main.OFFLINE_ALERT_SECONDS + 30)
        main._watchdog_tick(down_at)  # down
        # La sede vuelve a latir (updated_at fresco) 10 min después de caer.
        back = down_at + timedelta(minutes=10)
        self._seed_site("bogota", back)  # nuevo latido
        emitted = main._watchdog_tick(back)
        self.assertEqual([e[2] for e in emitted], ["up"])
        up_push = self.pushes[-1]
        self.assertIn("de vuelta", up_push[1])

    def test_no_topic_no_push_but_state_tracked(self):
        # Sin tema configurado: no se envía push, pero el estado igual se sigue.
        main._ORG_CONFIG[self.org] = {"alert_topic": None}
        now = main._now()
        self._seed_site("bogota", now)
        main._watchdog_tick(now)
        later = now + timedelta(seconds=main.OFFLINE_ALERT_SECONDS + 30)
        emitted = main._watchdog_tick(later)
        self.assertEqual([e[2] for e in emitted], ["down"])  # se detecta
        self.assertEqual(self.pushes, [])                     # pero no hay a quién avisar
        # Aunque no hubo push, el estado se confirma (org sin tema) → no reintenta.
        again = main._watchdog_tick(later + timedelta(seconds=60))
        self.assertEqual(again, [])

    def test_failed_push_retries_until_delivered(self):
        # Entrega FIABLE: si el push falla, el estado NO se confirma y el watchdog
        # REINTENTA en el próximo tick, hasta que sale. Así una caída no se pierde
        # por un hipo de red (egress intermitente a ntfy.sh).
        now = main._now()
        self._seed_site("bogota", now)
        main._watchdog_tick(now)  # baseline online

        # 1er intento: el push FALLA (simula timeout de egress).
        main._push_ntfy = lambda *a, **k: "ERR:URLError:timed out"
        down_at = now + timedelta(seconds=main.OFFLINE_ALERT_SECONDS + 30)
        e1 = main._watchdog_tick(down_at)
        self.assertEqual([e[2] for e in e1], ["down"])  # se decidió...

        # 2º tick, el push SIGUE fallando → REINTENTA (vuelve a emitir 'down').
        e2 = main._watchdog_tick(down_at + timedelta(seconds=60))
        self.assertEqual([e[2] for e in e2], ["down"])  # reintento, no se perdió

        # Ahora el push SALE → se confirma el estado.
        delivered = []
        main._push_ntfy = lambda topic, title, message, *, priority, tags: (
            delivered.append(title) or "ok:200")
        e3 = main._watchdog_tick(down_at + timedelta(seconds=120))
        self.assertEqual([e[2] for e in e3], ["down"])  # este sí entregó
        self.assertEqual(len(delivered), 1)

        # Confirmado: el siguiente tick ya NO re-avisa.
        e4 = main._watchdog_tick(down_at + timedelta(seconds=180))
        self.assertEqual(e4, [])


    # ── On-call: escalado + confirmación (ack) ──────────────────────────────
    def test_escalation_reminders_until_acked(self):
        now = main._now()
        self._seed_site("bogota", now)
        main._watchdog_tick(now)  # baseline online
        down_at = now + timedelta(seconds=main.OFFLINE_ALERT_SECONDS + 30)
        main._watchdog_tick(down_at)  # 'down' → push 1, abre incidente
        self.assertEqual(len(self.pushes), 1)
        # Antes del intervalo de escalado: no re-avisa.
        main._watchdog_tick(down_at + timedelta(seconds=60))
        self.assertEqual(len(self.pushes), 1)
        # Pasado el intervalo y SIN confirmar: recordatorio de escalado.
        esc_at = down_at + timedelta(seconds=main.ESCALATION_INTERVAL_SECONDS + 5)
        e = main._watchdog_tick(esc_at)
        self.assertEqual([x[2] for x in e], ["escalate"])
        self.assertEqual(len(self.pushes), 2)
        self.assertIn("SIGUE CAÍDA", self.pushes[-1][1])
        # Confirmar detiene los recordatorios.
        main.ack_incident("bogota", p=main._resolve_principal(self.org))
        e2 = main._watchdog_tick(
            esc_at + timedelta(seconds=main.ESCALATION_INTERVAL_SECONDS + 5))
        self.assertEqual(e2, [])
        self.assertEqual(len(self.pushes), 2)  # no más avisos

    def test_escalation_stops_at_max(self):
        now = main._now()
        self._seed_site("bogota", now)
        main._watchdog_tick(now)
        down_at = now + timedelta(seconds=main.OFFLINE_ALERT_SECONDS + 30)
        main._watchdog_tick(down_at)  # down
        t = down_at
        for _ in range(main.MAX_ESCALATIONS + 2):
            t = t + timedelta(seconds=main.ESCALATION_INTERVAL_SECONDS + 5)
            main._watchdog_tick(t)
        # 1 (down) + MAX_ESCALATIONS recordatorios, y no más.
        self.assertEqual(len(self.pushes), 1 + main.MAX_ESCALATIONS)

    def test_incidents_endpoint_and_ack(self):
        now = main._now()
        self._seed_site("bogota", now)
        main._watchdog_tick(now)
        main._watchdog_tick(now + timedelta(seconds=main.OFFLINE_ALERT_SECONDS + 30))
        p = main._resolve_principal(self.org)
        inc = main.incidents(p=p)["incidents"]
        self.assertEqual(len(inc), 1)
        self.assertEqual(inc[0]["site_id"], "bogota")
        self.assertFalse(inc[0]["acked"])
        main.ack_incident("bogota", p=p)
        self.assertTrue(main.incidents(p=p)["incidents"][0]["acked"])

    def test_recovery_closes_incident(self):
        now = main._now()
        self._seed_site("bogota", now)
        main._watchdog_tick(now)
        down_at = now + timedelta(seconds=main.OFFLINE_ALERT_SECONDS + 30)
        main._watchdog_tick(down_at)  # down
        back = down_at + timedelta(minutes=5)
        self._seed_site("bogota", back)
        main._watchdog_tick(back)  # up → cierra incidente
        self.assertEqual(main.incidents(p=main._resolve_principal(self.org))["incidents"], [])


class DecideEscalationTest(unittest.TestCase):
    def _inc(self, **kw):
        base = {"incident_open": True, "acked": False, "escalation_level": 0,
                "last_alert_at": main._now() - timedelta(seconds=301)}
        base.update(kw)
        return base

    def test_none_incident(self):
        self.assertFalse(main.decide_escalation(None, main._now(), 300, 3))

    def test_open_unacked_due(self):
        self.assertTrue(main.decide_escalation(self._inc(), main._now(), 300, 3))

    def test_not_due_yet(self):
        inc = self._inc(last_alert_at=main._now() - timedelta(seconds=100))
        self.assertFalse(main.decide_escalation(inc, main._now(), 300, 3))

    def test_acked_stops(self):
        self.assertFalse(
            main.decide_escalation(self._inc(acked=True), main._now(), 300, 3))

    def test_max_reached(self):
        self.assertFalse(
            main.decide_escalation(self._inc(escalation_level=3), main._now(), 300, 3))

    def test_closed_incident(self):
        self.assertFalse(
            main.decide_escalation(self._inc(incident_open=False), main._now(), 300, 3))


class ComputeUptimeTest(unittest.TestCase):
    def setUp(self):
        self.now = main._now()
        self.start = self.now - timedelta(days=30)

    def test_no_events_is_full_uptime(self):
        u = main.compute_uptime([], self.start, self.now)
        self.assertEqual(u["uptime_pct"], 100.0)
        self.assertEqual(u["incidents"], 0)

    def test_one_resolved_incident(self):
        down = self.now - timedelta(hours=2)
        up = self.now - timedelta(hours=1)  # 1h de caída
        u = main.compute_uptime(
            [{"event": "down", "at": down}, {"event": "up", "at": up}],
            self.start, self.now)
        self.assertEqual(u["incidents"], 1)
        self.assertEqual(u["downtime_seconds"], 3600)
        self.assertEqual(u["mttr_seconds"], 3600)
        self.assertLess(u["uptime_pct"], 100.0)
        self.assertGreater(u["uptime_pct"], 99.0)

    def test_still_down_counts_to_now(self):
        down = self.now - timedelta(hours=1)
        u = main.compute_uptime([{"event": "down", "at": down}],
                                self.start, self.now)
        self.assertEqual(u["incidents"], 1)
        self.assertEqual(u["mttr_seconds"], 0)  # sin resolver, no cuenta en MTTR
        self.assertAlmostEqual(u["downtime_seconds"], 3600, delta=2)

    def test_down_before_window_first_event_up(self):
        # Primer evento es 'up' → venía caída desde antes; cuenta desde start.
        up = self.start + timedelta(hours=1)
        u = main.compute_uptime([{"event": "up", "at": up}],
                                self.start, self.now)
        self.assertEqual(u["incidents"], 1)
        self.assertAlmostEqual(u["downtime_seconds"], 3600, delta=2)


class ComputeIncidentsTest(unittest.TestCase):
    def setUp(self):
        self.now = main._now()
        self.start = self.now - timedelta(days=30)

    def test_pairs_down_up_with_timestamps(self):
        d = self.now - timedelta(hours=3)
        u = self.now - timedelta(hours=2)
        incs = main.compute_incidents(
            [{"event": "down", "at": d}, {"event": "up", "at": u}],
            self.start, self.now)
        self.assertEqual(len(incs), 1)
        self.assertEqual(incs[0]["down_at"], d)
        self.assertEqual(incs[0]["up_at"], u)
        self.assertFalse(incs[0]["ongoing"])
        self.assertEqual(incs[0]["duration_seconds"], 3600)

    def test_ongoing_incident_has_no_up(self):
        d = self.now - timedelta(minutes=30)
        incs = main.compute_incidents([{"event": "down", "at": d}],
                                      self.start, self.now)
        self.assertEqual(len(incs), 1)
        self.assertIsNone(incs[0]["up_at"])
        self.assertTrue(incs[0]["ongoing"])

    def test_most_recent_first(self):
        d1 = self.now - timedelta(hours=10); u1 = self.now - timedelta(hours=9)
        d2 = self.now - timedelta(hours=2); u2 = self.now - timedelta(hours=1)
        incs = main.compute_incidents(
            [{"event": "down", "at": d1}, {"event": "up", "at": u1},
             {"event": "down", "at": d2}, {"event": "up", "at": u2}],
            self.start, self.now)
        self.assertEqual(incs[0]["down_at"], d2)  # más reciente primero
        self.assertEqual(incs[1]["down_at"], d1)


class SlaEndpointTest(unittest.TestCase):
    def setUp(self):
        main._STORE.clear()
        if hasattr(main.store, "_events"):
            main.store._events.clear()
        self.org = "org-sla-1"
        # store real en memoria para eventos (main.store envuelve los dicts).
        self.now = main._now()

    def tearDown(self):
        main._STORE.clear()
        if hasattr(main.store, "_events"):
            main.store._events.clear()

    def _seed(self, site_id):
        main._STORE.setdefault(self.org, {})[site_id] = {
            "site_name": site_id.title(),
            "summary": main.SiteSummary().model_dump(),
            "devices": [], "remote_admin": False, "updated_at": self.now,
        }

    def test_sla_reflects_recorded_events(self):
        self._seed("bogota")
        main.store.record_site_event(
            self.org, "bogota", "down", self.now - timedelta(hours=3))
        main.store.record_site_event(
            self.org, "bogota", "up", self.now - timedelta(hours=1))  # 2h caída
        out = main.sla(days=30, p=main._resolve_principal(self.org))
        site = out["sites"][0]
        self.assertEqual(site["site_id"], "bogota")
        self.assertEqual(site["incidents"], 1)
        self.assertEqual(site["downtime_seconds"], 7200)
        self.assertIn("uptime_pct", out["overall"])


class AlertRoutingTest(unittest.TestCase):
    """El watchdog en la nube prefiere Telegram (Railway alcanza api.telegram.org;
    ntfy.sh está bloqueado). ntfy queda como respaldo."""

    def setUp(self):
        self._tg = main._push_telegram
        self._ntfy = main._push_ntfy
        self.tg_calls = []
        self.ntfy_calls = []
        main._push_telegram = lambda bot, chat, title, body: (
            self.tg_calls.append((bot, chat, title)) or "ok:200")
        main._push_ntfy = lambda topic, title, message, *, priority, tags: (
            self.ntfy_calls.append((topic, title)) or "ok:200")

    def tearDown(self):
        main._push_telegram = self._tg
        main._push_ntfy = self._ntfy

    def test_prefers_telegram_when_configured(self):
        r = main._push_alert(
            {"tg_bot_token": "123:ABC", "tg_chat_id": "999", "alert_topic": "t"},
            "T", "B", priority="high", tags="x")
        self.assertEqual(r, "ok:200")
        self.assertEqual(len(self.tg_calls), 1)
        self.assertEqual(self.ntfy_calls, [])  # NO usa ntfy si hay Telegram

    def test_falls_back_to_ntfy_without_telegram(self):
        r = main._push_alert({"alert_topic": "mytopic"}, "T", "B",
                             priority="high", tags="x")
        self.assertEqual(r, "ok:200")
        self.assertEqual(self.tg_calls, [])
        self.assertEqual(len(self.ntfy_calls), 1)

    def test_no_channel_when_nothing_configured(self):
        r = main._push_alert({}, "T", "B", priority="high", tags="x")
        self.assertEqual(r, "no_channel")
        self.assertEqual(self.tg_calls, [])
        self.assertEqual(self.ntfy_calls, [])


class AlertChannelConfigTest(unittest.TestCase):
    def setUp(self):
        main._STORE.clear(); main._ORG_CONFIG.clear()
        self.org = "org-tel-1"

    def tearDown(self):
        main._ORG_CONFIG.clear()

    def test_set_and_read_back_redacted(self):
        master = main._resolve_principal(self.org)
        main.set_alert_channel(
            main.AlertChannelIn(telegram_bot_token="123:SECRET", telegram_chat_id="42"),
            p=master)
        cfg = main.get_org_config(p=master)
        self.assertTrue(cfg["telegram_set"])          # hay canal
        self.assertEqual(cfg["telegram_chat_id"], "42")
        self.assertNotIn("telegram_bot_token", cfg)    # el token nunca se devuelve

    def test_tg_escape_reserved_chars(self):
        self.assertEqual(main._tg_escape("a.b-c!"), "a\\.b\\-c\\!")

    def test_push_telegram_builds_valid_json_payload(self):
        # Regresión: main.py debía importar json (lo usa _push_telegram). Ejercita
        # la función REAL con un opener simulado (sin red) → payload JSON válido.
        import json as _json

        captured = {}

        class _Resp:
            status = 200

        class _Opener:
            def open(self, req, timeout=None):
                captured["url"] = req.full_url
                captured["body"] = req.data
                return _Resp()

        orig = main._IPV4_OPENER
        main._IPV4_OPENER = _Opener()
        try:
            res = main._push_telegram("123:ABC", "999", "Título.", "Cuerpo con áé!")
        finally:
            main._IPV4_OPENER = orig
        self.assertTrue(res.startswith("ok"))
        self.assertIn("/bot123:ABC/sendMessage", captured["url"])
        body = _json.loads(captured["body"].decode("utf-8"))  # JSON válido
        self.assertEqual(body["chat_id"], "999")
        self.assertIn("Cuerpo", body["text"])


if __name__ == "__main__":
    unittest.main()
