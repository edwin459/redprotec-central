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
        main._push_ntfy = lambda topic, title, message, *, priority, tags: (
            self.pushes.append((topic, title, message, priority, tags))
        )
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


if __name__ == "__main__":
    unittest.main()
