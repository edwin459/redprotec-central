"""Conformancia del almacén del relay.

Un ÚNICO conjunto de casos (StoreConformance) se corre contra:
  • MemoryStore  — siempre.
  • PostgresStore — solo si la variable de entorno RP_TEST_DATABASE_URL apunta a
                    un Postgres de PRUEBAS (se salta si no). Así se prueba que
                    ambos backends se comportan IGUAL — la premisa de la migración.

⚠️ RP_TEST_DATABASE_URL debe ser una base DESECHABLE: cada test limpia las tablas.
"""
import os
import threading
import unittest
from datetime import timedelta

from store import MemoryStore, _now


class StoreConformance:
    """Casos compartidos. Las subclases definen self.store (y lo limpian)."""

    ORG = "org-token-conformance-1"
    ORG2 = "org-token-conformance-2"

    # ── sedes ──
    def test_upsert_and_get_site_roundtrip(self):
        now = _now()
        summary = {"devices_total": 3, "alerts": 1}
        devices = [{"mac": "AA:BB", "name": "PC", "trust": "unknown", "online": True}]
        self.store.upsert_site(self.ORG, "bogota", "Bogotá", summary, devices, True, now)
        rec = self.store.get_site(self.ORG, "bogota")
        self.assertEqual(rec["site_name"], "Bogotá")
        self.assertEqual(rec["summary"], summary)
        self.assertEqual(rec["devices"], devices)
        self.assertTrue(rec["remote_admin"])
        self.assertLess(abs((rec["updated_at"] - now).total_seconds()), 1)

    def test_get_site_absent_is_none(self):
        self.assertIsNone(self.store.get_site(self.ORG, "no-existe"))

    def test_upsert_overwrites(self):
        now = _now()
        self.store.upsert_site(self.ORG, "s", "S", {"a": 1}, None, False, now)
        self.store.upsert_site(self.ORG, "s", "S2", {"a": 2}, [{"mac": "X"}], True, now)
        rec = self.store.get_site(self.ORG, "s")
        self.assertEqual(rec["site_name"], "S2")
        self.assertEqual(rec["summary"], {"a": 2})
        self.assertEqual(rec["devices"], [{"mac": "X"}])
        self.assertTrue(rec["remote_admin"])

    def test_devices_none_preserved(self):
        self.store.upsert_site(self.ORG, "s", "S", {}, None, False, _now())
        self.assertIsNone(self.store.get_site(self.ORG, "s")["devices"])

    def test_list_sites_and_isolation(self):
        now = _now()
        self.store.upsert_site(self.ORG, "a", "A", {}, None, True, now)
        self.store.upsert_site(self.ORG, "b", "B", {}, None, True, now)
        self.store.upsert_site(self.ORG2, "c", "C", {}, None, True, now)
        ids = {sid for sid, _ in self.store.list_sites(self.ORG)}
        self.assertEqual(ids, {"a", "b"})
        ids2 = {sid for sid, _ in self.store.list_sites(self.ORG2)}
        self.assertEqual(ids2, {"c"})

    def test_stats_counts_orgs_and_sites(self):
        now = _now()
        self.store.upsert_site(self.ORG, "a", "A", {}, None, True, now)
        self.store.upsert_site(self.ORG, "b", "B", {}, None, True, now)
        self.store.upsert_site(self.ORG2, "c", "C", {}, None, True, now)
        orgs, sites = self.store.stats()
        self.assertEqual(orgs, 2)
        self.assertEqual(sites, 3)

    # ── comandos ──
    def test_enqueue_and_pending(self):
        now = _now()
        self.store.enqueue_command(self.ORG, "s", {
            "id": "c1", "action": "block", "mac": "AA", "value": None,
            "created_at": now})
        self.store.enqueue_command(self.ORG, "s", {
            "id": "c2", "action": "rename", "mac": "BB", "value": "PC1",
            "created_at": now})
        pend = self.store.pending_commands(self.ORG, "s", 600, now)
        self.assertEqual([c["id"] for c in pend], ["c1", "c2"])
        self.assertEqual(pend[1]["value"], "PC1")
        # No filtra por org/sede ajena.
        self.assertEqual(self.store.pending_commands(self.ORG, "otra", 600, now), [])

    def test_ttl_prunes_old_commands(self):
        old = _now() - timedelta(seconds=1200)
        self.store.enqueue_command(self.ORG, "s", {
            "id": "viejo", "action": "block", "mac": "AA", "value": None,
            "created_at": old})
        self.store.enqueue_command(self.ORG, "s", {
            "id": "nuevo", "action": "block", "mac": "BB", "value": None,
            "created_at": _now()})
        pend = self.store.pending_commands(self.ORG, "s", 600, _now())
        self.assertEqual([c["id"] for c in pend], ["nuevo"])
        # La poda es permanente: el viejo ya no vuelve.
        pend2 = self.store.pending_commands(self.ORG, "s", 600, _now())
        self.assertEqual([c["id"] for c in pend2], ["nuevo"])

    def test_ack_removes_command(self):
        now = _now()
        self.store.enqueue_command(self.ORG, "s", {
            "id": "c1", "action": "block", "mac": "AA", "value": None,
            "created_at": now})
        self.store.ack_command(self.ORG, "s", "c1")
        self.assertEqual(self.store.pending_commands(self.ORG, "s", 600, now), [])

    # ── config ──
    def test_org_config_roundtrip(self):
        self.assertEqual(self.store.get_org_config(self.ORG), {})
        self.store.set_alert_topic(self.ORG, "mi-tema-ntfy")
        self.assertEqual(self.store.get_org_config(self.ORG)["alert_topic"], "mi-tema-ntfy")
        self.store.set_alert_topic(self.ORG, None)
        self.assertIsNone(self.store.get_org_config(self.ORG)["alert_topic"])

    # ── accesos ──
    def test_access_set_list_resolve(self):
        self.store.set_access(self.ORG, [
            {"token": "user-ana-0001", "name": "Ana", "role": "auditor", "sites": ["*"]},
            {"token": "user-ben-0002", "name": "Ben", "role": "siteAdmin", "sites": ["bogota"]},
        ])
        listed = self.store.list_access(self.ORG)
        self.assertEqual(listed["user-ben-0002"]["sites"], ["bogota"])
        org, u = self.store.resolve_user("user-ana-0001")
        self.assertEqual(org, self.ORG)
        self.assertEqual(u["role"], "auditor")

    def test_resolve_unknown_user_is_none(self):
        self.assertIsNone(self.store.resolve_user("token-que-no-existe"))

    def test_set_access_replaces(self):
        self.store.set_access(self.ORG, [
            {"token": "viejo-0001", "name": "", "role": "auditor", "sites": ["*"]}])
        self.store.set_access(self.ORG, [
            {"token": "nuevo-0002", "name": "", "role": "helpdesk", "sites": ["*"]}])
        self.assertIsNone(self.store.resolve_user("viejo-0001"))
        self.assertIsNotNone(self.store.resolve_user("nuevo-0002"))
        self.assertEqual(set(self.store.list_access(self.ORG)), {"nuevo-0002"})


class MemoryStoreTests(StoreConformance, unittest.TestCase):
    def setUp(self):
        self.store = MemoryStore({}, {}, {}, {}, threading.Lock())


@unittest.skipUnless(
    os.environ.get("RP_TEST_DATABASE_URL"),
    "define RP_TEST_DATABASE_URL (Postgres DESECHABLE) para probar la paridad Postgres",
)
class PostgresStoreTests(StoreConformance, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from store import PostgresStore
        cls.store = PostgresStore(os.environ["RP_TEST_DATABASE_URL"])

    @classmethod
    def tearDownClass(cls):
        cls.store.close()

    def setUp(self):
        # Limpia las tablas antes de cada caso (base DESECHABLE).
        with self.store._pool.connection() as conn, conn.cursor() as cur:
            cur.execute("TRUNCATE sites, commands, org_config, access")


if __name__ == "__main__":
    unittest.main()
