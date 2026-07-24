"""Tests del RBAC en la NUBE (relay multi-sede): alcance por sede + capacidades.

Llamadas directas a los handlers (sin TestClient) para no depender de httpx.
"""
import unittest

import main
from fastapi import HTTPException


def _seed_site(org_token: str, site_id: str, name: str, *, remote_admin=True, devices=None):
    main._STORE.setdefault(org_token, {})[site_id] = {
        "site_name": name,
        "summary": main.SiteSummary().model_dump(),
        "devices": devices or [],
        "remote_admin": remote_admin,
        "updated_at": main._now(),
    }


def _bearer(token: str) -> str:
    return f"Bearer {token}"


class CloudRbacTests(unittest.TestCase):
    def setUp(self):
        main._STORE.clear()
        main._COMMANDS.clear()
        main._ORG_CONFIG.clear()
        main._ACCESS.clear()
        self.org = "org-master-token-1234"
        _seed_site(self.org, "bogota", "Bogotá")
        _seed_site(self.org, "medellin", "Medellín")

    # ── Resolución de principal ─────────────────────────────────────────
    def test_unknown_token_is_master_root(self):
        p = main._resolve_principal(self.org)
        self.assertTrue(p.is_master)
        self.assertEqual(p.role, "owner")
        self.assertEqual(p.sites, ["*"])
        self.assertTrue(p.sees_site("bogota"))

    def test_registered_user_token_is_scoped(self):
        main.set_access(
            main.AccessListIn(users=[main.AccessUser(
                token="user-tok-bogota-it", name="Juan TI", role="siteAdmin", sites=["bogota"])]),
            p=main._resolve_principal(self.org))
        p = main._resolve_principal("user-tok-bogota-it")
        self.assertFalse(p.is_master)
        self.assertEqual(p.role, "siteAdmin")
        self.assertTrue(p.sees_site("bogota"))
        self.assertFalse(p.sees_site("medellin"))

    # ── Lectura filtrada por alcance ────────────────────────────────────
    def test_list_sites_filtered_by_scope(self):
        main._ACCESS[self.org] = {
            "u-bog": {"name": "Ana", "role": "siteAdmin", "sites": ["bogota"]}}
        allsites = main.list_sites(p=main._resolve_principal(self.org))
        self.assertEqual({s["site_id"] for s in allsites["sites"]}, {"bogota", "medellin"})
        scoped = main.list_sites(p=main._resolve_principal("u-bog"))
        self.assertEqual({s["site_id"] for s in scoped["sites"]}, {"bogota"})

    def test_site_detail_out_of_scope_403(self):
        main._ACCESS[self.org] = {
            "u-bog": {"name": "Ana", "role": "siteAdmin", "sites": ["bogota"]}}
        with self.assertRaises(HTTPException) as ctx:
            main.site_detail("medellin", p=main._resolve_principal("u-bog"))
        self.assertEqual(ctx.exception.status_code, 403)

    # ── Comandos: capacidad del rol + alcance ───────────────────────────
    def test_auditor_cannot_command(self):
        main._ACCESS[self.org] = {
            "aud": {"name": "Aud", "role": "auditor", "sites": ["*"]}}
        with self.assertRaises(HTTPException) as ctx:
            main.enqueue_command("bogota", main.CommandIn(action="block", mac="AA:BB"),
                                 p=main._resolve_principal("aud"))
        self.assertEqual(ctx.exception.status_code, 403)

    def test_siteadmin_commands_only_in_scope(self):
        main._ACCESS[self.org] = {
            "it-bog": {"name": "Juan", "role": "siteAdmin", "sites": ["bogota"]}}
        # En su sede → ok.
        out = main.enqueue_command("bogota", main.CommandIn(action="block", mac="AA:BB"),
                                   p=main._resolve_principal("it-bog"))
        self.assertTrue(out["ok"])
        # Fuera de su sede → 403.
        with self.assertRaises(HTTPException) as ctx:
            main.enqueue_command("medellin", main.CommandIn(action="block", mac="AA:BB"),
                                 p=main._resolve_principal("it-bog"))
        self.assertEqual(ctx.exception.status_code, 403)

    def test_helpdesk_rename_yes_block_no(self):
        main._ACCESS[self.org] = {
            "hd": {"name": "Sop", "role": "helpdesk", "sites": ["*"]}}
        # Renombrar (acción suave) → permitido.
        out = main.enqueue_command("bogota", main.CommandIn(action="rename", mac="AA:BB", value="PC1"),
                                   p=main._resolve_principal("hd"))
        self.assertTrue(out["ok"])
        # Bloquear → 403.
        with self.assertRaises(HTTPException) as ctx:
            main.enqueue_command("bogota", main.CommandIn(action="block", mac="AA:BB"),
                                 p=main._resolve_principal("hd"))
        self.assertEqual(ctx.exception.status_code, 403)

    def test_command_site_without_remote_admin_403(self):
        _seed_site(self.org, "cali", "Cali", remote_admin=False)
        with self.assertRaises(HTTPException) as ctx:
            main.enqueue_command("cali", main.CommandIn(action="block", mac="AA:BB"),
                                 p=main._resolve_principal(self.org))
        self.assertEqual(ctx.exception.status_code, 403)

    # ── Solo el maestro administra ──────────────────────────────────────
    def test_scoped_user_cannot_heartbeat(self):
        main._ACCESS[self.org] = {"u": {"name": "U", "role": "siteAdmin", "sites": ["bogota"]}}
        with self.assertRaises(HTTPException) as ctx:
            main.require_master(p=main._resolve_principal("u"))
        self.assertEqual(ctx.exception.status_code, 403)

    def test_master_passes_require_master(self):
        p = main.require_master(p=main._resolve_principal(self.org))
        self.assertTrue(p.is_master)

    # ── Reparto de accesos (PUT/GET) ────────────────────────────────────
    def test_set_and_list_access_roundtrip(self):
        master = main._resolve_principal(self.org)
        main.set_access(main.AccessListIn(users=[
            main.AccessUser(token="tok-ana-0001", name="Ana", role="auditor", sites=["*"]),
            main.AccessUser(token="tok-ben-0002", name="Ben", role="siteAdmin", sites=["bogota"]),
        ]), p=master)
        out = main.list_access(p=master)
        got = {u["token"]: u for u in out["users"]}
        self.assertEqual(got["tok-ana-0001"]["role"], "auditor")
        self.assertEqual(got["tok-ben-0002"]["sites"], ["bogota"])

    def test_cannot_grant_owner_or_invalid_role(self):
        master = main._resolve_principal(self.org)
        with self.assertRaises(HTTPException) as c1:
            main.set_access(main.AccessListIn(users=[
                main.AccessUser(token="tok-x-00001", role="owner")]), p=master)
        self.assertEqual(c1.exception.status_code, 400)
        with self.assertRaises(HTTPException) as c2:
            main.set_access(main.AccessListIn(users=[
                main.AccessUser(token="tok-y-00002", role="superuser")]), p=master)
        self.assertEqual(c2.exception.status_code, 400)

    def test_put_access_replaces_list(self):
        master = main._resolve_principal(self.org)
        main.set_access(main.AccessListIn(users=[
            main.AccessUser(token="old-tok-0001", role="auditor")]), p=master)
        main.set_access(main.AccessListIn(users=[
            main.AccessUser(token="new-tok-0002", role="helpdesk")]), p=master)
        tokens = {u["token"] for u in main.list_access(p=master)["users"]}
        self.assertEqual(tokens, {"new-tok-0002"})  # 'old' fue revocado al reemplazar


if __name__ == "__main__":
    unittest.main()
