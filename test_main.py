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
        if hasattr(main.store, "_agent_tokens"):
            main.store._agent_tokens.clear()
        if hasattr(main.store, "_entitlements"):
            main.store._entitlements.clear()
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

    # ── Viaje completo de un comando remoto (la garantía del control remoto) ──
    def test_command_roundtrip_heartbeat_to_ack(self):
        """app encola → el agente lo RECIBE en su latido → lo confirma → se va.

        Es el flujo exacto que corre el relay desplegado: prueba que un comando
        de la app llega al agente y no se re-ejecuta tras el ack."""
        master = main._resolve_principal(self.org)

        # 1) El agente late (permite admin remota) y reporta su sede.
        hb = main.Heartbeat(site_id="bogota", site_name="Bogotá", remote_admin=True)
        r0 = main.heartbeat(hb, p=master)
        self.assertEqual(r0["commands"], [])  # aún no hay nada encolado

        # 2) La app encola un bloqueo.
        enq = main.enqueue_command(
            "bogota", main.CommandIn(action="block", mac="AA:BB:CC"), p=master)
        self.assertTrue(enq["ok"])
        cmd_id = enq["command_id"]

        # 3) El agente vuelve a latir → RECIBE el comando.
        r1 = main.heartbeat(hb, p=master)
        self.assertEqual([c["id"] for c in r1["commands"]], [cmd_id])
        self.assertEqual(r1["commands"][0]["action"], "block")
        self.assertEqual(r1["commands"][0]["mac"], "AA:BB:CC")

        # 4) El agente confirma (ack) el comando ejecutado.
        main.ack_command(cmd_id, site_id="bogota", p=master)

        # 5) El siguiente latido ya NO trae el comando (no se re-ejecuta).
        r2 = main.heartbeat(hb, p=master)
        self.assertEqual(r2["commands"], [])

    def test_remote_admin_off_delivers_no_commands(self):
        """Una sede que NO permite admin remota no recibe comandos aunque existan
        (defensa en profundidad del opt-in por sede)."""
        _seed_site(self.org, "cali", "Cali", remote_admin=False)
        master = main._resolve_principal(self.org)
        # Encolar exige remote_admin en la sede → aquí ni siquiera deja encolar.
        with self.assertRaises(HTTPException) as ctx:
            main.enqueue_command(
                "cali", main.CommandIn(action="block", mac="AA:BB"), p=master)
        self.assertEqual(ctx.exception.status_code, 403)
        # Y un latido de esa sede tampoco entrega comandos.
        hb = main.Heartbeat(site_id="cali", site_name="Cali", remote_admin=False)
        self.assertEqual(main.heartbeat(hb, p=master)["commands"], [])

    # ── Auth-2: vincular una sede a una cuenta ──────────────────────────
    def test_agent_token_links_site_to_account_org(self):
        """La app (dueño de una cuenta = org) emite un token de agente; el agente
        que reporta con ese token queda en LA MISMA organización → sus sedes se
        ven bajo esa cuenta."""
        account = "cuenta-uuid-del-usuario-A"
        acc_p = main._resolve_principal(account)  # simula el principal de la cuenta
        # 1) La cuenta emite un token de agente.
        out = main.create_agent_token(main.AgentTokenIn(label="Casa"), p=acc_p)
        agent_token = out["token"]
        self.assertTrue(agent_token.startswith("rp_agent_"))
        # 2) principal() resuelve ese token a la MISMA org que la cuenta.
        p_agent = main.principal(authorization=f"Bearer {agent_token}")
        self.assertTrue(p_agent.is_master)
        self.assertEqual(p_agent.org_token, account)
        # 3) El agente late → la sede queda bajo la org de la cuenta.
        hb = main.Heartbeat(site_id="pc-casa", site_name="Casa", remote_admin=True)
        main.heartbeat(hb, p=p_agent)
        sites = main.list_sites(p=acc_p)["sites"]
        self.assertEqual([s["site_id"] for s in sites], ["pc-casa"])

    def test_agent_token_isolated_per_account(self):
        a = main._resolve_principal("cuenta-A")
        b = main._resolve_principal("cuenta-B")
        tok_a = main.create_agent_token(main.AgentTokenIn(label="A"), p=a)["token"]
        # El token de A resuelve a la org de A, no a la de B.
        pa = main.principal(authorization=f"Bearer {tok_a}")
        self.assertEqual(pa.org_token, "cuenta-A")
        # B no ve ese token en su lista.
        self.assertEqual(main.list_agent_tokens(p=b)["agents"], [])
        listed = main.list_agent_tokens(p=a)["agents"]
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0]["label"], "A")

    def test_agent_token_revoke(self):
        a = main._resolve_principal("cuenta-A")
        tok = main.create_agent_token(main.AgentTokenIn(label="A"), p=a)["token"]
        main.revoke_agent_token(tok, p=a)
        # Ya no resuelve a la org de la cuenta (cae al modelo opaco = su propio token).
        p_after = main.principal(authorization=f"Bearer {tok}")
        self.assertEqual(p_after.org_token, tok)  # opaco: org keyed por el token
        self.assertEqual(main.list_agent_tokens(p=a)["agents"], [])

    # ── Auth-3: entitlement / freemium ──────────────────────────────────
    def test_new_account_gets_pro_trial(self):
        p = main._resolve_principal("cuenta-nueva-Z")
        ent = main.get_entitlement(p=p)
        self.assertEqual(ent["plan"], "trial")
        self.assertEqual(ent["effective"], "pro")
        self.assertTrue(ent["can_control"])
        self.assertGreaterEqual(ent["trial_days_left"], 4)

    def test_command_allowed_during_trial(self):
        # self.org es nuevo → prueba Pro → puede comandar.
        out = main.enqueue_command(
            "bogota", main.CommandIn(action="block", mac="AA:BB"),
            p=main._resolve_principal(self.org))
        self.assertTrue(out["ok"])

    def test_command_blocked_when_free(self):
        # Marca la org como free (super-admin) → 402 al intentar comandar.
        main.ADMIN_TOKEN = "admin-secreto-test"
        try:
            main.admin_set_entitlement(
                main.AdminEntitlementIn(org_token=self.org, plan="free"),
                _=main.require_admin("Bearer admin-secreto-test"))
        finally:
            pass
        with self.assertRaises(HTTPException) as ctx:
            main.enqueue_command(
                "bogota", main.CommandIn(action="block", mac="AA:BB"),
                p=main._resolve_principal(self.org))
        self.assertEqual(ctx.exception.status_code, 402)
        main.ADMIN_TOKEN = ""

    def test_admin_fleet_aggregates_all_accounts(self):
        # Otra org con problema (agente "offline" por updated_at viejo).
        import datetime as _dt
        _seed_site("org-b-token-9999", "cali", "Cali")
        main._STORE["org-b-token-9999"]["cali"]["updated_at"] = (
            main._now() - _dt.timedelta(hours=2))
        main.ADMIN_TOKEN = "admin-secreto-test"
        try:
            out = main.admin_fleet(_=main.require_admin("Bearer admin-secreto-test"))
        finally:
            main.ADMIN_TOKEN = ""
        self.assertEqual(out["totals"]["accounts"], 2)
        # La cuenta con agente offline necesita atención y va primero (peor salud).
        self.assertTrue(out["fleet"][0]["needs_attention"])
        # No se filtra inventario de equipos de ningún cliente.
        self.assertNotIn("devices_list", out["fleet"][0])

    def test_download_info_not_configured_by_default(self):
        main.AGENT_DOWNLOAD_URL = ""
        info = main.download_info()
        self.assertFalse(info["available"])
        with self.assertRaises(HTTPException) as ctx:
            main.download_agent()
        self.assertEqual(ctx.exception.status_code, 404)

    def test_download_redirects_when_configured(self):
        main.AGENT_DOWNLOAD_URL = "https://example.com/RedProtecAgent-Setup.exe"
        try:
            resp = main.download_agent()
            self.assertEqual(resp.status_code, 302)
            self.assertEqual(resp.headers["location"], main.AGENT_DOWNLOAD_URL)
            self.assertTrue(main.download_info()["available"])
        finally:
            main.AGENT_DOWNLOAD_URL = ""

    def test_admin_fleet_requires_admin_token(self):
        main.ADMIN_TOKEN = ""
        with self.assertRaises(HTTPException) as ctx:
            main.admin_fleet(_=main.require_admin(None))
        self.assertEqual(ctx.exception.status_code, 403)

    def test_owner_is_always_pro(self):
        # El dueño (OWNER_ORGS) es Pro permanente aunque el almacén lo marque free.
        main.OWNER_ORGS = {"dueno-1"}
        main.ADMIN_TOKEN = "admin-secreto-test"
        try:
            main.admin_set_entitlement(
                main.AdminEntitlementIn(org_token="dueno-1", plan="free"),
                _=main.require_admin("Bearer admin-secreto-test"))
            ent = main._compute_entitlement("dueno-1", main._now())
            self.assertEqual(ent["effective"], "pro")
            self.assertTrue(ent["can_control"])
            self.assertTrue(ent["owner"])
            self.assertGreater(ent["max_sites"], 100)
        finally:
            main.OWNER_ORGS = set()
            main.ADMIN_TOKEN = ""

    def test_owner_can_command(self):
        main.OWNER_ORGS = {self.org}
        try:
            out = main.enqueue_command(
                "bogota", main.CommandIn(action="block", mac="AA:BB"),
                p=main._resolve_principal(self.org))
            self.assertTrue(out["ok"])
        finally:
            main.OWNER_ORGS = set()

    def test_entitlement_carries_signed_token_verifiable_with_pubkey(self):
        # Auth-3C: el veredicto viene firmado; la pública del endpoint lo verifica.
        import jwt
        p = main._resolve_principal("cuenta-firmada-1")
        ent = main.get_entitlement(p=p)
        self.assertIn("token", ent)
        pub = main.entitlement_pubkey()["public_key"]
        dec = jwt.decode(ent["token"], pub, algorithms=["EdDSA"],
                         options={"require": ["exp", "sub"]})
        self.assertEqual(dec["sub"], "cuenta-firmada-1")
        self.assertEqual(dec["can_control"], ent["can_control"])

    def test_expired_trial_is_free(self):
        main.ADMIN_TOKEN = "admin-secreto-test"
        # trial de 0 días → ya vencido → free efectivo.
        main.admin_set_entitlement(
            main.AdminEntitlementIn(org_token="cuenta-vencida", plan="trial", trial_days=0),
            _=main.require_admin("Bearer admin-secreto-test"))
        main.ADMIN_TOKEN = ""
        ent = main._compute_entitlement("cuenta-vencida", main._now())
        self.assertEqual(ent["plan"], "trial")
        self.assertEqual(ent["effective"], "free")
        self.assertFalse(ent["can_control"])

    def test_admin_requires_token(self):
        main.ADMIN_TOKEN = "admin-secreto-test"
        with self.assertRaises(HTTPException) as ctx:
            main.require_admin("Bearer token-equivocado")
        self.assertEqual(ctx.exception.status_code, 403)
        main.ADMIN_TOKEN = ""
        # Sin ADMIN_TOKEN configurado, el admin queda cerrado.
        with self.assertRaises(HTTPException) as ctx2:
            main.require_admin("Bearer lo-que-sea")
        self.assertEqual(ctx2.exception.status_code, 403)

    # ── Dar de baja una sede (quitarla del panel) ───────────────────────
    def test_delete_site_removes_it_from_panel(self):
        master = main._resolve_principal(self.org)
        self.assertIn("bogota", {s["site_id"] for s in main.list_sites(p=master)["sites"]})
        out = main.delete_site("bogota", p=master)
        self.assertTrue(out["ok"])
        self.assertNotIn("bogota", {s["site_id"] for s in main.list_sites(p=master)["sites"]})
        # Medellín sigue intacta.
        self.assertIn("medellin", {s["site_id"] for s in main.list_sites(p=master)["sites"]})

    def test_delete_unknown_site_404(self):
        master = main._resolve_principal(self.org)
        with self.assertRaises(HTTPException) as ctx:
            main.delete_site("no-existe", p=master)
        self.assertEqual(ctx.exception.status_code, 404)

    def test_delete_site_clears_watchdog_state(self):
        # Una sede eliminada NO debe generar un aviso de "sin conexión" tardío.
        master = main._resolve_principal(self.org)
        main._SITE_WATCH.setdefault(self.org, {})["bogota"] = {
            "state": "online", "since": main._now()}
        main.delete_site("bogota", p=master)
        self.assertNotIn("bogota", main._SITE_WATCH.get(self.org, {}))

    def test_scoped_user_cannot_delete_site(self):
        main._ACCESS[self.org] = {
            "u": {"name": "U", "role": "siteAdmin", "sites": ["bogota"]}}
        with self.assertRaises(HTTPException) as ctx:
            main.delete_site("bogota", p=main.require_master(
                p=main._resolve_principal("u")))
        self.assertEqual(ctx.exception.status_code, 403)


class FleetThreatsTests(unittest.TestCase):
    """Centro de Amenazas de Flota (/v1/threats): clasificación cruzada de sedes."""

    def setUp(self):
        main._STORE.clear()
        main._ACCESS.clear()
        self.org = "org-threats-token-abcd"

    def _threats(self):
        return main.fleet_threats(p=main._resolve_principal(self.org))

    def test_classifies_all_threat_types(self):
        # bogotá: intruso vetado, itinerante, evasivo (MAC privada), bloqueo local.
        _seed_site(self.org, "bogota", "Bogotá", devices=[
            {"mac": "AA:BB:CC:00:00:01", "name": "Vetado", "trust": "blocked", "online": False},
            {"mac": "11:22:33:44:55:66", "name": "Rondador", "trust": "unknown", "online": True},
            {"mac": "A6:00:00:00:00:99", "name": "Fantasma", "trust": "unknown", "online": True},
            {"mac": "00:11:22:33:44:55", "name": "SoloBloqueado", "trust": "blocked", "online": False},
        ])
        # medellín: el vetado y el rondador reaparecen.
        _seed_site(self.org, "medellin", "Medellín", devices=[
            {"mac": "AA:BB:CC:00:00:01", "name": "Vetado", "trust": "unknown", "online": True},
            {"mac": "11:22:33:44:55:66", "name": "Rondador", "trust": "unknown", "online": True},
        ])
        out = self._threats()
        by_mac = {t["mac"]: t for t in out["threats"]}
        self.assertEqual(by_mac["AA:BB:CC:00:00:01"]["type"], "known_bad_roaming")
        self.assertEqual(by_mac["AA:BB:CC:00:00:01"]["severity"], "critical")
        self.assertEqual(by_mac["11:22:33:44:55:66"]["type"], "roaming_unknown")
        self.assertEqual(by_mac["11:22:33:44:55:66"]["severity"], "high")
        self.assertEqual(by_mac["A6:00:00:00:00:99"]["type"], "evasive_unknown")
        self.assertEqual(by_mac["00:11:22:33:44:55"]["type"], "blocked")
        # Resumen coherente y orden por severidad (crítica primero).
        self.assertEqual(out["summary"]["critical"], 1)
        self.assertEqual(out["summary"]["high"], 1)
        self.assertEqual(out["summary"]["total"], 4)
        self.assertEqual(out["summary"]["sites"], 2)
        self.assertEqual(out["threats"][0]["severity"], "critical")

    def test_scope_filters_threats(self):
        # Un usuario con alcance a una sola sede no ve amenazas de otra.
        _seed_site(self.org, "bogota", "Bogotá", devices=[
            {"mac": "11:22:33:44:55:66", "name": "X", "trust": "unknown", "online": True}])
        _seed_site(self.org, "medellin", "Medellín", devices=[
            {"mac": "11:22:33:44:55:66", "name": "X", "trust": "unknown", "online": True}])
        main._ACCESS[self.org] = {
            "u-bog": {"name": "Ana", "role": "auditor", "sites": ["bogota"]}}
        scoped = main.fleet_threats(p=main._resolve_principal("u-bog"))
        # Solo ve una sede → el itinerante deja de serlo (no hay correlación cruzada).
        roaming = [t for t in scoped["threats"] if t["type"] == "roaming_unknown"]
        self.assertEqual(roaming, [])


if __name__ == "__main__":
    unittest.main()
