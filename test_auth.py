"""Tests de Auth-1 (SaaS): verificación del login de Supabase en el relay.

Se acuñan JWT HS256 de prueba con un secreto local (como los que emite Supabase)
y se comprueba: (1) un login válido identifica al usuario y le da SU organización,
(2) dos usuarios quedan AISLADOS, (3) lo inválido/expirado/no-configurado cae al
modelo de token opaco de siempre (compatibilidad hacia atrás).
"""
import importlib
import os
import time
import unittest

import jwt

TEST_SECRET = "test-supabase-jwt-secret-0123456789abcdef"


def _mint(sub: str, *, email: str = "", exp_delta: int = 3600,
          aud: str = "authenticated", secret: str = TEST_SECRET,
          iss: str | None = None) -> str:
    payload = {"sub": sub, "aud": aud, "exp": int(time.time()) + exp_delta}
    if email:
        payload["email"] = email
    if iss:
        payload["iss"] = iss
    return jwt.encode(payload, secret, algorithm="HS256")


class SupabaseAuthTests(unittest.TestCase):
    def setUp(self):
        os.environ["SUPABASE_JWT_SECRET"] = TEST_SECRET
        os.environ.pop("SUPABASE_URL", None)
        # Importar/recargar después de fijar el entorno.
        import auth
        import main
        importlib.reload(auth)
        importlib.reload(main)
        self.auth = auth
        self.main = main
        main._STORE.clear()
        main._COMMANDS.clear()
        main._ORG_CONFIG.clear()
        main._ACCESS.clear()

    def tearDown(self):
        os.environ.pop("SUPABASE_JWT_SECRET", None)
        os.environ.pop("SUPABASE_URL", None)

    # ── verify_supabase_jwt ──────────────────────────────────────────────
    def test_valid_jwt_returns_claims(self):
        claims = self.auth.verify_supabase_jwt(_mint("user-A", email="a@x.com"))
        self.assertIsNotNone(claims)
        self.assertEqual(claims["sub"], "user-A")
        self.assertEqual(claims["email"], "a@x.com")

    def test_bad_signature_rejected(self):
        tok = _mint("user-A", secret="otro-secreto-distinto-xxxxxxxxxxxx")
        self.assertIsNone(self.auth.verify_supabase_jwt(tok))

    def test_expired_rejected(self):
        self.assertIsNone(self.auth.verify_supabase_jwt(_mint("user-A", exp_delta=-10)))

    def test_opaque_token_is_not_a_jwt(self):
        # Un token opaco (el modelo viejo) no tiene forma de JWT → None.
        self.assertIsNone(self.auth.verify_supabase_jwt("org-token-opaco-1234"))

    def test_no_secret_configured_no_verification(self):
        os.environ.pop("SUPABASE_JWT_SECRET", None)
        self.assertIsNone(self.auth.verify_supabase_jwt(_mint("user-A")))

    # ── P0.2: endurecimiento ─────────────────────────────────────────────
    def test_require_asymmetric_rejects_hs256(self):
        """Con AUTH_REQUIRE_ASYMMETRIC, un HS256 se rechaza aunque la firma cuadre
        (el relay no debe confiar en un secreto capaz de FIRMAR identidades)."""
        os.environ["AUTH_REQUIRE_ASYMMETRIC"] = "1"
        try:
            self.assertIsNone(
                self.auth.verify_supabase_jwt(_mint("user-A", email="a@x.com")))
        finally:
            os.environ.pop("AUTH_REQUIRE_ASYMMETRIC", None)
        # Sin la bandera, el mismo token se acepta (compat).
        self.assertIsNotNone(self.auth.verify_supabase_jwt(_mint("user-A")))

    def test_issuer_mismatch_rejected_when_url_set(self):
        """Con SUPABASE_URL fijado, un token cuyo `iss` es de OTRO proyecto se
        rechaza; el del proyecto correcto se acepta. Un token sin `iss` sigue
        pasando (no se exige, por compat)."""
        os.environ["SUPABASE_URL"] = "https://proj.supabase.co"
        try:
            good = _mint("user-A", iss="https://proj.supabase.co/auth/v1")
            evil = _mint("user-A", iss="https://evil.example.com/auth/v1")
            self.assertIsNotNone(self.auth.verify_supabase_jwt(good))
            self.assertIsNone(self.auth.verify_supabase_jwt(evil))
            # Sin iss → se acepta (no se exige el claim).
            self.assertIsNotNone(self.auth.verify_supabase_jwt(_mint("user-A")))
        finally:
            os.environ.pop("SUPABASE_URL", None)

    # ── principal(): identidad SaaS ──────────────────────────────────────
    def test_principal_from_jwt_is_owner_of_own_org(self):
        p = self.main.principal(authorization=f"Bearer {_mint('user-A', email='a@x.com')}")
        self.assertTrue(p.is_master)
        self.assertEqual(p.org_token, "user-A")   # su org = su UUID
        self.assertEqual(p.role, "owner")
        self.assertEqual(p.name, "a@x.com")

    def test_two_users_are_isolated(self):
        pa = self.main.principal(authorization=f"Bearer {_mint('user-A')}")
        pb = self.main.principal(authorization=f"Bearer {_mint('user-B')}")
        # A registra una sede.
        hb = self.main.Heartbeat(site_id="casa", site_name="Casa de A")
        self.main.heartbeat(hb, p=pa)
        # A la ve; B NO ve nada (organizaciones aisladas por sub).
        self.assertEqual(
            [s["site_id"] for s in self.main.list_sites(p=pa)["sites"]], ["casa"])
        self.assertEqual(self.main.list_sites(p=pb)["sites"], [])

    def test_opaque_token_still_works_backward_compat(self):
        # Con Supabase configurado, un token OPACO (no JWT) sigue siendo dueño de
        # su propia org keyed por el token (modelo de siempre).
        p = self.main.principal(authorization="Bearer org-clasico-abcdef123")
        self.assertTrue(p.is_master)
        self.assertEqual(p.org_token, "org-clasico-abcdef123")


if __name__ == "__main__":
    unittest.main()
