"""Auth-3C: el permiso firmado del entitlement (anti-manipulación)."""

import unittest
from datetime import datetime, timedelta, timezone

import jwt

import signing
import store as store_mod


class SigningTests(unittest.TestCase):
    def setUp(self):
        signing._reset_cache_for_tests()
        self.store = store_mod.MemoryStore({}, {}, {}, {})

    def _sign(self, org="org-1", **claims):
        base = {"plan": "pro", "effective": "pro", "can_control": True,
                "max_sites": 5, "trial_days_left": 0}
        base.update(claims)
        return signing.sign_entitlement(self.store, org, base)

    def test_sign_and_verify_with_public_key(self):
        tok = self._sign()
        pub = signing.public_key_pem(self.store)
        dec = jwt.decode(tok, pub, algorithms=["EdDSA"],
                         options={"require": ["exp", "sub"]})
        self.assertEqual(dec["sub"], "org-1")
        self.assertTrue(dec["can_control"])
        self.assertEqual(dec["iss"], "redprotec-relay")

    def test_key_is_persisted_and_stable(self):
        self._sign()
        pub1 = signing.public_key_pem(self.store)
        stored = self.store.kv_get("entitlement_signing_key_ed25519_pem")
        self.assertIsNotNone(stored)
        # Un relay que reinicia (cache limpia) reusa la MISMA llave del almacén.
        signing._reset_cache_for_tests()
        pub2 = signing.public_key_pem(self.store)
        self.assertEqual(pub1, pub2)

    def test_forged_token_fails_verification(self):
        pub = signing.public_key_pem(self.store)
        # Token firmado con OTRA llave (atacante) → no verifica con la pública real.
        signing._reset_cache_for_tests()
        other_store = store_mod.MemoryStore({}, {}, {}, {})
        forged = signing.sign_entitlement(
            other_store, "org-1", {"plan": "pro", "can_control": True})
        with self.assertRaises(jwt.InvalidSignatureError):
            jwt.decode(forged, pub, algorithms=["EdDSA"])

    def test_expired_token_rejected(self):
        # Firma con caducidad en el pasado → verificación falla por exp.
        old = datetime.now(timezone.utc) - timedelta(days=10)
        tok = signing.sign_entitlement(
            self.store, "org-1",
            {"plan": "pro", "can_control": True},
            now=old,
        )
        pub = signing.public_key_pem(self.store)
        with self.assertRaises(jwt.ExpiredSignatureError):
            jwt.decode(tok, pub, algorithms=["EdDSA"])

    def test_env_key_takes_precedence(self):
        # Si el dueño fija ENTITLEMENT_PRIVATE_KEY, se usa esa (no se genera).
        import os
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        signing._reset_cache_for_tests()
        os.environ["ENTITLEMENT_PRIVATE_KEY"] = pem
        try:
            expected_pub = key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode()
            self.assertEqual(signing.public_key_pem(self.store), expected_pub)
            # No se persiste nada (la llave viene del entorno).
            self.assertIsNone(
                self.store.kv_get("entitlement_signing_key_ed25519_pem"))
        finally:
            del os.environ["ENTITLEMENT_PRIVATE_KEY"]
            signing._reset_cache_for_tests()


if __name__ == "__main__":
    unittest.main()
