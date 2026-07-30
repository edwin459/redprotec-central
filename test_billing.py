"""Auth-3C: Google Play Billing en el relay — caminos seguros sin credenciales."""

import base64
import json
import unittest

import billing_play
import main
from fastapi import HTTPException


class BillingConfigTests(unittest.TestCase):
    def setUp(self):
        billing_play._reset_cache_for_tests()

    def test_not_configured_by_default(self):
        # Sin GOOGLE_PLAY_SA_JSON/PLAY_PACKAGE_NAME → inerte y seguro.
        self.assertFalse(billing_play.is_configured())
        self.assertFalse(main.play_billing_config()["enabled"])

    def test_verify_returns_503_when_not_configured(self):
        with self.assertRaises(HTTPException) as ctx:
            main.play_verify(
                main.PlayVerifyIn(purchase_token="tok-abc-123456"),
                p=main._resolve_principal("org-x"))
        self.assertEqual(ctx.exception.status_code, 503)

    def test_verify_subscription_none_without_creds(self):
        self.assertIsNone(billing_play.verify_subscription("tok-abc-123456"))


class RtdnTests(unittest.TestCase):
    def setUp(self):
        billing_play._reset_cache_for_tests()
        main.RTDN_SECRET = ""

    def _push(self, note: dict) -> dict:
        raw = base64.b64encode(json.dumps(note).encode()).decode()
        return {"message": {"data": raw}}

    def test_decode_rtdn_roundtrip(self):
        note = {"subscriptionNotification": {"purchaseToken": "pt-1", "notificationType": 4}}
        self.assertEqual(billing_play.decode_rtdn(self._push(note)), note)

    def test_rtdn_unknown_token_is_ignored(self):
        note = {"subscriptionNotification": {"purchaseToken": "no-existe"}}
        out = main.play_rtdn(self._push(note))
        self.assertTrue(out["ok"])
        self.assertEqual(out.get("ignored"), "unknown_token")

    def test_rtdn_bad_secret_rejected(self):
        main.RTDN_SECRET = "s3cr3t"
        try:
            with self.assertRaises(HTTPException) as ctx:
                main.play_rtdn({"message": {"data": ""}}, secret="malo")
            self.assertEqual(ctx.exception.status_code, 403)
        finally:
            main.RTDN_SECRET = ""

    def test_rtdn_no_token_noop(self):
        out = main.play_rtdn(self._push({"testNotification": {"version": "1"}}))
        self.assertTrue(out["ok"])


if __name__ == "__main__":
    unittest.main()
