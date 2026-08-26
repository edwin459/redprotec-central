"""IA de identificación en el relay: caché global (gratis para todos), gate por
plan, topes de gasto y parseo. Sin LLM real (se mockea la llamada)."""
import json
import unittest

import ai_identify


class _FakeStore:
    def __init__(self):
        self.kv = {}
    def kv_get(self, k):
        return self.kv.get(k)
    def kv_set(self, k, v):
        self.kv[k] = v


class AiIdentifyTests(unittest.TestCase):
    def setUp(self):
        self.store = _FakeStore()
        self._orig_call = ai_identify._call_gemini
        self._orig_key = ai_identify._GEMINI_KEY
        ai_identify._GEMINI_KEY = "test-key"  # enabled()

    def tearDown(self):
        ai_identify._call_gemini = self._orig_call
        ai_identify._GEMINI_KEY = self._orig_key

    def test_parse_and_signature(self):
        r = ai_identify.parse_model('{"model":"iPhone 14","category":"smartphone","confidence":88,"reason":"x"}')
        self.assertEqual(r["model"], "iPhone 14")
        self.assertEqual(r["confidence"], 88)
        self.assertIsNone(ai_identify.parse_model('{"model":"unknown"}'))
        s1 = ai_identify.signature({"vendor": "Apple", "ports": ["62078"]})
        s2 = ai_identify.signature({"vendor": "Apple", "ports": ["62078"]})
        self.assertEqual(s1, s2)

    def test_pro_calls_llm_and_caches(self):
        ai_identify._call_gemini = lambda *a, **k: '{"model":"Samsung BU8000","category":"tv","confidence":90,"reason":"y"}'
        sig = {"vendor": "Samsung", "hostname": "tv", "ports": ["8009"]}
        out = ai_identify.identify(self.store, "org1", sig, plan_ok=True)
        self.assertTrue(out["available"])
        self.assertEqual(out["model"], "Samsung BU8000")
        self.assertFalse(out["cached"])
        # Segunda vez: acierto de CACHÉ, sin llamar al LLM (aunque sea Free).
        ai_identify._call_gemini = lambda *a, **k: (_ for _ in ()).throw(AssertionError("no debía llamar"))
        out2 = ai_identify.identify(self.store, "orgX", sig, plan_ok=False)
        self.assertTrue(out2["available"])
        self.assertTrue(out2["cached"])
        self.assertEqual(out2["model"], "Samsung BU8000")

    def test_free_without_cache_is_gated(self):
        ai_identify._call_gemini = lambda *a, **k: (_ for _ in ()).throw(AssertionError("Free no debe llamar"))
        out = ai_identify.identify(self.store, "org1", {"vendor": "Dell"}, plan_ok=False)
        self.assertFalse(out["available"])
        self.assertEqual(out["reason"], "plan")

    def test_daily_cap_blocks_new_calls(self):
        day = ai_identify._today()
        self.store.kv_set(f"ai_calls::{day}", str(ai_identify._DAILY_CAP))
        ai_identify._call_gemini = lambda *a, **k: (_ for _ in ()).throw(AssertionError("tope alcanzado"))
        out = ai_identify.identify(self.store, "org1", {"vendor": "HP"}, plan_ok=True)
        self.assertFalse(out["available"])
        self.assertEqual(out["reason"], "rate")

    def test_relay_off_when_no_key(self):
        ai_identify._GEMINI_KEY = ""
        out = ai_identify.identify(self.store, "org1", {"vendor": "HP"}, plan_ok=True)
        self.assertFalse(out["available"])
        self.assertEqual(out["reason"], "relay_ai_off")

    def test_assess_pro_and_cache(self):
        ai_identify._call_gemini = lambda *a, **k: (
            '{"risk_level":"critical","confidence":85,'
            '"findings":[{"title":"Telnet","severity":"critical","detail":"claves de fabrica"}],'
            '"recommendations":["Bloquea el equipo","Cambia la clave"]}'
        )
        sig = {"model": "XMeye DVR", "category": "camera", "ports": ["34567", "23"]}
        out = ai_identify.assess(self.store, "org1", sig, plan_ok=True)
        self.assertTrue(out["available"])
        self.assertEqual(out["risk_level"], "critical")
        self.assertEqual(len(out["findings"]), 1)
        self.assertEqual(len(out["recommendations"]), 2)
        # Caché: sirve gratis a un Free sin llamar al LLM.
        ai_identify._call_gemini = lambda *a, **k: (_ for _ in ()).throw(AssertionError("no debía llamar"))
        out2 = ai_identify.assess(self.store, "orgY", sig, plan_ok=False)
        self.assertTrue(out2["available"])
        self.assertTrue(out2["cached"])
        self.assertEqual(out2["risk_level"], "critical")

    def test_parse_assessment_clamps_and_defaults(self):
        r = ai_identify.parse_assessment('{"risk_level":"weird","confidence":999,"findings":[{"title":"x","severity":"nope","detail":"y"}]}')
        self.assertEqual(r["risk_level"], "low")   # nivel inválido → low
        self.assertEqual(r["confidence"], 100)     # clamp
        self.assertEqual(r["findings"][0]["severity"], "medium")  # severidad inválida → medium


if __name__ == "__main__":
    unittest.main()
