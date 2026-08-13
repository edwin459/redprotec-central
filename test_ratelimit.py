"""Tests del rate limiting / bloqueo por fuerza bruta (P0.3).

Se inyecta el tiempo (`now`) para probar ventanas y expiración de forma
determinista, sin `sleep`.
"""
import unittest

from ratelimit import FailureLockout, SlidingWindow, client_ip


class SlidingWindowTests(unittest.TestCase):
    def test_allows_up_to_max_then_blocks(self):
        w = SlidingWindow(max_events=3, window_seconds=10)
        t = 1000.0
        self.assertTrue(w.hit("ip", t))
        self.assertTrue(w.hit("ip", t))
        self.assertTrue(w.hit("ip", t))
        self.assertFalse(w.hit("ip", t))  # el 4º excede

    def test_window_slides(self):
        w = SlidingWindow(2, 10)
        self.assertTrue(w.hit("ip", 100.0))
        self.assertTrue(w.hit("ip", 105.0))
        self.assertFalse(w.hit("ip", 106.0))
        # Cuando la 1ª sale de la ventana (>110) vuelve a permitir.
        self.assertTrue(w.hit("ip", 111.0))

    def test_keys_are_independent(self):
        w = SlidingWindow(1, 10)
        self.assertTrue(w.hit("a", 1.0))
        self.assertTrue(w.hit("b", 1.0))
        self.assertFalse(w.hit("a", 1.0))


class FailureLockoutTests(unittest.TestCase):
    def test_locks_after_max_failures_and_expires(self):
        f = FailureLockout(max_failures=3, window_seconds=60, lock_seconds=120)
        t = 500.0
        self.assertFalse(f.record_failure("ip", t))
        self.assertFalse(f.record_failure("ip", t))
        self.assertTrue(f.record_failure("ip", t))   # el 3º dispara el bloqueo
        self.assertTrue(f.is_locked("ip", t))
        self.assertTrue(f.is_locked("ip", t + 119))
        self.assertFalse(f.is_locked("ip", t + 121))  # el bloqueo expira

    def test_success_resets_failures(self):
        f = FailureLockout(2, 60, 120)
        t = 10.0
        f.record_failure("ip", t)
        f.record_success("ip")
        self.assertFalse(f.record_failure("ip", t))  # contador reiniciado

    def test_old_failures_leave_window(self):
        f = FailureLockout(2, 30, 100)
        self.assertFalse(f.record_failure("ip", 0.0))
        # El primer fallo sale de la ventana (>30) → no acumula para bloquear.
        self.assertFalse(f.record_failure("ip", 40.0))
        self.assertFalse(f.is_locked("ip", 40.0))


class ClientIpTests(unittest.TestCase):
    def test_uses_first_xff(self):
        self.assertEqual(
            client_ip({"x-forwarded-for": "1.2.3.4, 5.6.7.8"}, "9.9.9.9"),
            "1.2.3.4")

    def test_falls_back_to_direct(self):
        self.assertEqual(client_ip({}, "9.9.9.9"), "9.9.9.9")

    def test_unknown_when_nothing(self):
        self.assertEqual(client_ip({}, ""), "unknown")


if __name__ == "__main__":
    unittest.main()
