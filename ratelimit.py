"""Rate limiting y bloqueo por fallos de autenticación (en memoria, por IP).

El relay corre en una sola instancia, así que un contador en memoria basta y
evita dependencias externas. Dos defensas complementarias (P0.3):

- **Límite global por IP** (`SlidingWindow`): frena inundaciones — una IP que
  dispara cientos de peticiones por minuto recibe 429.
- **Bloqueo por fallos de auth** (`FailureLockout`): tras N respuestas 401/403
  desde una IP en una ventana, esa IP queda BLOQUEADA un rato. Es la defensa
  contra fuerza bruta del `ADMIN_TOKEN` o de tokens/JWT.

Los umbrales se configuran por entorno; los valores por defecto son generosos
con el uso normal (la app hace polling) y estrictos con los fallos.
"""
from __future__ import annotations

import os
import threading
import time
from collections import deque
from typing import Mapping


def int_env(name: str, default: int) -> int:
    try:
        return int((os.environ.get(name, "") or "").strip() or default)
    except ValueError:
        return default


class SlidingWindow:
    """Cuenta eventos por clave dentro de una ventana deslizante."""

    def __init__(self, max_events: int, window_seconds: int):
        self.max = max_events
        self.window = window_seconds
        self._events: dict[str, deque] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, now: float | None = None) -> bool:
        """Registra un evento. True si está dentro del límite, False si lo excede
        (en cuyo caso el evento NO se cuenta, para no penalizar de más)."""
        now = time.time() if now is None else now
        with self._lock:
            dq = self._events.setdefault(key, deque())
            cutoff = now - self.window
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= self.max:
                return False
            dq.append(now)
            return True


class FailureLockout:
    """Bloquea una clave (IP) tras demasiados fallos de auth en una ventana."""

    def __init__(self, max_failures: int, window_seconds: int, lock_seconds: int):
        self.max = max_failures
        self.window = window_seconds
        self.lock = lock_seconds
        self._fails: dict[str, deque] = {}
        self._locked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def is_locked(self, key: str, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        with self._lock:
            until = self._locked_until.get(key, 0.0)
            if until > now:
                return True
            if until:
                self._locked_until.pop(key, None)
            return False

    def record_failure(self, key: str, now: float | None = None) -> bool:
        """Registra un fallo de auth. Devuelve True si disparó el bloqueo."""
        now = time.time() if now is None else now
        with self._lock:
            dq = self._fails.setdefault(key, deque())
            cutoff = now - self.window
            while dq and dq[0] < cutoff:
                dq.popleft()
            dq.append(now)
            if len(dq) >= self.max:
                self._locked_until[key] = now + self.lock
                dq.clear()
                return True
            return False

    def record_success(self, key: str) -> None:
        """Un acceso válido limpia el historial de fallos de esa IP."""
        with self._lock:
            self._fails.pop(key, None)
            self._locked_until.pop(key, None)


def client_ip(headers: Mapping[str, str], fallback: str) -> str:
    """IP real del cliente detrás de un proxy (Railway): primer valor de
    `X-Forwarded-For`; si no lo hay, la IP directa de la conexión."""
    xff = headers.get("x-forwarded-for") or headers.get("X-Forwarded-For")
    if xff:
        first = xff.split(",")[0].strip()
        if first:
            return first
    return fallback or "unknown"
