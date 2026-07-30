"""Auth-3C — **permiso firmado con caducidad** del entitlement.

El relay es la única fuente de verdad del plan (Free/Pro). Para que el agente y
el móvil no puedan ser engañados (un proxy que devuelva ``can_control:true``, o
un plan compartido), el relay **firma** el entitlement con una llave privada y
publica solo la **llave pública**. El cliente verifica la firma y la caducidad
antes de confiar en el veredicto.

Diseño sin que el dueño toque nada (pero permitiendo fijarla por entorno):
- La llave privada se toma de ``ENTITLEMENT_PRIVATE_KEY`` (PEM) si está definida;
  si no, se genera una Ed25519 y se **persiste** en el almacén (``relay_kv``), de
  modo que sobrevive reinicios y es estable para todos los clientes.
- Se firma un JWT **EdDSA** compacto con ``exp`` (caducidad corta + gracia). El
  cliente lo verifica con la llave pública que sirve ``/v1/entitlement/pubkey``.

Nunca se expone la llave privada: el endpoint público solo entrega la pública.
"""

from __future__ import annotations

import os
import threading
from datetime import datetime, timedelta, timezone

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Clave del almacén donde se guarda la llave privada PEM (singleton del relay).
_KV_PRIVATE_KEY = "entitlement_signing_key_ed25519_pem"
# Vida del permiso firmado. Corta para limitar el uso de un token robado, pero
# con holgura para el agente offline (el cliente honra el último válido). El
# latido llega cada ~60s, así que 2 días es amplio.
SIGNED_TTL_SECONDS = int(os.environ.get("ENTITLEMENT_TOKEN_TTL", str(2 * 24 * 3600)))

_lock = threading.Lock()
_cached_private: Ed25519PrivateKey | None = None
_cached_public_pem: str | None = None


def _load_from_env() -> Ed25519PrivateKey | None:
    pem = os.environ.get("ENTITLEMENT_PRIVATE_KEY", "").strip()
    if not pem:
        return None
    key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("ENTITLEMENT_PRIVATE_KEY no es una llave Ed25519")
    return key


def _private_pem(key: Ed25519PrivateKey) -> str:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def _public_pem(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def _get_private_key(store) -> Ed25519PrivateKey:
    """Devuelve la llave privada (env > almacén > generada+persistida). Cacheada."""
    global _cached_private, _cached_public_pem
    if _cached_private is not None:
        return _cached_private
    with _lock:
        if _cached_private is not None:
            return _cached_private
        key = _load_from_env()
        if key is None:
            # ¿Ya hay una guardada en el almacén? (persiste entre reinicios).
            stored = None
            try:
                stored = store.kv_get(_KV_PRIVATE_KEY)
            except Exception:  # noqa: BLE001 - almacén no listo → se genera efímera
                stored = None
            if stored:
                loaded = serialization.load_pem_private_key(
                    stored.encode("utf-8"), password=None)
                if isinstance(loaded, Ed25519PrivateKey):
                    key = loaded
            if key is None:
                key = Ed25519PrivateKey.generate()
                try:
                    store.kv_set(_KV_PRIVATE_KEY, _private_pem(key))
                except Exception:  # noqa: BLE001 - sin persistencia igual firma
                    pass
        _cached_private = key
        _cached_public_pem = _public_pem(key)
        return key


def public_key_pem(store) -> str:
    """PEM de la llave PÚBLICA (segura de publicar). El cliente la fija y verifica."""
    if _cached_public_pem is not None:
        return _cached_public_pem
    _get_private_key(store)
    return _cached_public_pem or ""


def sign_entitlement(store, org: str, claims: dict,
                     *, now: datetime | None = None) -> str:
    """Firma el entitlement como JWT EdDSA con caducidad. `claims` son los campos
    del plan (plan, effective, can_control, max_sites, trial_days_left)."""
    now = now or datetime.now(timezone.utc)
    key = _get_private_key(store)
    payload = {
        **claims,
        "sub": org,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=SIGNED_TTL_SECONDS)).timestamp()),
        "iss": "redprotec-relay",
    }
    return jwt.encode(payload, _private_pem(key), algorithm="EdDSA")


def _reset_cache_for_tests() -> None:
    """Solo para pruebas: olvida la llave cacheada."""
    global _cached_private, _cached_public_pem
    with _lock:
        _cached_private = None
        _cached_public_pem = None
