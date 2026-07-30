"""Verificación del inicio de sesión de Supabase (Auth-1 del modelo SaaS).

Cada cliente se registra en la app con **correo + contraseña** (Supabase Auth).
Supabase le entrega un **JWT** firmado; la app lo manda al relay como
``Authorization: Bearer <jwt>``. Aquí lo **verificamos** y sacamos su identidad:
el claim ``sub`` (UUID del usuario) se usa como **organización** → cada cliente
queda aislado automáticamente, sin repartir tokens a mano.

100% ADITIVO y compatible hacia atrás:
- Si NO hay configuración de Supabase (ni ``SUPABASE_JWT_SECRET`` ni
  ``SUPABASE_URL``), o el Bearer no es un JWT válido, ``verify_supabase_jwt``
  devuelve ``None`` y el relay cae al modelo de token opaco de siempre. Así,
  desplegar este módulo sin configurar nada **no cambia nada**.

Soporta las dos formas de firmar de Supabase:
- **HS256** con el secreto simétrico ``SUPABASE_JWT_SECRET`` (Project Settings →
  API → JWT Secret).
- **RS256/ES256** (claves asimétricas nuevas) verificando contra el JWKS público
  del proyecto: ``{SUPABASE_URL}/auth/v1/.well-known/jwks.json``.
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

# El claim `aud` de un usuario autenticado en Supabase.
_AUD = os.environ.get("SUPABASE_JWT_AUD", "authenticated")

# Cliente JWKS perezoso (para firmas asimétricas). Cachea las llaves.
_jwk_client = None
_jwk_client_ready = False


def _jwks_url() -> str | None:
    base = os.environ.get("SUPABASE_URL", "").strip().rstrip("/")
    if not base:
        return None
    return f"{base}/auth/v1/.well-known/jwks.json"


def _get_jwk_client():
    """Devuelve un PyJWKClient cacheado o None si no hay SUPABASE_URL/PyJWT."""
    global _jwk_client, _jwk_client_ready
    if _jwk_client_ready:
        return _jwk_client
    _jwk_client_ready = True
    url = _jwks_url()
    if not url:
        return None
    try:
        from jwt import PyJWKClient

        _jwk_client = PyJWKClient(url, cache_keys=True)
    except Exception as exc:  # noqa: BLE001 - degradar con elegancia
        logger.warning("No se pudo iniciar el cliente JWKS: %s", exc)
        _jwk_client = None
    return _jwk_client


def verify_supabase_jwt(token: str) -> dict | None:
    """Verifica un JWT de Supabase. Devuelve sus claims si es válido, o None.

    None significa "no es un login de Supabase válido" → el llamador debe tratar
    el Bearer con el modelo de token opaco (compatibilidad hacia atrás). Nunca
    lanza: cualquier fallo de verificación devuelve None (falla cerrado)."""
    if not token or token.count(".") != 2:
        return None  # no tiene forma de JWT → es un token opaco
    try:
        import jwt
    except Exception:  # noqa: BLE001 - PyJWT no instalado → sin verificación JWT
        return None

    try:
        header = jwt.get_unverified_header(token)
    except Exception:
        return None
    alg = header.get("alg", "")

    try:
        if alg == "HS256":
            secret = os.environ.get("SUPABASE_JWT_SECRET", "").strip()
            if not secret:
                return None
            return jwt.decode(
                token, secret, algorithms=["HS256"], audience=_AUD,
                options={"require": ["exp", "sub"]},
            )
        if alg in ("RS256", "ES256"):
            client = _get_jwk_client()
            if client is None:
                return None
            signing_key = client.get_signing_key_from_jwt(token).key
            return jwt.decode(
                token, signing_key, algorithms=[alg], audience=_AUD,
                options={"require": ["exp", "sub"]},
            )
    except Exception as exc:  # noqa: BLE001 - firma/exp/aud inválidos → None
        logger.debug("JWT de Supabase rechazado: %s", exc)
        return None
    return None  # algoritmo no soportado


def supabase_auth_configured() -> bool:
    """True si hay alguna vía de verificación configurada (secreto o JWKS)."""
    return bool(
        os.environ.get("SUPABASE_JWT_SECRET", "").strip() or _jwks_url()
    )
