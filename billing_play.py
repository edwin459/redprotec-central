"""Auth-3C — verificación de compras de **Google Play Billing** (suscripción Pro).

El móvil (Play) hace la compra con Google Play Billing y manda al relay el
``purchaseToken``. El relay lo **verifica con la API de Google Play Developer**
(no se fía del cliente) y, si la suscripción está activa, marca la cuenta como
Pro. Los cambios posteriores (renovación, cancelación, reembolso) llegan por
**RTDN** (Real-time Developer Notifications, un push de Pub/Sub) y actualizan el
plan.

Sin credenciales configuradas, TODO queda **inerte y seguro**: `is_configured()`
es False y `verify_subscription` devuelve None → el endpoint responde "no
configurado" y NADIE se vuelve Pro por engaño. Se enciende poniendo en el host
(Railway), por canal seguro y como variables de entorno (NUNCA en el repo/chat):

- ``GOOGLE_PLAY_SA_JSON``  = el JSON de la cuenta de servicio (androidpublisher).
- ``PLAY_PACKAGE_NAME``    = el applicationId de la app (ej. com.redprotec.app).

Implementación sin dependencias nuevas: el flujo OAuth2 de cuenta de servicio se
hace firmando un JWT (RS256) con PyJWT —ya presente— y llamando por ``urllib``.
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.parse
import urllib.request

logger = logging.getLogger(__name__)

_TOKEN_URI = "https://oauth2.googleapis.com/token"
_SCOPE = "https://www.googleapis.com/auth/androidpublisher"
_API = "https://androidpublisher.googleapis.com/androidpublisher/v3"

# Estados de la API subscriptionsv2 que consideramos "con derecho a Pro".
_ACTIVE_STATES = {
    "SUBSCRIPTION_STATE_ACTIVE",
    "SUBSCRIPTION_STATE_IN_GRACE_PERIOD",
    "SUBSCRIPTION_STATE_CANCELED",  # cancelada pero aún dentro del periodo pagado
}

_cached_sa: dict | None = None
_cached_token: tuple[str, float] | None = None  # (access_token, expira_en_epoch)


def _service_account() -> dict | None:
    global _cached_sa
    if _cached_sa is not None:
        return _cached_sa
    raw = os.environ.get("GOOGLE_PLAY_SA_JSON", "").strip()
    if not raw:
        return None
    try:
        _cached_sa = json.loads(raw)
        return _cached_sa
    except Exception as exc:  # noqa: BLE001
        logger.error("GOOGLE_PLAY_SA_JSON no es un JSON válido: %s", exc)
        return None


def package_name() -> str:
    return os.environ.get("PLAY_PACKAGE_NAME", "").strip()


def is_configured() -> bool:
    """¿Están las credenciales para verificar con Google? Si no, todo queda inerte."""
    return _service_account() is not None and bool(package_name())


def _access_token() -> str | None:
    """Obtiene un access token de Google vía JWT-bearer de cuenta de servicio."""
    global _cached_token
    if _cached_token and _cached_token[1] - 60 > time.time():
        return _cached_token[0]
    sa = _service_account()
    if sa is None:
        return None
    try:
        import jwt
        now = int(time.time())
        assertion = jwt.encode(
            {
                "iss": sa["client_email"],
                "scope": _SCOPE,
                "aud": sa.get("token_uri", _TOKEN_URI),
                "iat": now,
                "exp": now + 3600,
            },
            sa["private_key"],
            algorithm="RS256",
        )
        data = urllib.parse.urlencode({
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion,
        }).encode()
        req = urllib.request.Request(
            sa.get("token_uri", _TOKEN_URI), data=data, method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urllib.request.urlopen(req, timeout=12) as resp:  # noqa: S310
            body = json.loads(resp.read().decode("utf-8"))
        tok = body.get("access_token")
        if tok:
            _cached_token = (tok, time.time() + int(body.get("expires_in", 3600)))
            return tok
    except Exception as exc:  # noqa: BLE001
        logger.error("No se pudo obtener el token de Google Play: %s", exc)
    return None


def verify_subscription(purchase_token: str) -> dict | None:
    """Consulta la suscripción por su token (subscriptionsv2). Devuelve un dict
    ``{active: bool, state, expiry_ms}`` o None si no se puede verificar."""
    if not is_configured():
        return None
    token = _access_token()
    if not token:
        return None
    pkg = package_name()
    url = f"{_API}/applications/{pkg}/purchases/subscriptionsv2/tokens/{purchase_token}"
    try:
        req = urllib.request.Request(
            url, method="GET", headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req, timeout=12) as resp:  # noqa: S310
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        logger.warning("Verificación de suscripción falló: %s", exc)
        return None
    state = data.get("subscriptionState", "")
    expiry_ms = None
    for li in data.get("lineItems", []) or []:
        et = li.get("expiryTime")
        if et:
            expiry_ms = et  # ISO8601; se guarda tal cual para trazabilidad
            break
    return {"active": state in _ACTIVE_STATES, "state": state, "expiry": expiry_ms}


def decode_rtdn(message: dict) -> dict | None:
    """Extrae la notificación de desarrollador de un push RTDN (Pub/Sub).

    El cuerpo trae ``message.data`` en base64 con un JSON
    ``{subscriptionNotification:{purchaseToken,...}}``. Devuelve ese dict o None."""
    import base64
    try:
        data_b64 = (message.get("message") or {}).get("data") or message.get("data")
        if not data_b64:
            return None
        return json.loads(base64.b64decode(data_b64).decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        logger.warning("RTDN ilegible: %s", exc)
        return None


def _reset_cache_for_tests() -> None:
    global _cached_sa, _cached_token
    _cached_sa = None
    _cached_token = None
