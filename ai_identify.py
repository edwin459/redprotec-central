"""IA de identificación de dispositivos EN EL RELAY — escalable a miles.

Por qué en el relay y no en cada agente:
- **Costo/cuota bajo control**: una sola llave central + rate-limit + tope diario.
  Miles de agentes no revientan la cuota del plan gratis.
- **Gate por plan**: solo Pro/Empresa disparan una consulta NUEVA al LLM; Free usa
  el motor determinista del agente. La IA se vuelve argumento de venta.
- **🔑 Caché global tipo Fing (efecto de red)**: se guarda `hash(señales)→modelo`
  entre TODOS los usuarios. Un acierto de caché se sirve GRATIS a cualquiera (Free
  incluido) sin llamar al LLM. Con el tiempo casi no se llama al modelo → se
  construye una base de identificación propia y el costo tiende a cero.
- **Privacidad**: NUNCA se persiste el hostname ni señales crudas; solo el HASH y
  el resultado (modelo genérico). El hash es de una vía.

Sin dependencias nuevas: urllib (stdlib) para hablar con Gemini.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import urllib.request
from datetime import datetime, timezone

logger = logging.getLogger("redprotec.central.ai")

# Llave central del relay (se configura en Railway). Si está vacía, la IA del
# relay queda apagada → los agentes caen a su LLM local/motor determinista.
_GEMINI_KEY = os.environ.get("RELAY_GEMINI_API_KEY", os.environ.get("GEMINI_API_KEY", "")).strip()
_GEMINI_MODEL = os.environ.get("RELAY_GEMINI_MODEL", "gemini-2.5-flash").strip()
_GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models"

# Topes de gasto (peticiones NUEVAS al LLM; los aciertos de caché no cuentan).
_DAILY_CAP = int(os.environ.get("AI_DAILY_CAP", "5000"))       # global/día
_ORG_DAILY_CAP = int(os.environ.get("AI_ORG_DAILY_CAP", "150"))  # por cuenta/día

_SYSTEM_PROMPT = (
    "Eres un experto en identificar dispositivos de red por sus huellas. Te dan "
    "señales REALES de un equipo en una LAN. Devuelve SOLO un JSON con el MODELO "
    "comercial más probable. Prohibido inventar: si no basta, model=\"unknown\". "
    "Esquema: {\"model\": string, \"category\": string, \"confidence\": int(0-100), "
    "\"reason\": string breve}. category en: smartphone, tablet, laptop, desktop, "
    "tv, streaming, console, camera, printer, router, nas, iot, speaker, wearable, "
    "unknown."
)

_PORT_SERVICE = {
    "62078": "Apple lockdownd (iPhone/iPad)", "554": "RTSP (cámara IP)",
    "8009": "Chromecast", "1400": "Sonos", "9100": "impresora", "631": "IPP",
    "1883": "MQTT (IoT)", "32469": "Plex", "3389": "RDP (Windows)",
    "445": "SMB (Windows)", "37777": "Dahua DVR", "34567": "DVR (XMeye)",
    "23": "Telnet", "22": "SSH", "80": "HTTP", "443": "HTTPS",
}


def signature(sig: dict) -> str:
    raw = "|".join([
        str(sig.get("vendor") or "").lower(),
        str(sig.get("hostname") or "").lower(),
        ",".join(sorted(str(p) for p in (sig.get("ports") or []))),
        str(sig.get("device_type") or "").lower(),
        "r" if sig.get("mac_random") else "u",
    ])
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def build_prompt(sig: dict) -> str:
    lines = ["Señales del equipo:"]
    lines.append(f"- Fabricante (OUI): {sig.get('vendor') or 'desconocido'}")
    if sig.get("mac_random"):
        lines.append("- MAC privada/aleatoria (iOS/Android modernos)")
    lines.append(f"- Hostname: {sig.get('hostname') or '(ninguno)'}")
    ports = [str(p) for p in (sig.get("ports") or [])]
    if ports:
        svc = [f"{p} ({_PORT_SERVICE[p]})" if p in _PORT_SERVICE else p for p in ports]
        lines.append(f"- Puertos/servicios: {', '.join(svc)}")
    if sig.get("device_type"):
        lines.append(f"- Tipo previo: {sig['device_type']}")
    lines.append("\nDevuelve SOLO el JSON del modelo más probable.")
    return "\n".join(lines)


def parse_model(raw: str) -> dict | None:
    if not raw:
        return None
    m = re.search(r"\{.*\}", raw, re.DOTALL)
    if not m:
        return None
    try:
        data = json.loads(m.group(0))
    except (ValueError, TypeError):
        return None
    model = str(data.get("model") or "").strip()
    if not model or model.lower() in ("unknown", "desconocido", "n/a", "none"):
        return None
    try:
        conf = max(0, min(100, int(data.get("confidence") or 0)))
    except (ValueError, TypeError):
        conf = 0
    return {
        "model": model[:120],
        "category": str(data.get("category") or "").strip().lower()[:40],
        "confidence": conf,
        "reason": str(data.get("reason") or "").strip()[:250],
    }


def _call_gemini(system: str, user: str, timeout: float = 20.0) -> str | None:
    if not _GEMINI_KEY:
        return None
    url = f"{_GEMINI_URL}/{_GEMINI_MODEL}:generateContent?key={_GEMINI_KEY}"
    body = json.dumps({
        "system_instruction": {"parts": [{"text": system}]},
        "contents": [{"role": "user", "parts": [{"text": user}]}],
        "generationConfig": {"temperature": 0.1, "response_mime_type": "application/json"},
    }).encode()
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            data = json.loads(resp.read().decode("utf-8", "ignore"))
        return (data.get("candidates") or [{}])[0].get(
            "content", {}).get("parts", [{}])[0].get("text")
    except Exception as exc:  # noqa: BLE001
        logger.warning("Gemini (relay) falló: %s", exc)
        return None


def enabled() -> bool:
    return bool(_GEMINI_KEY)


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d")


def identify(store, org: str, sig: dict, *, plan_ok: bool) -> dict:
    """Resuelve el modelo. Orden: (1) caché global → gratis para todos;
    (2) si falla, gate por plan + topes → llama al LLM y cachea. Devuelve dict con
    `available` y, si hay, model/category/confidence/reason/cached."""
    key = signature(sig)
    cached = store.kv_get(f"aiid::{key}")
    if cached:
        try:
            out = json.loads(cached)
            out["cached"] = True
            out["available"] = True
            return out
        except (ValueError, TypeError):
            pass

    if not enabled():
        return {"available": False, "reason": "relay_ai_off"}
    if not plan_ok:
        return {"available": False, "reason": "plan"}

    # Topes de gasto (solo cuentan las llamadas NUEVAS al LLM).
    day = _today()
    gkey, okey = f"ai_calls::{day}", f"aiorg::{org}::{day}"
    gcount = int(store.kv_get(gkey) or "0")
    ocount = int(store.kv_get(okey) or "0")
    if gcount >= _DAILY_CAP or ocount >= _ORG_DAILY_CAP:
        return {"available": False, "reason": "rate"}

    raw = _call_gemini(_SYSTEM_PROMPT, build_prompt(sig))
    # Contabiliza el intento (aunque falle) para no reintentar en bucle si el LLM
    # está caído — protege la cuota.
    store.kv_set(gkey, str(gcount + 1))
    store.kv_set(okey, str(ocount + 1))
    result = parse_model(raw or "")
    if result is None:
        return {"available": False, "reason": "unknown"}
    # Cachea GLOBALMENTE (solo el hash→modelo; sin datos personales).
    store.kv_set(f"aiid::{key}", json.dumps(result))
    result = dict(result)
    result["cached"] = False
    result["available"] = True
    return result
