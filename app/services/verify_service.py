# backend/app/services/verify_service.py

import base64
import json
import time
from functools import lru_cache
from typing import Any, Dict, Tuple, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

from app.core.config import settings


# ----------------------------
# Helpers base64url
# ----------------------------
def b64url_decode(s: str) -> bytes:
    """Base64URL decode with padding."""
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def get_int_setting(name: str, default: int) -> int:
    """Lee un setting int desde settings aunque venga como str."""
    val = getattr(settings, name, default)
    try:
        return int(val)
    except Exception:
        return default


# ----------------------------
# Exceptions
# ----------------------------
class TokenError(Exception):
    """Errores controlados de token (firma/claims/exp)."""
    pass


# ----------------------------
# Key loading (cached)
# ----------------------------
@lru_cache(maxsize=1)
def _load_ed25519_public_key_from_settings() -> Ed25519PublicKey:
    """
    Lee ED25519_PUBLIC_KEY_B64 desde settings (.env).
    Espera PEM en base64 (base64 estándar de bytes PEM).
    Cacheado para no recargar/parsear en cada request.
    """
    pub_b64 = getattr(settings, "ED25519_PUBLIC_KEY_B64", None)
    if not pub_b64:
        raise RuntimeError("Missing ED25519_PUBLIC_KEY_B64 in settings/.env")

    try:
        pub_pem = base64.b64decode(pub_b64)
        public_key = serialization.load_pem_public_key(pub_pem)
    except Exception as e:
        raise RuntimeError(f"Could not load public key: {e}")

    if not isinstance(public_key, Ed25519PublicKey):
        raise RuntimeError("Public key is not Ed25519")

    return public_key


def clear_public_key_cache() -> None:
    """
    Útil si cambias ED25519_PUBLIC_KEY_B64 sin reiniciar el servidor (debug/local).
    En producción normalmente reinicias y ya.
    """
    _load_ed25519_public_key_from_settings.cache_clear()


# ----------------------------
# Parsing
# ----------------------------
def parse_jws_compact(token: str) -> Tuple[Dict[str, Any], Dict[str, Any], bytes, bytes]:
    """
    JWS compact: header.payload.signature (base64url)
    Regresa: (header_dict, payload_dict, signing_input_bytes, signature_bytes)
    """
    if not isinstance(token, str) or not token:
        raise TokenError("Missing token")

    parts = token.split(".")
    if len(parts) != 3:
        raise TokenError("Invalid token format (expected 3 parts: header.payload.signature)")

    header_b64, payload_b64, sig_b64 = parts

    try:
        header_json = b64url_decode(header_b64)
        payload_json = b64url_decode(payload_b64)
        signature = b64url_decode(sig_b64)
    except Exception as e:
        raise TokenError(f"Invalid base64url encoding: {e}")

    try:
        header = json.loads(header_json.decode("utf-8"))
        payload = json.loads(payload_json.decode("utf-8"))
    except Exception as e:
        raise TokenError(f"Invalid JSON in token: {e}")

    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise TokenError("Invalid token JSON (header/payload must be objects)")

    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    return header, payload, signing_input, signature


# ----------------------------
# Main verification
# ----------------------------
def verify_student_qr_token(token: str, now_ts: Optional[int] = None) -> Dict[str, Any]:
    """
    Verifica firma Ed25519 + claims mínimos del token QR.
    Retorna payload si OK; lanza TokenError si falla.

    Payload esperado:
      sub (matricula), cid, iat (int), exp (int), jti (str opc), scope="student_qr"
    Header esperado:
      alg="EdDSA", (kid opcional), (typ opcional)
    """
    header, payload, signing_input, signature = parse_jws_compact(token)

    # --- Header checks
    alg = header.get("alg")
    if alg != "EdDSA":
        raise TokenError(f"Unsupported alg: {alg}")

    # typ opcional (si quieres forzarlo en el futuro)
    # typ = header.get("typ")
    # if typ not in (None, "JWT", "AURORA"):
    #     raise TokenError("Invalid typ")

    # kid opcional (en v1 lo usarás para rotación de llaves)
    # kid = header.get("kid")

    # --- Signature verification
    pub = _load_ed25519_public_key_from_settings()
    try:
        pub.verify(signature, signing_input)
    except Exception:
        raise TokenError("Invalid signature")

    # --- Payload checks
    sub = payload.get("sub")
    cid = payload.get("cid")
    scope = payload.get("scope")
    exp = payload.get("exp")
    iat = payload.get("iat")
    jti = payload.get("jti")  # recomendado

    if not isinstance(sub, str) or not sub:
        raise TokenError("Missing/invalid sub")
    if not isinstance(cid, str) or not cid:
        raise TokenError("Missing/invalid cid")
    if scope != "student_qr":
        raise TokenError("Invalid scope")
    if not isinstance(exp, int):
        raise TokenError("Missing/invalid exp")
    if not isinstance(iat, int):
        raise TokenError("Missing/invalid iat")
    if jti is not None and (not isinstance(jti, str) or not jti):
        raise TokenError("Invalid jti")

    # --- Time checks
    now = int(time.time()) if now_ts is None else int(now_ts)

    # tolerancia por reloj desfasado
    skew = get_int_setting("CLOCK_SKEW_SEC", 120)

    # Expiración con tolerancia (permite un token apenas expirado dentro del skew)
    if exp <= now - skew:
        raise TokenError("Token expired")

    # iat no debe estar demasiado en el futuro
    if iat > now + skew:
        raise TokenError("iat is in the future")

    # exp no debe ser menor/equiv a iat (con un margen mínimo)
    if exp <= iat:
        raise TokenError("exp must be > iat")

    # TTL máximo esperado (desde .env puede venir como str)
    max_ttl = get_int_setting("QR_TOKEN_TTL_SEC", 45)

    # +10s de tolerancia por skew/redondeos (como ya lo estabas haciendo)
    if (exp - iat) > (max_ttl + 10):
        raise TokenError("Token TTL too long")

    return payload


def verify_student_qr_token_debug(token: str, now_ts: Optional[int] = None) -> Dict[str, Any]:
    """
    Variante para debug:
    - Verifica token (firma + claims)
    - Regresa header + payload para inspección en Swagger
    """
    header, payload, _, _ = parse_jws_compact(token)

    # Reusa la verificación completa (incluye firma/claims/exp)
    _ = verify_student_qr_token(token, now_ts=now_ts)

    return {"header": header, "payload": payload}


# ----------------------------
# Aliases (para usar desde validate_offline_sim sin renombrar)
# ----------------------------
def verify_qr_token(token: str, now_ts: Optional[int] = None) -> Dict[str, Any]:
    """
    Alias cómodo para el validador offline sim y otros routers.
    """
    return verify_student_qr_token(token, now_ts=now_ts)