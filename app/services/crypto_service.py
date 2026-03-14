# aurora/backend/app/services/crypto_service.py

import base64
import hashlib
import json
from typing import Any, Dict, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

from app.core.config import settings


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def _load_ed25519_keys_from_settings() -> Tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """
    Lee ED25519_PRIVATE_KEY_B64 y ED25519_PUBLIC_KEY_B64 desde settings (.env)
    Espera que sean bytes PEM en base64 (lo más práctico).
    """
    if not settings.ED25519_PRIVATE_KEY_B64 or not settings.ED25519_PUBLIC_KEY_B64:
        raise RuntimeError(
            "Missing ED25519 keys. Set ED25519_PRIVATE_KEY_B64 and ED25519_PUBLIC_KEY_B64 in .env"
        )

    priv_pem = base64.b64decode(settings.ED25519_PRIVATE_KEY_B64)
    pub_pem = base64.b64decode(settings.ED25519_PUBLIC_KEY_B64)

    private_key = serialization.load_pem_private_key(priv_pem, password=None)
    public_key = serialization.load_pem_public_key(pub_pem)

    if not isinstance(private_key, Ed25519PrivateKey) or not isinstance(public_key, Ed25519PublicKey):
        raise RuntimeError("Keys are not Ed25519")

    return private_key, public_key


def compute_kid_from_public_key(pub: Ed25519PublicKey) -> str:
    """
    kid = sha256(pubkey_raw)[:16] (hex) -> corto, estable.
    """
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    h = hashlib.sha256(raw).hexdigest()
    return h[:16]  # 16 hex = 8 bytes aprox


# ----------------------------
# NUEVO: Canonical JSON helpers
# ----------------------------
def canonical_json_bytes(payload: Dict[str, Any]) -> bytes:
    """
    Canonicaliza JSON para firma/verificación:
    - sort_keys=True
    - separators=(",", ":") sin espacios
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ----------------------------
# EXISTENTE: JWS compact EdDSA
# ----------------------------
def sign_jws_eddsa(payload: Dict[str, Any]) -> str:
    """
    Genera JWS compact: base64url(header).base64url(payload).base64url(signature)
    Firma Ed25519 sobre: header_b64 + "." + payload_b64
    """
    priv, pub = _load_ed25519_keys_from_settings()
    kid = compute_kid_from_public_key(pub)

    header = {
        "alg": "EdDSA",
        "typ": "JWT",      # puedes poner "AURORA" si quieres, pero JWT es estándar
        "kid": kid,
    }

    header_json = json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    payload_json = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    header_b64 = b64url_encode(header_json)
    payload_b64 = b64url_encode(payload_json)

    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    sig = priv.sign(signing_input)
    sig_b64 = b64url_encode(sig)

    return f"{header_b64}.{payload_b64}.{sig_b64}"


# ----------------------------
# NUEVO: Firma "detached" (CRL)
# ----------------------------
def sign_detached_json(payload: Dict[str, Any]) -> Tuple[str, str]:
    """
    Firma Ed25519 sobre el JSON canónico del payload.
    Retorna (signature_b64url, kid)
    """
    priv, pub = _load_ed25519_keys_from_settings()
    kid = compute_kid_from_public_key(pub)
    msg = canonical_json_bytes(payload)
    sig = priv.sign(msg)
    return b64url_encode(sig), kid


def verify_detached_json(payload: Dict[str, Any], signature_b64url: str) -> bool:
    """
    Verifica firma Ed25519 sobre JSON canónico.
    """
    _, pub = _load_ed25519_keys_from_settings()
    msg = canonical_json_bytes(payload)
    sig = b64url_decode(signature_b64url)
    try:
        pub.verify(sig, msg)
        return True
    except Exception:
        return False