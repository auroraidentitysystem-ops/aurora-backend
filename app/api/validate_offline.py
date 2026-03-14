# backend/app/api/validate_offline.py
from __future__ import annotations

import base64
import json
import time
import uuid
from typing import Any, Dict, Optional, Literal

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

from app.core.config import settings
from app.db.session import get_db
from app.db.models import EventLog, EventMode, EventResult, Validator
from app.services.verify_service import TokenError
from app.services.crypto_service import verify_detached_json

router = APIRouter(prefix="/validate", tags=["validate"])


# =========================
# Schemas
# =========================
class OfflineValidateInput(BaseModel):
    token: str = Field(..., description="QR token en formato header.payload.signature (base64url)")
    crl: Dict[str, Any] = Field(..., description="CRL firmada: {payload, signature, kid}")
    event_type: Literal["ACCESS", "ATTENDANCE"] = "ACCESS"
    risk: Literal["LOW", "HIGH"] = "HIGH"
    now_ts: Optional[int] = Field(None, description="Epoch seconds para simular reloj offline (si no, usa now)")

    # NUEVO: identificar validador (para logs/auditoría)
    validator_email: Optional[str] = Field(None, description="Email institucional del validador")
    validator_id: Optional[str] = Field(None, description="UUID del validador (string)")
    device_id: Optional[str] = Field(None, description="Identificador de dispositivo del validador")


class OfflineValidateOutput(BaseModel):
    allow: bool
    reason: str
    mode: str = "OFFLINE"
    event_type: str
    crl_status: str
    subject: Dict[str, Any]


# =========================
# Helpers
# =========================
def _get_now_ts(inp: OfflineValidateInput) -> int:
    return int(inp.now_ts) if inp.now_ts is not None else int(time.time())


def _b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def _load_ed25519_public_key_from_settings() -> Ed25519PublicKey:
    pub_b64 = getattr(settings, "ED25519_PUBLIC_KEY_B64", None)
    if not isinstance(pub_b64, str) or not pub_b64.strip():
        raise HTTPException(status_code=500, detail="ED25519_PUBLIC_KEY_B64 not configured")

    try:
        pem_bytes = base64.b64decode(pub_b64.encode("utf-8"))
        key = serialization.load_pem_public_key(pem_bytes)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Invalid ED25519 public key: {e}")

    if not isinstance(key, Ed25519PublicKey):
        raise HTTPException(status_code=500, detail="Public key is not Ed25519")
    return key


def _verify_student_qr_token_strict(token: str, *, now_ts: int) -> Dict[str, Any]:
    if not isinstance(token, str) or token.count(".") != 2:
        raise TokenError("MALFORMED_TOKEN")

    h_b64, p_b64, sig_b64 = token.split(".", 2)

    try:
        header = json.loads(_b64url_decode(h_b64).decode("utf-8"))
        payload = json.loads(_b64url_decode(p_b64).decode("utf-8"))
        sig = _b64url_decode(sig_b64)
    except Exception:
        raise TokenError("MALFORMED_TOKEN")

    alg = header.get("alg")
    if alg != "EdDSA":
        raise TokenError("UNSUPPORTED_ALG")

    signing_input = f"{h_b64}.{p_b64}".encode("utf-8")
    pub = _load_ed25519_public_key_from_settings()
    try:
        pub.verify(sig, signing_input)
    except Exception:
        raise TokenError("INVALID_SIGNATURE")

    exp = payload.get("exp")
    iat = payload.get("iat")
    scope = payload.get("scope")

    if exp is None or iat is None:
        raise TokenError("MISSING_CLAIMS")
    try:
        exp_i = int(exp)
        iat_i = int(iat)
    except Exception:
        raise TokenError("BAD_CLAIMS")

    if now_ts > exp_i:
        raise TokenError("TOKEN_EXPIRED")
    if iat_i > now_ts + 5:
        raise TokenError("IAT_IN_FUTURE")

    if scope != "student_qr":
        raise TokenError("BAD_SCOPE")

    return payload


def _extract_crl_parts(crl: Dict[str, Any]) -> tuple[Dict[str, Any], str, str]:
    if not isinstance(crl, dict):
        raise HTTPException(status_code=400, detail="CRL must be an object")

    payload = crl.get("payload")
    signature = crl.get("signature")
    kid = crl.get("kid")

    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="CRL missing payload object")
    if not isinstance(signature, str) or not signature:
        raise HTTPException(status_code=400, detail="CRL missing signature")
    if not isinstance(kid, str) or not kid:
        raise HTTPException(status_code=400, detail="CRL missing kid")

    return payload, signature, kid


def _read_crl_meta(payload: Dict[str, Any]) -> tuple[int, int]:
    issued = payload.get("crl_issued_at") or payload.get("issued_at") or payload.get("iat")
    exp = payload.get("crl_exp") or payload.get("exp")
    if issued is None or exp is None:
        raise HTTPException(status_code=400, detail="CRL payload missing crl_issued_at and/or crl_exp")
    return int(issued), int(exp)


def _is_cid_revoked(payload: Dict[str, Any], cid: str) -> bool:
    revoked = payload.get("revoked") or []
    if not isinstance(revoked, list):
        return False

    for item in revoked:
        if isinstance(item, dict) and item.get("cid") == cid:
            return True
        if isinstance(item, str) and item == cid:
            return True
    return False


def _resolve_validator_offline(inp: OfflineValidateInput, db: Session) -> Optional[Validator]:
    v: Optional[Validator] = None

    if inp.validator_id:
        try:
            vid = uuid.UUID(inp.validator_id)
            v = db.query(Validator).filter(Validator.id == vid).first()
        except ValueError:
            v = None

    if v is None and inp.validator_email:
        vemail = inp.validator_email.strip().lower()
        v = db.query(Validator).filter(Validator.email == vemail).first()

    return v


def _cid_to_uuid(cid: Any) -> Optional[uuid.UUID]:
    if not cid:
        return None
    try:
        return uuid.UUID(str(cid))
    except Exception:
        return None


def _log_offline(
    db: Session,
    *,
    allow: bool,
    reason: str,
    event_type: str,
    validator: Optional[Validator],
    device_id: Optional[str],
    claims: Optional[Dict[str, Any]],
):
    cid_uuid = _cid_to_uuid((claims or {}).get("cid"))
    db.add(
        EventLog(
            event_name="QR_VALIDATION",
            matricula=(claims or {}).get("sub"),
            cid=cid_uuid,
            validator_id=validator.id if validator else None,
            device_id=device_id,
            mode=EventMode.OFFLINE,
            result=EventResult.ALLOW if allow else EventResult.DENY,
            reason=f"{event_type}:{reason}",
        )
    )
    db.commit()


# =========================
# Endpoint (REAL) + LOGGING
# =========================
@router.post("/offline/v2", response_model=OfflineValidateOutput)
def validate_offline_v2(inp: OfflineValidateInput, db: Session = Depends(get_db)):
    now_ts = _get_now_ts(inp)
    event_type = inp.event_type

    # 0) Resolver validator (para auditoría)
    validator = _resolve_validator_offline(inp, db)

    # (Opcional pero recomendable) exigir validator para offline v2
    if validator is None or not validator.is_active:
        _log_offline(
            db,
            allow=False,
            reason="VALIDATOR_NOT_AUTHORIZED",
            event_type=event_type,
            validator=validator,
            device_id=inp.device_id,
            claims=None,
        )
        return OfflineValidateOutput(
            allow=False,
            reason="VALIDATOR_NOT_AUTHORIZED",
            event_type=event_type,
            crl_status="UNKNOWN",
            subject={},
        )

    # 1) Extraer CRL + verificar firma
    crl_payload, crl_sig, _kid = _extract_crl_parts(inp.crl)
    if not verify_detached_json(crl_payload, crl_sig):
        _log_offline(
            db,
            allow=False,
            reason="CRL_SIGNATURE_INVALID",
            event_type=event_type,
            validator=validator,
            device_id=inp.device_id,
            claims=None,
        )
        return OfflineValidateOutput(
            allow=False,
            reason="CRL_SIGNATURE_INVALID",
            event_type=event_type,
            crl_status="INVALID",
            subject={},
        )

    # 2) CRL meta + status
    _, crl_exp = _read_crl_meta(crl_payload)
    crl_status = "FRESH" if now_ts <= crl_exp else "STALE"

    # 3) Verificar token QR (estricto)
    try:
        claims = _verify_student_qr_token_strict(inp.token, now_ts=now_ts)
    except TokenError as e:
        _log_offline(
            db,
            allow=False,
            reason=f"TOKEN_INVALID:{str(e)}",
            event_type=event_type,
            validator=validator,
            device_id=inp.device_id,
            claims=None,
        )
        return OfflineValidateOutput(
            allow=False,
            reason=f"TOKEN_INVALID: {str(e)}",
            event_type=event_type,
            crl_status=crl_status,
            subject={},
        )

    cid = claims.get("cid")
    if not isinstance(cid, str) or not cid:
        _log_offline(
            db,
            allow=False,
            reason="TOKEN_MISSING_CID",
            event_type=event_type,
            validator=validator,
            device_id=inp.device_id,
            claims=claims,
        )
        return OfflineValidateOutput(
            allow=False,
            reason="TOKEN_MISSING_CID",
            event_type=event_type,
            crl_status=crl_status,
            subject=claims,
        )

    # 4) Revocación por CRL
    if _is_cid_revoked(crl_payload, cid):
        _log_offline(
            db,
            allow=False,
            reason="CID_REVOKED_BY_CRL",
            event_type=event_type,
            validator=validator,
            device_id=inp.device_id,
            claims=claims,
        )
        return OfflineValidateOutput(
            allow=False,
            reason="CID_REVOKED_BY_CRL",
            event_type=event_type,
            crl_status=crl_status,
            subject=claims,
        )

    # 5) Política Option C si CRL está stale
    if crl_status == "STALE":
        if inp.risk == "HIGH":
            _log_offline(
                db,
                allow=False,
                reason="CRL_STALE_HIGH_RISK_DENY",
                event_type=event_type,
                validator=validator,
                device_id=inp.device_id,
                claims=claims,
            )
            return OfflineValidateOutput(
                allow=False,
                reason="CRL_STALE_HIGH_RISK_DENY",
                event_type=event_type,
                crl_status=crl_status,
                subject=claims,
            )

        _log_offline(
            db,
            allow=True,
            reason="CRL_STALE_LOW_RISK_ALLOW",
            event_type=event_type,
            validator=validator,
            device_id=inp.device_id,
            claims=claims,
        )
        return OfflineValidateOutput(
            allow=True,
            reason="CRL_STALE_LOW_RISK_ALLOW",
            event_type=event_type,
            crl_status=crl_status,
            subject=claims,
        )

    # OK normal
    _log_offline(
        db,
        allow=True,
        reason="OK",
        event_type=event_type,
        validator=validator,
        device_id=inp.device_id,
        claims=claims,
    )
    return OfflineValidateOutput(
        allow=True,
        reason="OK",
        event_type=event_type,
        crl_status=crl_status,
        subject=claims,
    )