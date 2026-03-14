# backend/app/api/validate_offline_sim.py

from __future__ import annotations

import time
from typing import Any, Dict, Optional, Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.verify_service import verify_student_qr_token, TokenError

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


def _extract_crl_payload(crl: Dict[str, Any]) -> Dict[str, Any]:
    """
    Espera CRL como:
      { "payload": {...}, "signature": "...", "kid": "..." }

    Nota: en Fase 1 (demo Swagger) NO verificamos firma aquí
    para evitar mismatch con crypto_service. La app validadora real sí lo hará.
    """
    if not isinstance(crl, dict):
        raise HTTPException(status_code=400, detail="CRL must be an object")

    payload = crl.get("payload")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="CRL missing payload object")

    return payload


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


# =========================
# Endpoint
# =========================
@router.post("/offline", response_model=OfflineValidateOutput)
def validate_offline(inp: OfflineValidateInput):
    now_ts = _get_now_ts(inp)

    # 1) Extraer payload CRL (y opcionalmente verificar firma)
    crl_payload = _extract_crl_payload(inp.crl)

    # 2) CRL meta + status
    _, crl_exp = _read_crl_meta(crl_payload)
    crl_status = "FRESH" if now_ts <= crl_exp else "STALE"

    # 3) Verificar token QR (firma + claims + exp/iat)
    try:
        claims = verify_student_qr_token(inp.token, now_ts=now_ts)
    except TokenError as e:
        return OfflineValidateOutput(
            allow=False,
            reason=f"TOKEN_INVALID: {str(e)}",
            event_type=inp.event_type,
            crl_status=crl_status,
            subject={},
        )

    cid = claims.get("cid")
    if not isinstance(cid, str) or not cid:
        return OfflineValidateOutput(
            allow=False,
            reason="TOKEN_MISSING_CID",
            event_type=inp.event_type,
            crl_status=crl_status,
            subject=claims,
        )

    # 4) Revocación por CRL
    if _is_cid_revoked(crl_payload, cid):
        return OfflineValidateOutput(
            allow=False,
            reason="CID_REVOKED_BY_CRL",
            event_type=inp.event_type,
            crl_status=crl_status,
            subject=claims,
        )

    # 5) Política Option C si CRL está stale
    if crl_status == "STALE":
        if inp.risk == "HIGH":
            return OfflineValidateOutput(
                allow=False,
                reason="CRL_STALE_HIGH_RISK_DENY",
                event_type=inp.event_type,
                crl_status=crl_status,
                subject=claims,
            )
        else:
            return OfflineValidateOutput(
                allow=True,
                reason="CRL_STALE_LOW_RISK_ALLOW",
                event_type=inp.event_type,
                crl_status=crl_status,
                subject=claims,
            )

    # OK normal
    return OfflineValidateOutput(
        allow=True,
        reason="OK",
        event_type=inp.event_type,
        crl_status=crl_status,
        subject=claims,
    )