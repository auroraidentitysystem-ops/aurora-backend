# aurora/backend/app/api/validate.py
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Optional, Set

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.services.verify_service import verify_student_qr_token, TokenError
from app.db.session import get_db
from app.db.models import (
    AuthSession,
    EventLog,
    EventMode,
    EventResult,
    Validator,
    ActorType,
    SessionStatus,
)

router = APIRouter(prefix="/validate", tags=["validation"])


class ValidateRequest(BaseModel):
    token: str
    event_type: str  # ACCESS or ATTENDANCE

    # opcional: identificación del dispositivo validador
    device_id: Optional[str] = None

    # compatibilidad temporal con clientes viejos; ya no se usan
    validator_email: Optional[str] = None
    validator_id: Optional[str] = None


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def hash_session_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def get_bearer_token(authorization: str | None) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    prefix = "bearer "
    if not authorization.lower().startswith(prefix):
        raise HTTPException(status_code=401, detail="Invalid Authorization header")

    token = authorization[len(prefix):].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing bearer token")

    return token


def get_validator_from_session(db: Session, authorization: str | None) -> Validator:
    token = get_bearer_token(authorization)
    token_hash = hash_session_token(token)

    session = (
        db.query(AuthSession)
        .filter(AuthSession.token_hash == token_hash)
        .first()
    )

    if not session:
        raise HTTPException(status_code=401, detail="Invalid session")

    now = utcnow()

    if session.status != SessionStatus.ACTIVE:
        raise HTTPException(status_code=401, detail="Session is not active")

    if session.expires_at <= now:
        session.status = SessionStatus.EXPIRED
        db.add(session)
        db.commit()
        raise HTTPException(status_code=401, detail="Session expired")

    if session.actor_type != ActorType.VALIDATOR:
        raise HTTPException(status_code=403, detail="This session is not a validator session")

    if not session.validator_id:
        raise HTTPException(status_code=401, detail="Validator session without validator_id")

    validator = (
        db.query(Validator)
        .filter(Validator.id == session.validator_id)
        .first()
    )

    if not validator or not validator.is_active:
        raise HTTPException(status_code=403, detail="Validator not authorized")

    session.last_seen_at = now
    db.add(session)
    db.commit()

    return validator


def _roles_allowed_for_event(event_type: str) -> Set[str]:
    """
    Política v0:
      - ACCESS     -> GUARD, ADMIN
      - ATTENDANCE -> TEACHER, ADMIN
    """
    if event_type == "ACCESS":
        return {"GUARD", "ADMIN"}
    if event_type == "ATTENDANCE":
        return {"TEACHER", "ADMIN"}
    return set()


@router.post("/")
def validate_qr(
    req: ValidateRequest,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    # Resolver validator desde sesión autenticada
    validator = get_validator_from_session(db, authorization)

    # -------------------------
    # 0) Validar event_type
    # -------------------------
    event_type = (req.event_type or "").strip().upper()
    if event_type not in {"ACCESS", "ATTENDANCE"}:
        db.add(
            EventLog(
                event_name="QR_VALIDATION",
                matricula=None,
                cid=None,
                validator_id=validator.id,
                device_id=req.device_id,
                mode=EventMode.ONLINE,
                result=EventResult.DENY,
                reason=f"{event_type or 'UNKNOWN'}:INVALID_EVENT_TYPE",
            )
        )
        db.commit()
        return {"result": "DENY", "reason": "Invalid event_type", "payload": None}

    # -------------------------
    # 1) Enforce role vs event_type
    # -------------------------
    allowed_roles = _roles_allowed_for_event(event_type)

    role_obj = getattr(validator, "role", None)
    role = (getattr(role_obj, "value", None) or str(role_obj or "")).strip().upper()
    if "." in role:
        role = role.split(".")[-1].strip().upper()

    if role not in allowed_roles:
        db.add(
            EventLog(
                event_name="QR_VALIDATION",
                matricula=None,
                cid=None,
                validator_id=validator.id,
                device_id=req.device_id,
                mode=EventMode.ONLINE,
                result=EventResult.DENY,
                reason=f"{event_type}:ROLE_NOT_ALLOWED_FOR_EVENT:{role or 'UNKNOWN'}",
            )
        )
        db.commit()
        return {
            "result": "DENY",
            "reason": "Role not allowed for this event_type",
            "payload": None,
        }

    # -------------------------
    # 2) Verificar token (firma/claims/exp)
    # -------------------------
    try:
        payload = verify_student_qr_token(req.token)
        result = EventResult.ALLOW
        reason = "OK"
    except TokenError as e:
        payload = {}
        result = EventResult.DENY
        reason = str(e)

    # -------------------------
    # 3) cid a UUID (tu DB espera UUID)
    # -------------------------
    cid_uuid = None
    if payload.get("cid"):
        try:
            cid_uuid = uuid.UUID(str(payload["cid"]))
        except Exception:
            cid_uuid = None

    # -------------------------
    # 4) Log en event_logs
    # -------------------------
    db.add(
        EventLog(
            event_name="QR_VALIDATION",
            matricula=payload.get("sub"),
            cid=cid_uuid,
            validator_id=validator.id,
            device_id=req.device_id,
            mode=EventMode.ONLINE,
            result=result,
            reason=f"{event_type}:{reason}",
        )
    )
    db.commit()

    return {
        "result": result.value,
        "reason": reason,
        "payload": payload if result == EventResult.ALLOW else None,
    }