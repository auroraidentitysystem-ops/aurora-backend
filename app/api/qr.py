# aurora/backend/app/api/qr.py

import uuid
import hashlib
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import SessionLocal
from app.db.models import (
    Student,
    Credential,
    CredentialStatus,
    AuthSession,
    ActorType,
    SessionStatus,
)
from app.services.crypto_service import sign_jws_eddsa

router = APIRouter(prefix="/qr", tags=["qr"])


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


def get_student_session(db: Session, authorization: str | None) -> AuthSession:
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

    if session.actor_type != ActorType.STUDENT:
        raise HTTPException(status_code=403, detail="This session is not a student session")

    if not session.student_matricula:
        raise HTTPException(status_code=401, detail="Student session without matricula")

    session.last_seen_at = now
    db.add(session)
    db.commit()

    return session


class QRTokenResponse(BaseModel):
    token: str
    exp: str
    rotate_sec: int
    ttl_sec: int


@router.get("/token", response_model=QRTokenResponse)
def issue_student_qr_token(
    authorization: str | None = Header(default=None),
):
    """
    Endpoint protegido: genera token QR firmado para PWA.

    Cambio importante:
    - Ya NO recibe email por query.
    - El backend obtiene la identidad del estudiante desde AuthSession.
    - Evita que alguien pida un QR solo con conocer el correo.
    """

    db: Session = SessionLocal()

    try:
        auth_session = get_student_session(db, authorization)

        student = (
            db.query(Student)
            .filter(Student.matricula == auth_session.student_matricula)
            .first()
        )

        if not student:
            raise HTTPException(status_code=404, detail="Student not found")

        matricula = student.matricula

        cred = (
            db.query(Credential)
            .filter(Credential.student_matricula == matricula)
            .filter(Credential.status == CredentialStatus.ACTIVE)
            .order_by(Credential.issued_at.desc())
            .first()
        )

        if not cred:
            raise HTTPException(status_code=404, detail="Active credential not found")

        now = utcnow()
        exp = now + timedelta(seconds=settings.QR_TOKEN_TTL_SEC)

        payload = {
            "sub": matricula,
            "cid": str(cred.cid),
            "iat": int(now.timestamp()),
            "exp": int(exp.timestamp()),
            "jti": str(uuid.uuid4()),
            "scope": "student_qr",
        }

        token = sign_jws_eddsa(payload)

        return QRTokenResponse(
            token=token,
            exp=exp.isoformat(),
            rotate_sec=settings.QR_ROTATE_SEC,
            ttl_sec=settings.QR_TOKEN_TTL_SEC,
        )

    finally:
        db.close()