# aurora/backend/app/api/student.py

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.db.models import (
    Student,
    Credential,
    CredentialStatus,
    AuthSession,
    ActorType,
    SessionStatus,
)

router = APIRouter(prefix="/student", tags=["student"])


class CredentialView(BaseModel):
    # Visible fields (PWA)
    photo_url: str | None = None
    full_name: str
    matricula: str
    program: str | None = None
    expires_at: datetime | None = None

    # Opcionales (útiles para debug; no estrictamente visibles en UI)
    cid: str
    issued_at: datetime
    status: str


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


def resolve_photo_url(request: Request, matricula: str) -> str | None:
    """
    Busca una foto cuyo nombre sea exactamente la matrícula.
    Ejemplos:
      backend/static/photos/2512312001.png
      backend/static/photos/A00123456.jpg

    Si no encuentra, usa:
      backend/static/default/default.png
    """

    # .../backend/app/api/student.py
    # parents[2] => .../backend
    base_dir = Path(__file__).resolve().parents[2]
    static_dir = base_dir / "static"
    photos_dir = static_dir / "photos"
    default_image = static_dir / "default" / "default.png"

    allowed_exts = [".png", ".jpg", ".jpeg", ".webp"]

    for ext in allowed_exts:
        candidate = photos_dir / f"{matricula}{ext}"
        if candidate.exists():
            return f"{str(request.base_url).rstrip('/')}/static/photos/{matricula}{ext}"

    if default_image.exists():
        return f"{str(request.base_url).rstrip('/')}/static/default/default.png"

    return None


@router.get("/credential", response_model=CredentialView)
def get_my_credential(
    request: Request,
    authorization: str | None = Header(default=None),
):
    """
    Endpoint protegido: ver mi credencial.

    Cambio importante:
    - Ya NO recibe email por query.
    - El estudiante se identifica por Authorization: Bearer <session_token>.
    - El backend obtiene la matrícula desde AuthSession.
    - La foto se resuelve desde archivos estáticos por matrícula.
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

        cred = (
            db.query(Credential)
            .filter(Credential.student_matricula == student.matricula)
            .filter(Credential.status == CredentialStatus.ACTIVE)
            .order_by(Credential.issued_at.desc())
            .first()
        )

        if not cred:
            raise HTTPException(status_code=404, detail="Active credential not found")

        return CredentialView(
            photo_url=resolve_photo_url(request, student.matricula),
            full_name=student.full_name,
            matricula=student.matricula,
            program=student.program,
            expires_at=cred.expires_at,
            cid=str(cred.cid),
            issued_at=cred.issued_at,
            status=cred.status.value,
        )

    finally:
        db.close()