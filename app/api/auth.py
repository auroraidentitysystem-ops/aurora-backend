import random
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

from app.core.config import settings
from app.db.session import SessionLocal

# ✅ Imports directos por módulo, con fallback
try:
    from app.db.models.auth_session import AuthSession
    from app.db.models.otp_request import OTPRequest
    from app.db.models.student import Student
    from app.db.models.credential import Credential
    from app.db.models.crl_item import CRLItem
    from app.db.models.event_log import EventLog
    from app.db.models.validator import Validator
    from app.db.models.enums import (
        ActorType,
        CredentialStatus,
        EventMode,
        EventResult,
        SessionStatus,
    )
except ImportError:
    from app.db.models import (  # type: ignore
        AuthSession,
        OTPRequest,
        Student,
        Credential,
        CRLItem,
        EventLog,
        Validator,
        ActorType,
        CredentialStatus,
        EventMode,
        EventResult,
        SessionStatus,
    )

from app.services.email_service import send_email

router = APIRouter(prefix="/auth", tags=["auth"])


# =========================
# Schemas
# =========================
class FlowDiscoverInput(BaseModel):
    email: EmailStr


class OTPRequestInput(BaseModel):
    email: EmailStr


class OTPVerifyInput(BaseModel):
    email: EmailStr
    otp: str  # "023523"


class ActivateInput(BaseModel):
    email: EmailStr
    activation_token: str
    full_name: str | None = None
    program: str | None = None


# =========================
# Helpers
# =========================
def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def generate_otp() -> str:
    return "".join(str(random.randint(0, 9)) for _ in range(settings.OTP_DIGITS))


def hash_otp(email: str, otp: str) -> str:
    payload = f"{email.lower()}|{otp}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def hash_session_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_session_token() -> str:
    return secrets.token_urlsafe(48)


def get_session_ttl_hours() -> int:
    return int(getattr(settings, "SESSION_TTL_HOURS", 12))


def ensure_institution_domain(email: str) -> None:
    domain = (settings.INSTITUTION_EMAIL_DOMAIN or "").strip().lower()
    if not domain:
        return
    if not email.lower().endswith(domain):
        raise HTTPException(status_code=400, detail=f"Email must be institutional ({domain})")


def get_hour_bucket(now: datetime) -> datetime:
    return now.replace(minute=0, second=0, microsecond=0)


def latest_otp_for_email(db: Session, email: str) -> OTPRequest | None:
    return (
        db.query(OTPRequest)
        .filter(OTPRequest.email == email)
        .order_by(OTPRequest.requested_at.desc())
        .first()
    )


def get_active_validator_by_email(db: Session, email: str) -> Validator | None:
    return (
        db.query(Validator)
        .filter(Validator.email == email)
        .filter(Validator.is_active.is_(True))
        .first()
    )


def get_student_by_email(db: Session, email: str) -> Student | None:
    return db.query(Student).filter(Student.email == email).first()


def get_active_credential_for_student(db: Session, matricula: str) -> Credential | None:
    return (
        db.query(Credential)
        .filter(Credential.student_matricula == matricula)
        .filter(Credential.status == CredentialStatus.ACTIVE)
        .order_by(Credential.issued_at.desc())
        .first()
    )


def resolve_flow(db: Session, email: str) -> dict[str, Any]:
    """
    Regla simple para AURORA v0:
    - Si está en whitelist activa de validators => flow=validator
    - En otro caso => flow=student
    """
    validator = get_active_validator_by_email(db, email)
    if validator:
        return {
            "flow": "validator",
            "allowed": True,
            "role": validator.role.value,
            "has_active_credential": False,
        }

    student = get_student_by_email(db, email)
    active_cred = None
    if student:
        active_cred = get_active_credential_for_student(db, student.matricula)

    return {
        "flow": "student",
        "allowed": True,
        "role": "STUDENT",
        "has_active_credential": active_cred is not None,
    }


def revoke_active_sessions_for_email(
    db: Session,
    actor_type: ActorType,
    email: str,
    reason: str,
) -> None:
    now = utcnow()

    sessions = (
        db.query(AuthSession)
        .filter(AuthSession.actor_type == actor_type)
        .filter(AuthSession.email == email)
        .filter(AuthSession.status == SessionStatus.ACTIVE)
        .all()
    )

    for s in sessions:
        s.status = SessionStatus.REVOKED
        s.revoked_at = now
        s.revoke_reason = reason
        db.add(s)


def create_auth_session(
    db: Session,
    actor_type: ActorType,
    email: str,
    student_matricula: str | None = None,
    validator_id: Any = None,
    device_id: str | None = None,
    device_name: str | None = None,
) -> tuple[str, AuthSession]:
    now = utcnow()

    revoke_active_sessions_for_email(
        db=db,
        actor_type=actor_type,
        email=email,
        reason="new_login",
    )

    plain_token = generate_session_token()
    token_hash = hash_session_token(plain_token)

    session = AuthSession(
        actor_type=actor_type,
        email=email,
        student_matricula=student_matricula,
        validator_id=validator_id,
        token_hash=token_hash,
        status=SessionStatus.ACTIVE,
        device_id=device_id,
        device_name=device_name,
        issued_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(hours=get_session_ttl_hours()),
        revoked_at=None,
        revoke_reason=None,
    )

    db.add(session)
    db.flush()

    return plain_token, session


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


def get_session_from_authorization(db: Session, authorization: str | None) -> AuthSession:
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

    session.last_seen_at = now
    db.add(session)
    db.commit()

    return session


def _eventlog_has_field(field_name: str) -> bool:
    try:
        return field_name in getattr(EventLog, "__mapper__").c.keys()
    except Exception:
        return hasattr(EventLog, field_name)


def log_event(
    db: Session,
    event_name: str,
    matricula: str | None = None,
    cid: Any = None,
    mode: EventMode = EventMode.ONLINE,
    result: EventResult | None = None,
    reason: str | None = None,
    validator_id: Any = None,
    device_id: str | None = None,
    extra: str | None = None,
) -> None:
    try:
        payload: dict[str, Any] = dict(
            event_name=event_name,
            matricula=matricula,
            cid=cid,
            mode=mode,
            result=result,
            reason=reason,
            validator_id=validator_id,
            device_id=device_id,
            ts=utcnow(),
        )

        if extra is not None and _eventlog_has_field("extra"):
            payload["extra"] = extra

        db.add(EventLog(**payload))
        db.flush()

    except (TypeError, SQLAlchemyError):
        db.rollback()
        return


# =========================
# Endpoints
# =========================
@router.post("/discover-flow")
def discover_flow(data: FlowDiscoverInput):
    ensure_institution_domain(data.email)

    db: Session = SessionLocal()
    try:
        return resolve_flow(db, data.email.lower())
    finally:
        db.close()


@router.post("/request-otp")
def request_otp(data: OTPRequestInput):
    ensure_institution_domain(data.email)

    email = data.email.lower()
    db: Session = SessionLocal()

    try:
        now = utcnow()
        last = latest_otp_for_email(db, email)

        if last and last.locked_until and last.locked_until > now:
            mins = int((last.locked_until - now).total_seconds() // 60) + 1
            raise HTTPException(status_code=429, detail=f"Too many attempts. Try again in ~{mins} min.")

        if last and last.last_sent_at:
            cooldown = timedelta(minutes=settings.OTP_COOLDOWN_MIN)
            if last.last_sent_at + cooldown > now:
                secs = int((last.last_sent_at + cooldown - now).total_seconds())
                raise HTTPException(status_code=429, detail=f"Cooldown active. Try again in {secs} seconds.")

        hour_bucket = get_hour_bucket(now)

        sent_count = 0
        if last and last.hour_bucket == hour_bucket:
            sent_count = last.sent_count_hour

        if sent_count >= settings.OTP_MAX_PER_HOUR:
            raise HTTPException(status_code=429, detail="Max OTP requests per hour reached. Try later.")

        otp = generate_otp()
        otp_hash = hash_otp(email, otp)
        expires_at = now + timedelta(minutes=settings.OTP_TTL_MIN)

        otp_record = OTPRequest(
            email=email,
            otp_hash=otp_hash,
            requested_at=now,
            expires_at=expires_at,
            attempts_used=0,
            locked_until=None,
            last_sent_at=now,
            sent_count_hour=sent_count + 1,
            hour_bucket=hour_bucket,
            verified=False,
            activation_token=None,
            activation_expires_at=None,
            activation_used=False,
        )

        db.add(otp_record)
        db.commit()

        try:
            send_email(
                to_email=email,
                subject="AURORA OTP Code",
                body=f"Tu código OTP es: {otp}\n\nExpira en {settings.OTP_TTL_MIN} minutos.",
            )
        except Exception as e:
            db.delete(otp_record)
            db.commit()
            raise HTTPException(status_code=500, detail=f"SMTP error: {str(e)}")

        log_event(db, "OTP_REQUESTED", matricula=None, reason=f"email={email}")
        db.commit()

        flow_info = resolve_flow(db, email)

        return {
            "message": "OTP sent",
            "email": email,
            "flow": flow_info["flow"],
        }

    finally:
        db.close()


@router.post("/verify-otp")
def verify_otp(data: OTPVerifyInput):
    ensure_institution_domain(data.email)

    email = data.email.lower()
    otp = data.otp.strip()

    if not otp.isdigit() or len(otp) != settings.OTP_DIGITS:
        raise HTTPException(status_code=400, detail="Invalid OTP format")

    db: Session = SessionLocal()

    try:
        now = utcnow()
        rec = latest_otp_for_email(db, email)

        if not rec:
            raise HTTPException(status_code=404, detail="No OTP requested for this email")

        if rec.verified:
            raise HTTPException(status_code=400, detail="OTP already used")

        if rec.locked_until and rec.locked_until > now:
            mins = int((rec.locked_until - now).total_seconds() // 60) + 1
            raise HTTPException(status_code=429, detail=f"Locked. Try again in ~{mins} min.")

        if rec.expires_at <= now:
            raise HTTPException(status_code=400, detail="OTP expired")

        expected = hash_otp(email, otp)

        if expected != rec.otp_hash:
            rec.attempts_used = (rec.attempts_used or 0) + 1

            if rec.attempts_used >= settings.OTP_MAX_ATTEMPTS:
                rec.locked_until = now + timedelta(minutes=settings.OTP_LOCK_MIN)
                log_event(db, "OTP_FAILED", reason="max_attempts_reached")
            else:
                log_event(db, "OTP_FAILED", reason="invalid_otp")

            db.add(rec)
            db.commit()

            raise HTTPException(status_code=401, detail="Invalid OTP")

        rec.verified = True
        db.add(rec)

        flow_info = resolve_flow(db, email)

        # -------------------------
        # VALIDATOR FLOW
        # -------------------------
        if flow_info["flow"] == "validator":
            validator = get_active_validator_by_email(db, email)
            if not validator:
                raise HTTPException(status_code=403, detail="Validator not authorized")

            # En validador no emitimos activation_token; emitimos sesión directamente
            session_token, session = create_auth_session(
                db=db,
                actor_type=ActorType.VALIDATOR,
                email=email,
                student_matricula=None,
                validator_id=validator.id,
            )

            log_event(
                db,
                "OTP_VERIFIED",
                reason=f"validator_email={email}",
                validator_id=validator.id,
            )
            log_event(
                db,
                "VALIDATOR_LOGIN",
                reason=f"role={validator.role.value}",
                validator_id=validator.id,
            )

            db.commit()

            return {
                "message": "OTP verified",
                "flow": "validator",
                "session_token": session_token,
                "session_expires_at": session.expires_at.isoformat(),
                "validator": {
                    "id": str(validator.id),
                    "email": validator.email,
                    "role": validator.role.value,
                },
            }

        # -------------------------
        # STUDENT FLOW
        # -------------------------
        activation_token = secrets.token_urlsafe(32)
        rec.activation_token = activation_token
        rec.activation_expires_at = now + timedelta(minutes=15)
        rec.activation_used = False

        db.add(rec)
        log_event(db, "OTP_VERIFIED", reason=f"student_email={email}")
        db.commit()

        return {
            "message": "OTP verified",
            "flow": "student",
            "activation_token": activation_token,
            "email": email,
            "activation_expires_at": rec.activation_expires_at.isoformat(),
            "has_active_credential": flow_info["has_active_credential"],
        }

    finally:
        db.close()


@router.post("/activate")
def activate(data: ActivateInput):
    ensure_institution_domain(data.email)

    email = data.email.lower()
    db: Session = SessionLocal()

    try:
        now = utcnow()

        # Si es validator, no debe entrar por activate
        validator = get_active_validator_by_email(db, email)
        if validator:
            raise HTTPException(status_code=400, detail="This email belongs to a validator. Use validator login flow.")

        rec = latest_otp_for_email(db, email)

        if not rec or not rec.verified:
            raise HTTPException(status_code=401, detail="OTP not verified")

        if not rec.activation_token or rec.activation_token != data.activation_token:
            raise HTTPException(status_code=401, detail="Invalid activation token")

        if rec.activation_used:
            raise HTTPException(status_code=400, detail="Activation token already used")

        if not rec.activation_expires_at or rec.activation_expires_at <= now:
            raise HTTPException(status_code=400, detail="Activation token expired")

        # 🔵 matrícula derivada del email
        derived_matricula = email

        existing_by_matricula = (
            db.query(Student)
            .filter(Student.matricula == derived_matricula)
            .first()
        )

        existing_by_email = (
            db.query(Student)
            .filter(Student.email == email)
            .first()
        )

        student = existing_by_email or existing_by_matricula

        incoming_full_name = (data.full_name or "").strip()
        incoming_program = data.program.strip() if data.program else None

        if not student:
            if not incoming_full_name:
                raise HTTPException(
                    status_code=400,
                    detail="full_name is required for first activation"
                )

            student = Student(
                matricula=derived_matricula,
                email=email,
                full_name=incoming_full_name,
                program=incoming_program,
            )

            db.add(student)
            db.flush()

        else:
            # Reactivación o actualización
            if incoming_full_name:
                student.full_name = incoming_full_name

            if data.program is not None:
                student.program = incoming_program

            db.add(student)
            db.flush()

        prev_actives = (
            db.query(Credential)
            .filter(Credential.student_matricula == student.matricula)
            .filter(Credential.status == CredentialStatus.ACTIVE)
            .all()
        )

        for c in prev_actives:
            c.status = CredentialStatus.REVOKED
            c.revoked_at = now
            db.add(c)

            db.add(CRLItem(cid=c.cid, revoked_at=now, reason="reactivation"))

            log_event(
                db,
                "CREDENTIAL_REVOKED",
                matricula=student.matricula,
                cid=c.cid,
                reason="reactivation",
            )

        new_cred = Credential(
            student_matricula=student.matricula,
            status=CredentialStatus.ACTIVE,
            issued_at=now,
            revoked_at=None,
            expires_at=now + timedelta(days=100),
        )

        db.add(new_cred)
        db.flush()

        rec.activation_used = True
        db.add(rec)

        # Crear sesión autenticada del estudiante
        session_token, session = create_auth_session(
            db=db,
            actor_type=ActorType.STUDENT,
            email=student.email,
            student_matricula=student.matricula,
            validator_id=None,
        )

        log_event(db, "ACCOUNT_ACTIVATED", matricula=student.matricula, reason=f"email={student.email}")
        log_event(db, "CREDENTIAL_ISSUED", matricula=student.matricula, cid=new_cred.cid)

        db.commit()

        return {
            "message": "Account activated",
            "flow": "student",
            "session_token": session_token,
            "session_expires_at": session.expires_at.isoformat(),
            "student": {
                "matricula": student.matricula,
                "email": student.email,
                "full_name": student.full_name,
                "program": student.program,
            },
            "credential": {
                "cid": str(new_cred.cid),
                "status": new_cred.status.value,
                "issued_at": new_cred.issued_at.isoformat(),
                "expires_at": new_cred.expires_at.isoformat() if new_cred.expires_at else None,
            },
        }

    finally:
        db.close()


@router.get("/me")
def me(authorization: str | None = Header(default=None)):
    db: Session = SessionLocal()

    try:
        session = get_session_from_authorization(db, authorization)

        payload: dict[str, Any] = {
            "session_id": str(session.id),
            "actor_type": session.actor_type.value,
            "email": session.email,
            "student_matricula": session.student_matricula,
            "validator_id": str(session.validator_id) if session.validator_id else None,
            "status": session.status.value,
            "issued_at": session.issued_at.isoformat(),
            "last_seen_at": session.last_seen_at.isoformat(),
            "expires_at": session.expires_at.isoformat(),
        }

        if session.actor_type == ActorType.STUDENT and session.student_matricula:
            student = (
                db.query(Student)
                .filter(Student.matricula == session.student_matricula)
                .first()
            )
            payload["student"] = (
                {
                    "matricula": student.matricula,
                    "email": student.email,
                    "full_name": student.full_name,
                    "program": student.program,
                    "status": student.status.value,
                }
                if student
                else None
            )

        if session.actor_type == ActorType.VALIDATOR and session.validator_id:
            validator = (
                db.query(Validator)
                .filter(Validator.id == session.validator_id)
                .first()
            )
            payload["validator"] = (
                {
                    "id": str(validator.id),
                    "email": validator.email,
                    "role": validator.role.value,
                    "is_active": validator.is_active,
                }
                if validator
                else None
            )

        return payload

    finally:
        db.close()


@router.post("/logout")
def logout(authorization: str | None = Header(default=None)):
    db: Session = SessionLocal()

    try:
        token = get_bearer_token(authorization)
        token_hash = hash_session_token(token)

        session = (
            db.query(AuthSession)
            .filter(AuthSession.token_hash == token_hash)
            .first()
        )

        if not session:
            raise HTTPException(status_code=401, detail="Invalid session")

        session.status = SessionStatus.REVOKED
        session.revoked_at = utcnow()
        session.revoke_reason = "logout"
        db.add(session)

        log_event(
            db,
            "SESSION_REVOKED",
            matricula=session.student_matricula,
            validator_id=session.validator_id,
            reason="logout",
        )

        db.commit()

        return {"message": "Logged out"}

    finally:
        db.close()