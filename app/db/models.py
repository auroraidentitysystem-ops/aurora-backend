import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    String,
    DateTime,
    Enum,
    Integer,
    Boolean,
    Text,
    ForeignKey,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.db.base import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# -------------------------
# Enums
# -------------------------
class StudentStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"


class CredentialStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    SUSPENDED = "SUSPENDED"


class ValidatorRole(str, enum.Enum):
    GUARD = "GUARD"
    TEACHER = "TEACHER"
    ADMIN = "ADMIN"


class EventMode(str, enum.Enum):
    ONLINE = "ONLINE"
    OFFLINE = "OFFLINE"


class EventResult(str, enum.Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class ActorType(str, enum.Enum):
    STUDENT = "STUDENT"
    VALIDATOR = "VALIDATOR"


class SessionStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


# -------------------------
# Tables
# -------------------------
class Student(Base):
    """
    AURORA v0:
    - matrícula es el identificador principal (PK).
    - email institucional es único e inmutable (en lógica de negocio).
    """
    __tablename__ = "students"

    matricula = Column(String(64), primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    full_name = Column(String(255), nullable=False)
    program = Column(String(255), nullable=True)

    status = Column(Enum(StudentStatus), nullable=False, default=StudentStatus.ACTIVE)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class OTPRequest(Base):
    """
    Guarda solicitudes OTP por email.
    Nota: la lógica de rate-limit/lockout se implementa en endpoints/servicios.
    """
    __tablename__ = "otp_requests"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    email = Column(String(255), index=True, nullable=False)
    otp_hash = Column(String(255), nullable=False)

    requested_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)

    attempts_used = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime(timezone=True), nullable=True)

    # rate limiting (max per hour + cooldown)
    last_sent_at = Column(DateTime(timezone=True), nullable=True)
    sent_count_hour = Column(Integer, default=0, nullable=False)
    hour_bucket = Column(DateTime(timezone=True), nullable=True)

    verified = Column(Boolean, default=False, nullable=False)

    # activation token para flujo posterior a verify-otp
    activation_token = Column(String(255), nullable=True, index=True)
    activation_expires_at = Column(DateTime(timezone=True), nullable=True)
    activation_used = Column(Boolean, default=False, nullable=False)


class Credential(Base):
    """
    Credencial activa por estudiante (la política lo controla).
    'cid' es el id de credencial usado para CRL / revocación.
    """
    __tablename__ = "credentials"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # credential id para CRL (no se muestra a estudiante)
    cid = Column(UUID(as_uuid=True), unique=True, index=True, default=uuid.uuid4, nullable=False)

    # FK a matrícula (PK de students)
    student_matricula = Column(
        String(64),
        ForeignKey("students.matricula"),
        index=True,
        nullable=False,
    )

    status = Column(Enum(CredentialStatus), nullable=False, default=CredentialStatus.ACTIVE)

    issued_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)


class Validator(Base):
    """
    Whitelist de validadores (Guard/Teacher/Admin).
    """
    __tablename__ = "validators"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, index=True, nullable=False)
    role = Column(Enum(ValidatorRole), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AuthSession(Base):
    """
    Sesiones autenticadas para STUDENT o VALIDATOR.

    Idea:
    - El frontend ya no debe pedir credencial/QR solo por email.
    - Primero autentica y recibe un session_token.
    - El backend guarda solo hash del token, no el token plano.
    - Una sesión pertenece o a un STUDENT o a un VALIDATOR.
    """
    __tablename__ = "auth_sessions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    actor_type = Column(Enum(ActorType), index=True, nullable=False)

    # Identidad base
    email = Column(String(255), index=True, nullable=False)

    # Nullable según actor_type
    student_matricula = Column(
        String(64),
        ForeignKey("students.matricula"),
        index=True,
        nullable=True,
    )
    validator_id = Column(
        UUID(as_uuid=True),
        ForeignKey("validators.id"),
        index=True,
        nullable=True,
    )

    # Token de sesión (guardar hash, no token plano)
    token_hash = Column(String(255), unique=True, index=True, nullable=False)

    status = Column(Enum(SessionStatus), nullable=False, default=SessionStatus.ACTIVE)

    # Para binding por dispositivo si luego lo endureces más
    device_id = Column(String(128), nullable=True)
    device_name = Column(String(255), nullable=True)

    issued_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_seen_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)

    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revoke_reason = Column(String(255), nullable=True)


class CRLItem(Base):
    """
    Lista de credenciales revocadas/suspendidas para validación offline.
    """
    __tablename__ = "crl_items"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    cid = Column(UUID(as_uuid=True), index=True, nullable=False)
    revoked_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    reason = Column(String(255), nullable=True)


class EventLog(Base):
    """
    Bitácora de eventos (identity/credential/validation/validator).
    """
    __tablename__ = "event_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ts = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    event_name = Column(String(64), index=True, nullable=False)

    # subject / actor
    matricula = Column(String(64), index=True, nullable=True)
    cid = Column(UUID(as_uuid=True), nullable=True)

    validator_id = Column(UUID(as_uuid=True), nullable=True)
    device_id = Column(String(128), nullable=True)

    mode = Column(Enum(EventMode), nullable=False, default=EventMode.ONLINE)
    result = Column(Enum(EventResult), nullable=True)

    reason = Column(Text, nullable=True)