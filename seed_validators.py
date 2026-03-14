# backend/seed_validators.py
from __future__ import annotations

import uuid

from app.db.session import SessionLocal
from app.db.models import Validator, ValidatorRole


SEED_VALIDATORS = [
    ("admin1@utcorregidora.edu.mx", ValidatorRole.ADMIN),
    ("guardia1@utcorregidora.edu.mx", ValidatorRole.GUARD),
    ("teacher_role_test@utcorregidora.edu.mx", ValidatorRole.TEACHER),
]


def upsert_validator(db, email: str, role: ValidatorRole):
    email_norm = email.strip().lower()

    existing = (
        db.query(Validator)
        .filter(Validator.email == email_norm)
        .first()
    )

    if existing is None:
        v = Validator(
            id=uuid.uuid4(),
            email=email_norm,
            role=role,
            is_active=True,
        )
        db.add(v)
        print(f"[CREATE] {email_norm} -> {role.value}")
    else:
        changed = False

        if existing.role != role:
            existing.role = role
            changed = True

        if not existing.is_active:
            existing.is_active = True
            changed = True

        print(f"[UPDATE] {email_norm} -> {role.value} (changed={changed})")

    db.commit()


def main():
    db = SessionLocal()
    try:
        for email, role in SEED_VALIDATORS:
            upsert_validator(db, email, role)
    finally:
        db.close()


if __name__ == "__main__":
    main()