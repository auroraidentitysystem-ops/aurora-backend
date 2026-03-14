# aurora/backend/app/api/crl.py

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.models import Validator
from app.services.crl_service import build_and_sign_crl

router = APIRouter(prefix="/crl", tags=["crl"])


class CRLResponse(BaseModel):
    payload: dict
    signature: str
    kid: str


@router.get("/current", response_model=CRLResponse)
def get_current_crl(validator_email: str, db: Session = Depends(get_db)):
    """
    Descarga CRL firmada para que el validador la almacene y use offline.
    Por ahora la "autenticación" es whitelist por validator_email (temporal).
    """
    email = (validator_email or "").strip().lower()
    v = db.query(Validator).filter(Validator.email == email).first()
    if v is None or not v.is_active:
        raise HTTPException(status_code=403, detail="Validator not authorized")

    # TTL 24h (Option C)
    return build_and_sign_crl(db, ttl_seconds=24 * 3600)