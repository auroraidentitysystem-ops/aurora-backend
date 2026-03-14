# aurora/backend/app/services/crl_service.py

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.db.models import CRLItem
from app.services.crypto_service import sign_detached_json


def _dt_to_epoch_seconds(dt) -> Optional[int]:
    if dt is None:
        return None
    if hasattr(dt, "timestamp"):
        return int(dt.timestamp())
    return None


def build_crl_payload(db: Session, ttl_seconds: int = 24 * 3600) -> Dict[str, Any]:
    """
    Construye payload CRL desde crl_items.
    ttl_seconds default: 24h (Option C).
    """
    issued_at = int(time.time())
    exp = issued_at + int(ttl_seconds)

    items: List[CRLItem] = db.query(CRLItem).all()

    revoked: List[Dict[str, Any]] = []
    for it in items:
        # En tu modelo CRLItem normalmente existe cid (UUID)
        cid_val = getattr(it, "cid", None)
        if cid_val is None:
            continue

        revoked_at = getattr(it, "revoked_at", None) or getattr(it, "created_at", None)
        reason = getattr(it, "reason", None)

        entry: Dict[str, Any] = {"cid": str(cid_val)}
        ts = _dt_to_epoch_seconds(revoked_at)
        if ts is not None:
            entry["revoked_at"] = ts
        if reason:
            entry["reason"] = str(reason)

        revoked.append(entry)

    return {
        "crl_issued_at": issued_at,
        "crl_exp": exp,
        "revoked": revoked,
    }


def build_and_sign_crl(db: Session, ttl_seconds: int = 24 * 3600) -> Dict[str, Any]:
    """
    Retorna:
      {
        "payload": {...},
        "signature": "<b64url>",
        "kid": "<kid>"
      }
    """
    payload = build_crl_payload(db, ttl_seconds=ttl_seconds)
    signature, kid = sign_detached_json(payload)
    return {"payload": payload, "signature": signature, "kid": kid}