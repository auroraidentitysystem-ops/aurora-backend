# backend/app/api/token_debug.py

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.verify_service import verify_student_qr_token, TokenError

router = APIRouter(prefix="/_debug", tags=["debug"])


class VerifyRequest(BaseModel):
    token: str


@router.post("/verify-token")
def debug_verify_token(req: VerifyRequest):
    """
    Debug endpoint: verifica firma y expiración del token QR.
    Útil para probar D1 antes de implementar /validate.
    """
    try:
        payload = verify_student_qr_token(req.token)
        return {"ok": True, "payload": payload}
    except TokenError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        # Por si hay algo inesperado, que Swagger te muestre algo útil
        raise HTTPException(status_code=500, detail=f"Unexpected error: {e}")