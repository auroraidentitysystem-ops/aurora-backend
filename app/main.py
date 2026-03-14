from contextlib import asynccontextmanager
import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.api import crl
from app.api.validate_offline_sim import router as validate_offline_router
from app.api.validate_offline import router as validate_offline_v2_router  # NUEVO (REAL)
from app.api.validate import router as validate_router
from app.api.auth import router as auth_router
from app.api.student import router as student_router
from app.api.qr import router as qr_router
from app.api.token_debug import router as debug_router

from app.db.session import engine
from app.db.base import Base
import app.db.models  # noqa: F401  (importa modelos para que Base los registre)

logger = logging.getLogger("aurora")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup/shutdown estable.
    - Intenta crear tablas.
    - Si falla la DB, NO tumba el server: deja que /health siga vivo
      y verás el error en logs (para diagnóstico).
    """
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("DB schema ensured (create_all ok).")
    except Exception as e:
        logger.exception("DB not ready / create_all failed: %s", e)

    yield

    logger.info("Shutting down AURORA API.")


app = FastAPI(
    title="AURORA v0 API",
    version="0.1.0",
    lifespan=lifespan,
)

# (Opcional pero recomendado) CORS para cuando conectes PWA/Frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # cámbialo luego por dominios específicos
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================
# STATIC FILES
# =========================
# Estructura esperada:
# backend/
# ├─ app/
# ├─ static/
# │  ├─ photos/
# │  │  ├─ 2512312001.png
# │  │  ├─ A00123456.png
# │  │  └─ ...
# │  └─ default/
# │     └─ default.png

BASE_DIR = Path(__file__).resolve().parents[1]   # backend/
STATIC_DIR = BASE_DIR / "static"

# crea la carpeta si no existe
STATIC_DIR.mkdir(parents=True, exist_ok=True)
(STATIC_DIR / "photos").mkdir(parents=True, exist_ok=True)
(STATIC_DIR / "default").mkdir(parents=True, exist_ok=True)

# expone /static/...
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# ✅ Registrar routers (DESPUÉS de crear app)
app.include_router(auth_router)
app.include_router(student_router)
app.include_router(qr_router)
app.include_router(debug_router)
app.include_router(validate_router)
app.include_router(crl.router)

# OFFLINE
app.include_router(validate_offline_router)       # SIM (fase 1)
app.include_router(validate_offline_v2_router)    # REAL (fase 2: verifica firma CRL)


@app.get("/", tags=["default"])
def root():
    return {"message": "AURORA backend running"}


@app.get("/health", tags=["default"])
def health():
    return {"status": "ok"}


@app.get("/_debug/config", tags=["default"])
def debug_config():
    from app.core.config import settings

    return {
        "status": "ok",
        "institution_email_domain": settings.INSTITUTION_EMAIL_DOMAIN,
        "otp_digits": settings.OTP_DIGITS,
        "otp_ttl_min": settings.OTP_TTL_MIN,
        "qr_rotate_sec": settings.QR_ROTATE_SEC,
        "qr_token_ttl_sec": settings.QR_TOKEN_TTL_SEC,
        "crl_valid_hours": settings.CRL_VALID_HOURS,
        "crl_refresh_hours": settings.CRL_REFRESH_HOURS,
        "smtp_host": settings.SMTP_HOST,
        "smtp_user": settings.SMTP_USER,
    }