from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from dotenv import load_dotenv
from pathlib import Path

# Carga backend/.env siempre (sin depender del "working directory")
ENV_PATH = Path(__file__).resolve().parents[2] / ".env"
load_dotenv(dotenv_path=ENV_PATH)

# 👉 Ruta absoluta a backend/.env
ENV_PATH = Path(__file__).resolve().parents[2] / ".env"


class Settings(BaseSettings):
    # -------------------------
    # DATABASE
    # -------------------------
    DATABASE_URL: str

    # -------------------------
    # INSTITUTION
    # -------------------------
    INSTITUTION_EMAIL_DOMAIN: str = "@utcorregidora.edu.mx"

    # -------------------------
    # OTP POLICY
    # -------------------------
    OTP_DIGITS: int = 6
    OTP_TTL_MIN: int = 10
    OTP_MAX_ATTEMPTS: int = 3
    OTP_LOCK_MIN: int = 60
    OTP_MAX_PER_HOUR: int = 3
    OTP_COOLDOWN_MIN: int = 1

    # -------------------------
    # QR POLICY
    # -------------------------
    QR_ROTATE_SEC: int = 30
    QR_TOKEN_TTL_SEC: int = 45
    CLOCK_SKEW_SEC: int = 30

    # -------------------------
    # CRL POLICY
    # -------------------------
    CRL_VALID_HOURS: int = 24
    CRL_REFRESH_HOURS: int = 6

    # -------------------------
    # CRYPTO (ED25519)
    # -------------------------
    ED25519_PRIVATE_KEY_B64: str | None = None
    ED25519_PUBLIC_KEY_B64: str | None = None

    # -------------------------
    # SMTP (GMAIL)
    # -------------------------
    SMTP_HOST: str
    SMTP_PORT: int
    SMTP_USER: str
    SMTP_PASSWORD: str
    SMTP_TLS: bool = True

    # -------------------------
    # Pydantic Config
    # -------------------------
    model_config = SettingsConfigDict(
        env_file=str(ENV_PATH),
        extra="ignore",
    )


settings = Settings()