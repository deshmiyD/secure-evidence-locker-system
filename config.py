import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "sqlite:///" + os.path.join(BASE_DIR, "app.db"),
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Where encrypted evidence files are stored
    EVIDENCE_FOLDER = os.path.join(BASE_DIR, "evidence_store")
    os.makedirs(EVIDENCE_FOLDER, exist_ok=True)

    # AES/Fernet key for encryption (for demo, from env or generated once)
    # In production, store this securely (e.g., env var, vault).
    EVIDENCE_ENC_KEY = os.environ.get("EVIDENCE_ENC_KEY", None)

    # Email configuration (Gmail example; fill with your values)
    MAIL_SERVER = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", 587))
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "desh9884@gmail.com")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD", "jofnzpmjtqrpspxa")
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER", MAIL_USERNAME)
    ALERT_EMAIL_TO = os.environ.get("ALERT_EMAIL_TO", MAIL_USERNAME)

    # Security alert thresholds
    FAILED_LOGIN_THRESHOLD = int(os.environ.get("FAILED_LOGIN_THRESHOLD", 3))
    FAILED_LOGIN_WINDOW_MINUTES = int(os.environ.get("FAILED_LOGIN_WINDOW_MINUTES", 15))


