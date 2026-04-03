import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
IS_VERCEL = os.getenv("VERCEL") == "1"


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "securecloud-secret-key")

    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "sqlite:////tmp/secure_cloud.db" if IS_VERCEL else "sqlite:///" + os.path.join(BASE_DIR, "secure_cloud.db")
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    UPLOAD_FOLDER = os.getenv(
        "UPLOAD_FOLDER",
        "/tmp/uploads" if IS_VERCEL else os.path.join(BASE_DIR, "uploads")
    )

    ENCRYPTED_FOLDER = os.getenv(
        "ENCRYPTED_FOLDER",
        "/tmp/encrypted" if IS_VERCEL else os.path.join(BASE_DIR, "encrypted")
    )