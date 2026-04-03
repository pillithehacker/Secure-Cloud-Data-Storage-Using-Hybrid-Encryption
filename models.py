from datetime import datetime

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")
    public_key = db.Column(db.Text, nullable=True)
    private_key = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    files = db.relationship("File", backref="owner", lazy=True, cascade="all, delete-orphan")
    logs = db.relationship(
        "ActivityLog", backref="actor", lazy=True, cascade="all, delete-orphan"
    )

    def get_id(self):
        return str(self.id)


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, nullable=True)
    file_type = db.Column(db.String(100), nullable=True)
    encrypted_path = db.Column(db.String(255), nullable=True)
    decrypted_path = db.Column(db.String(255), nullable=True)
    encrypted_aes_key = db.Column(db.Text, nullable=True)
    iv_or_nonce = db.Column(db.Text, nullable=True)
    file_hash = db.Column(db.String(128), nullable=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    shared_with = db.Column(db.Text, nullable=True)  # comma separated user ids
    encryption_status = db.Column(db.String(20), default="raw", nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    logs = db.relationship("ActivityLog", backref="file", lazy=True)

    def shared_user_ids(self):
        if not self.shared_with:
            return []
        return [int(x) for x in self.shared_with.split(",") if x.strip().isdigit()]

    def set_shared_user_ids(self, user_ids):
        user_ids = sorted(set(int(uid) for uid in user_ids))
        self.shared_with = ",".join(str(uid) for uid in user_ids)


class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey("file.id"), nullable=True)
    ip_address = db.Column(db.String(50), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    status = db.Column(db.String(20), default="success", nullable=False)
