from flask_bcrypt import Bcrypt

from app import app
from models import User, db
from services.rsa_key_manager import generate_rsa_keypair


def create_demo_users():
    bcrypt = Bcrypt(app)
    users = [
        ("admin", "admin@securecloud.com", "Admin@123", "admin"),
        ("user", "user@securecloud.com", "User@123", "user"),
        ("auditor", "auditor@securecloud.com", "Auditor@123", "auditor"),
    ]
    for username, email, password, role in users:
        if User.query.filter_by(email=email).first():
            continue
        pub, pri = generate_rsa_keypair()
        u = User(
            username=username,
            email=email,
            password_hash=bcrypt.generate_password_hash(password).decode("utf-8"),
            role=role,
            public_key=pub,
            private_key=pri,
            is_active=True,
        )
        db.session.add(u)
    db.session.commit()


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        create_demo_users()
        print("Demo users seeded.")
