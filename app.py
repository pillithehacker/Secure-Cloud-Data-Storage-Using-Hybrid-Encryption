import os
from datetime import datetime

from flask import Flask, flash, redirect, render_template, request, send_file, url_for
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, current_user, login_required, login_user, logout_user

from config import Config
from models import ActivityLog, File, User, db
from services.access_control import role_required
from services.encryption_service import decrypt_file_hybrid, encrypt_file_hybrid
from services.file_service import decrypted_file_path, encrypted_file_path, save_uploaded_file
from services.hash_service import sha256_file
from services.rsa_key_manager import generate_rsa_keypair

app = Flask(__name__)
app.config.from_object(Config)

bcrypt = Bcrypt(app)
db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "warning"

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
os.makedirs(app.config["ENCRYPTED_FOLDER"], exist_ok=True)

with app.app_context():
    db.create_all()

    if not User.query.filter_by(email="admin@securecloud.com").first():
        admin_public, admin_private = generate_rsa_keypair()
        user_public, user_private = generate_rsa_keypair()
        auditor_public, auditor_private = generate_rsa_keypair()

        admin = User(
            username="admin",
            email="admin@securecloud.com",
            password_hash=bcrypt.generate_password_hash("admin123").decode("utf-8"),
            role="admin",
            is_active=True,
            public_key=admin_public,
            private_key=admin_private,
        )

        demo_user = User(
            username="user",
            email="user@securecloud.com",
            password_hash=bcrypt.generate_password_hash("user123").decode("utf-8"),
            role="user",
            is_active=True,
            public_key=user_public,
            private_key=user_private,
        )

        auditor = User(
            username="auditor",
            email="auditor@securecloud.com",
            password_hash=bcrypt.generate_password_hash("auditor123").decode("utf-8"),
            role="auditor",
            is_active=True,
            public_key=auditor_public,
            private_key=auditor_private,
        )

        db.session.add(admin)
        db.session.add(demo_user)
        db.session.add(auditor)
        db.session.commit()


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def log_activity(action, file_id=None, status="success"):
    if not current_user.is_authenticated:
        return

    entry = ActivityLog(
        user_id=current_user.id,
        action=action,
        file_id=file_id,
        ip_address=request.remote_addr,
        status=status,
    )
    db.session.add(entry)
    db.session.commit()


def can_access_file(file_obj):
    if current_user.role == "admin":
        return True
    if file_obj.owner_id == current_user.id:
        return True
    return current_user.id in file_obj.shared_user_ids()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/developers")
def developers():
    return render_template("developers.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if user and user.is_active and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user)
            log_activity("Logged in")

            if user.role == "admin":
                return redirect(url_for("admin_dashboard"))
            elif user.role == "auditor":
                return redirect(url_for("auditor_dashboard"))
            else:
                return redirect(url_for("user_dashboard"))

        flash("Invalid credentials or inactive account.", "danger")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    log_activity("Logged out")
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for("index"))


@app.route("/admin/dashboard")
@login_required
@role_required("admin")
def admin_dashboard():
    users = User.query.order_by(User.created_at.desc()).all()
    files = File.query.order_by(File.uploaded_at.desc()).all()
    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(10).all()

    stats = {
        "total_users": User.query.count(),
        "active_users": User.query.filter_by(is_active=True).count(),
        "total_files": File.query.count(),
    }

    return render_template(
        "dashboard/admin_dashboard.html",
        users=users,
        files=files,
        logs=logs,
        stats=stats,
    )


@app.route("/user/dashboard")
@login_required
@role_required("user")
def user_dashboard():
    user_files = File.query.filter_by(owner_id=current_user.id).all()
    logs = ActivityLog.query.filter_by(user_id=current_user.id).order_by(ActivityLog.timestamp.desc()).limit(8).all()

    return render_template(
        "dashboard/user_dashboard.html",
        user_files=user_files,
        logs=logs,
    )


@app.route("/auditor/dashboard")
@login_required
@role_required("auditor")
def auditor_dashboard():
    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(50).all()
    files = File.query.order_by(File.uploaded_at.desc()).all()

    return render_template(
        "dashboard/auditor_dashboard.html",
        logs=logs,
        all_files=files,
    )


@app.route("/files")
@login_required
def files():
    if current_user.role == "admin":
        records = File.query.order_by(File.uploaded_at.desc()).all()
    else:
        records = [f for f in File.query.order_by(File.uploaded_at.desc()).all() if can_access_file(f)]

    recent_activity = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(7).all()

    return render_template("files/files.html", files=records, recent_activity=recent_activity)


@app.route("/upload", methods=["GET", "POST"])
@login_required
@role_required("user", "admin")
def upload():
    if request.method == "POST":
        uploaded_file = request.files.get("file")

        if not uploaded_file or uploaded_file.filename == "":
            flash("Please select a file.", "warning")
            return redirect(url_for("upload"))

        filename, original_name, file_path = save_uploaded_file(uploaded_file, app.config["UPLOAD_FOLDER"])

        file_record = File(
            filename=filename,
            original_filename=original_name,
            file_size=os.path.getsize(file_path),
            file_type=uploaded_file.content_type,
            decrypted_path=file_path,
            owner_id=current_user.id,
            encryption_status="raw",
            uploaded_at=datetime.utcnow(),
            file_hash=sha256_file(file_path),
        )

        db.session.add(file_record)
        db.session.commit()

        log_activity("Uploaded file", file_record.id)
        flash("File uploaded successfully.", "success")
        return redirect(url_for("files"))

    return render_template("files/upload.html")


@app.errorhandler(403)
def forbidden(_):
    return render_template("errors/access_denied.html"), 403


@app.errorhandler(404)
def not_found(_):
    return render_template("errors/access_denied.html"), 404


@app.errorhandler(500)
def server_error(error):
    db.session.rollback()
    return render_template("errors/access_denied.html"), 500


if __name__ == "__main__":
    app.run(debug=True)