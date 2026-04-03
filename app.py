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
db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
os.makedirs(app.config["ENCRYPTED_FOLDER"], exist_ok=True)


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


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "user")

        if User.query.filter((User.email == email) | (User.username == username)).first():
            flash("Email or username already exists.", "danger")
            return redirect(url_for("register"))

        public_key, private_key = generate_rsa_keypair()
        hashed = bcrypt.generate_password_hash(password).decode("utf-8")
        user = User(
            username=username,
            email=email,
            password_hash=hashed,
            role=role if role in {"user", "auditor"} else "user",
            public_key=public_key,
            private_key=private_key,
        )
        db.session.add(user)
        db.session.commit()
        flash("Registration successful. Login now.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


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
            if user.role == "auditor":
                return redirect(url_for("auditor_dashboard"))
            return redirect(url_for("user_dashboard"))
        if user:
            db.session.add(
                ActivityLog(
                    user_id=user.id,
                    action="Failed login",
                    ip_address=request.remote_addr,
                    status="failed",
                )
            )
            db.session.commit()
        flash("Invalid credentials or account blocked.", "danger")
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
    return render_template("dashboard/admin_dashboard.html", users=users, files=files, logs=logs, stats=stats)


@app.route("/admin/user/block/<int:user_id>", methods=["POST"])
@login_required
@role_required("admin")
def admin_block_user(user_id):
    target = db.session.get(User, user_id)
    if not target or target.id == current_user.id:
        return redirect(url_for("admin_dashboard"))

    target.is_active = not target.is_active
    db.session.commit()
    log_activity("Blocked user" if not target.is_active else "Unblocked user")
    flash("User status updated.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/user/delete/<int:user_id>", methods=["POST"])
@login_required
@role_required("admin")
def admin_delete_user(user_id):
    target = db.session.get(User, user_id)
    if not target or target.id == current_user.id:
        return redirect(url_for("admin_dashboard"))

    # Best-effort cleanup of physical files.
    for f in list(target.files):
        for p in [f.decrypted_path, f.encrypted_path]:
            if p and os.path.exists(p):
                os.remove(p)
    db.session.delete(target)
    db.session.commit()
    log_activity("Deleted user")
    flash("User deleted.", "info")
    return redirect(url_for("admin_dashboard"))


@app.route("/user/dashboard")
@login_required
@role_required("user")
def user_dashboard():
    user_files = File.query.filter_by(owner_id=current_user.id).order_by(File.uploaded_at.desc()).all()
    shared_files = [f for f in File.query.order_by(File.uploaded_at.desc()).all() if current_user.id in f.shared_user_ids()]
    logs = ActivityLog.query.filter_by(user_id=current_user.id).order_by(ActivityLog.timestamp.desc()).limit(8).all()
    storage = sum(f.file_size or 0 for f in user_files)
    return render_template(
        "dashboard/user_dashboard.html",
        user_files=user_files,
        shared_files=shared_files,
        logs=logs,
        storage=storage,
    )


@app.route("/auditor/dashboard")
@login_required
@role_required("auditor")
def auditor_dashboard():
    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(50).all()
    all_files = File.query.order_by(File.uploaded_at.desc()).all()
    failed_logins = ActivityLog.query.filter_by(action="Failed login").count()
    return render_template(
        "dashboard/auditor_dashboard.html", logs=logs, all_files=all_files, failed_logins=failed_logins
    )


@app.route("/files")
@login_required
def files():
    if current_user.role == "admin":
        records = File.query.order_by(File.uploaded_at.desc()).all()
        recent_activity = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(7).all()
    else:
        records = [f for f in File.query.order_by(File.uploaded_at.desc()).all() if can_access_file(f)]
        recent_activity = (
            ActivityLog.query.filter_by(user_id=current_user.id)
            .order_by(ActivityLog.timestamp.desc())
            .limit(7)
            .all()
        )
    return render_template("files/files.html", files=records, recent_activity=recent_activity)


@app.route("/upload", methods=["GET", "POST"])
@login_required
@role_required("user", "admin")
def upload():
    if request.method == "POST":
        file = request.files.get("file")
        if not file or not file.filename:
            flash("Please select a file.", "warning")
            return redirect(url_for("upload"))

        filename, original, path = save_uploaded_file(file, app.config["UPLOAD_FOLDER"])
        file_record = File(
            filename=filename,
            original_filename=original,
            file_size=os.path.getsize(path),
            file_type=file.content_type,
            decrypted_path=path,
            owner_id=current_user.id,
            encryption_status="raw",
            uploaded_at=datetime.utcnow(),
        )
        file_record.file_hash = sha256_file(path)
        db.session.add(file_record)
        db.session.commit()
        log_activity("Uploaded file", file_record.id)
        flash("File uploaded.", "success")
        return redirect(url_for("files"))
    return render_template("files/upload.html")


@app.route("/encrypt/<int:file_id>")
@login_required
@role_required("user", "admin")
def encrypt_file(file_id):
    fobj = db.session.get(File, file_id)
    if not fobj or not can_access_file(fobj):
        return render_template("errors/access_denied.html"), 403
    if not fobj.decrypted_path or not os.path.exists(fobj.decrypted_path):
        flash("Original file not found.", "danger")
        return redirect(url_for("files"))

    enc_path = encrypted_file_path(app.config["ENCRYPTED_FOLDER"], fobj.filename)
    encrypted_key, nonce = encrypt_file_hybrid(fobj.decrypted_path, enc_path, current_user.public_key)
    fobj.encrypted_path = enc_path
    fobj.encrypted_aes_key = encrypted_key
    fobj.iv_or_nonce = nonce
    fobj.encryption_status = "encrypted"
    db.session.commit()
    log_activity("Encrypted file", fobj.id)
    flash("File encrypted successfully.", "success")
    return redirect(url_for("files"))


@app.route("/decrypt/<int:file_id>")
@login_required
@role_required("user", "admin")
def decrypt_file(file_id):
    fobj = db.session.get(File, file_id)
    if not fobj or not can_access_file(fobj):
        return render_template("errors/access_denied.html"), 403
    if not fobj.encrypted_path or not os.path.exists(fobj.encrypted_path):
        flash("Encrypted file not found.", "danger")
        return redirect(url_for("files"))

    out_path = decrypted_file_path(app.config["UPLOAD_FOLDER"], fobj.filename)
    decrypt_file_hybrid(
        fobj.encrypted_path, out_path, current_user.private_key, fobj.encrypted_aes_key, fobj.iv_or_nonce
    )
    fobj.decrypted_path = out_path
    fobj.file_hash = sha256_file(out_path)
    fobj.encryption_status = "decrypted"
    db.session.commit()
    log_activity("Decrypted file", fobj.id)
    flash("File decrypted successfully.", "success")
    return redirect(url_for("files"))


@app.route("/download/<int:file_id>")
@login_required
def download_file(file_id):
    fobj = db.session.get(File, file_id)
    if not fobj or not can_access_file(fobj):
        return render_template("errors/access_denied.html"), 403
    if current_user.role == "auditor":
        return render_template("errors/access_denied.html"), 403

    path = fobj.decrypted_path if fobj.decrypted_path and os.path.exists(fobj.decrypted_path) else fobj.encrypted_path
    if not path or not os.path.exists(path):
        flash("File path missing.", "danger")
        return redirect(url_for("files"))
    log_activity("Downloaded file", fobj.id)
    return send_file(path, as_attachment=True, download_name=fobj.original_filename)


@app.route("/delete/<int:file_id>")
@login_required
def delete_file(file_id):
    fobj = db.session.get(File, file_id)
    if not fobj:
        flash("File not found.", "warning")
        return redirect(url_for("files"))
    if current_user.role != "admin" and fobj.owner_id != current_user.id:
        return render_template("errors/access_denied.html"), 403

    for p in [fobj.decrypted_path, fobj.encrypted_path]:
        if p and os.path.exists(p):
            os.remove(p)
    db.session.delete(fobj)
    db.session.commit()
    log_activity("Deleted file", file_id)
    flash("File deleted.", "info")
    return redirect(url_for("files"))


@app.route("/share/<int:file_id>", methods=["POST"])
@login_required
@role_required("user", "admin")
def share_file(file_id):
    fobj = db.session.get(File, file_id)
    if not fobj or (current_user.role != "admin" and fobj.owner_id != current_user.id):
        return render_template("errors/access_denied.html"), 403
    email = request.form.get("email", "").strip().lower()
    target = User.query.filter_by(email=email).first()
    if not target:
        flash("User not found.", "warning")
        return redirect(url_for("files"))
    shared = fobj.shared_user_ids()
    shared.append(target.id)
    fobj.set_shared_user_ids(shared)
    db.session.commit()
    log_activity(f"Shared file with {email}", fobj.id)
    flash("File shared successfully.", "success")
    return redirect(url_for("files"))


@app.route("/files/shared")
@login_required
def shared_files():
    files_list = [f for f in File.query.order_by(File.uploaded_at.desc()).all() if current_user.id in f.shared_user_ids()]
    return render_template("files/shared_files.html", files=files_list)


@app.route("/logs")
@login_required
def logs():
    if current_user.role in {"admin", "auditor"}:
        records = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).all()
    else:
        records = ActivityLog.query.filter_by(user_id=current_user.id).order_by(ActivityLog.timestamp.desc()).all()
    return render_template("files/logs.html", logs=records)


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        current_user.username = request.form.get("username", current_user.username)
        if request.form.get("password"):
            current_user.password_hash = bcrypt.generate_password_hash(request.form["password"]).decode("utf-8")
        db.session.commit()
        log_activity("Updated profile")
        flash("Profile updated.", "success")
        return redirect(url_for("profile"))
    return render_template("files/profile.html")


@app.errorhandler(403)
def handle_403(_):
    return render_template("errors/access_denied.html"), 403


@app.errorhandler(404)
def handle_404(_):
    return render_template("errors/access_denied.html"), 404


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
