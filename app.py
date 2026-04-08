import os
import secrets
from datetime import datetime

from flask import Flask, flash, redirect, render_template, request, send_file, url_for
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, current_user, login_required, login_user, logout_user

from config import Config
from models import ActivityLog, File, User, Workspace, WorkspaceMember, WorkspaceInvite, db
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
    if current_user.id in file_obj.shared_user_ids():
        return True
    if file_obj.workspace_id:
        membership = WorkspaceMember.query.filter_by(
            user_id=current_user.id,
            workspace_id=file_obj.workspace_id
        ).first()
        if membership:
            return True
    return False


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


@login_required
@app.route("/logout")
def logout():
    log_activity("Logged out")
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for("index"))


@login_required
@role_required("admin")
@app.route("/admin/dashboard")
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


@login_required
@role_required("admin")
@app.route("/admin/user/block/<int:user_id>", methods=["POST"])
def admin_block_user(user_id):
    target = db.session.get(User, user_id)
    if not target or target.id == current_user.id:
        return redirect(url_for("admin_dashboard"))

    target.is_active = not target.is_active
    db.session.commit()
    log_activity("Blocked user" if not target.is_active else "Unblocked user")
    flash("User status updated.", "success")
    return redirect(url_for("admin_dashboard"))


@login_required
@role_required("admin")
@app.route("/admin/user/delete/<int:user_id>", methods=["POST"])
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


@login_required
@role_required("user")
@app.route("/user/dashboard")
def user_dashboard():
    user_files = File.query.filter_by(owner_id=current_user.id).order_by(File.uploaded_at.desc()).all()
    shared_files = [f for f in File.query.order_by(File.uploaded_at.desc()).all() if current_user.id in f.shared_user_ids()]
    logs = ActivityLog.query.filter_by(user_id=current_user.id).order_by(ActivityLog.timestamp.desc()).limit(8).all()
    storage = sum(f.file_size or 0 for f in user_files)
    
    # Get user's workspaces
    workspaces = current_user.get_workspaces()
    
    return render_template(
        "dashboard/user_dashboard.html",
        user_files=user_files,
        shared_files=shared_files,
        logs=logs,
        storage=storage,
        workspaces=workspaces,
    )


@login_required
@role_required("auditor")
@app.route("/auditor/dashboard")
def auditor_dashboard():
    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(50).all()
    all_files = File.query.order_by(File.uploaded_at.desc()).all()
    failed_logins = ActivityLog.query.filter_by(action="Failed login").count()
    return render_template(
        "dashboard/auditor_dashboard.html", logs=logs, all_files=all_files, failed_logins=failed_logins
    )


# ==================== WORKSPACE ROUTES ====================

@login_required
@app.route("/workspaces")
def workspaces():
    """List all workspaces user is a member of"""
    my_workspaces = current_user.get_workspaces()
    # Also show workspaces where user has pending invites
    pending_invites = WorkspaceInvite.query.filter_by(email=current_user.email).all()
    return render_template("workspaces/workspaces.html", 
                         workspaces=my_workspaces, 
                         pending_invites=pending_invites)


@login_required
@role_required("user", "admin")
@app.route("/workspaces/create", methods=["GET", "POST"])
def create_workspace():
    """Create a new workspace"""
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        
        if not name:
            flash("Workspace name is required.", "danger")
            return redirect(url_for("create_workspace"))
        
        # Generate unique invite code
        invite_code = secrets.token_urlsafe(8)
        while Workspace.query.filter_by(invite_code=invite_code).first():
            invite_code = secrets.token_urlsafe(8)
        
        workspace = Workspace(
            name=name,
            description=description,
            owner_id=current_user.id,
            invite_code=invite_code
        )
        db.session.add(workspace)
        db.session.commit()
        
        # Add creator as admin member
        membership = WorkspaceMember(
            workspace_id=workspace.id,
            user_id=current_user.id,
            role="admin"
        )
        db.session.add(membership)
        db.session.commit()
        
        log_activity(f"Created workspace: {name}")
        flash(f"Workspace '{name}' created successfully!", "success")
        return redirect(url_for("workspaces"))
    
    return render_template("workspaces/create_workspace.html")


@login_required
@app.route("/workspaces/<int:workspace_id>")
def view_workspace(workspace_id):
    """View workspace details and files"""
    workspace = db.session.get(Workspace, workspace_id)
    if not workspace:
        flash("Workspace not found.", "warning")
        return redirect(url_for("workspaces"))
    
    # Check if user is member
    if not workspace.is_member(current_user.id):
        flash("You are not a member of this workspace.", "danger")
        return redirect(url_for("workspaces"))
    
    # Get workspace files
    workspace_files = File.query.filter_by(workspace_id=workspace_id).order_by(File.uploaded_at.desc()).all()
    
    # Get members
    members = WorkspaceMember.query.filter_by(workspace_id=workspace_id).all()
    
    # Get pending invites
    invites = WorkspaceInvite.query.filter_by(workspace_id=workspace_id).all()
    
    return render_template("workspaces/workspace_detail.html", 
                         workspace=workspace, 
                         files=workspace_files,
                         members=members,
                         invites=invites,
                         is_admin=workspace.is_admin(current_user.id))


@login_required
@app.route("/workspaces/<int:workspace_id>/invite", methods=["POST"])
def invite_to_workspace(workspace_id):
    """Invite a user to workspace by email"""
    workspace = db.session.get(Workspace, workspace_id)
    if not workspace:
        flash("Workspace not found.", "warning")
        return redirect(url_for("workspaces"))
    
    if not workspace.is_admin(current_user.id):
        flash("Only workspace admins can invite members.", "danger")
        return redirect(url_for("view_workspace", workspace_id=workspace_id))
    
    email = request.form.get("email", "").strip().lower()
    if not email:
        flash("Email is required.", "danger")
        return redirect(url_for("view_workspace", workspace_id=workspace_id))
    
    # Check if user exists
    target_user = User.query.filter_by(email=email).first()
    
    # Check if already a member
    if target_user and workspace.is_member(target_user.id):
        flash(f"{email} is already a member.", "warning")
        return redirect(url_for("view_workspace", workspace_id=workspace_id))
    
    # Check if invite already exists
    existing_invite = WorkspaceInvite.query.filter_by(workspace_id=workspace_id, email=email).first()
    if existing_invite:
        flash(f"Invite already sent to {email}.", "info")
        return redirect(url_for("view_workspace", workspace_id=workspace_id))
    
    invite = WorkspaceInvite(
        workspace_id=workspace_id,
        email=email,
        invited_by=current_user.id
    )
    db.session.add(invite)
    db.session.commit()
    
    log_activity(f"Invited {email} to workspace {workspace.name}")
    flash(f"Invite sent to {email}.", "success")
    return redirect(url_for("view_workspace", workspace_id=workspace_id))


@login_required
@app.route("/workspaces/invite/<int:invite_id>/accept")
def accept_workspace_invite(invite_id):
    """Accept a workspace invitation"""
    invite = db.session.get(WorkspaceInvite, invite_id)
    if not invite:
        flash("Invite not found.", "warning")
        return redirect(url_for("workspaces"))
    
    if invite.email.lower() != current_user.email.lower():
        flash("This invite is not for you.", "danger")
        return redirect(url_for("workspaces"))
    
    # Add user as member
    membership = WorkspaceMember(
        workspace_id=invite.workspace_id,
        user_id=current_user.id,
        role="member"
    )
    db.session.add(membership)
    db.session.delete(invite)
    db.session.commit()
    
    workspace = db.session.get(Workspace, invite.workspace_id)
    log_activity(f"Joined workspace: {workspace.name}")
    flash(f"You've joined {workspace.name}!", "success")
    return redirect(url_for("view_workspace", workspace_id=invite.workspace_id))


@login_required
@app.route("/workspaces/invite/<int:invite_id>/decline")
def decline_workspace_invite(invite_id):
    """Decline a workspace invitation"""
    invite = db.session.get(WorkspaceInvite, invite_id)
    if not invite:
        flash("Invite not found.", "warning")
        return redirect(url_for("workspaces"))
    
    if invite.email.lower() != current_user.email.lower():
        flash("This invite is not for you.", "danger")
        return redirect(url_for("workspaces"))
    
    workspace = db.session.get(Workspace, invite.workspace_id)
    db.session.delete(invite)
    db.session.commit()
    
    flash(f"Declined invite to {workspace.name}.", "info")
    return redirect(url_for("workspaces"))


@login_required
@app.route("/workspaces/<int:workspace_id>/join/<invite_code>")
def join_workspace_by_code(workspace_id, invite_code):
    """Join a workspace using invite code"""
    workspace = db.session.get(Workspace, workspace_id)
    if not workspace:
        flash("Workspace not found.", "warning")
        return redirect(url_for("workspaces"))
    
    if workspace.invite_code != invite_code:
        flash("Invalid invite code.", "danger")
        return redirect(url_for("workspaces"))
    
    if workspace.is_member(current_user.id):
        flash("You are already a member.", "info")
        return redirect(url_for("view_workspace", workspace_id=workspace_id))
    
    membership = WorkspaceMember(
        workspace_id=workspace_id,
        user_id=current_user.id,
        role="member"
    )
    db.session.add(membership)
    db.session.commit()
    
    log_activity(f"Joined workspace: {workspace.name}")
    flash(f"You've joined {workspace.name}!", "success")
    return redirect(url_for("view_workspace", workspace_id=workspace_id))


@login_required
@app.route("/workspaces/<int:workspace_id>/member/<int:member_id>/remove", methods=["POST"])
def remove_workspace_member(workspace_id, member_id):
    """Remove a member from workspace"""
    workspace = db.session.get(Workspace, workspace_id)
    if not workspace:
        flash("Workspace not found.", "warning")
        return redirect(url_for("workspaces"))
    
    if not workspace.is_admin(current_user.id):
        flash("Only workspace admins can remove members.", "danger")
        return redirect(url_for("view_workspace", workspace_id=workspace_id))
    
    # Can't remove yourself if you're the only admin
    if member_id == current_user.id:
        admin_count = WorkspaceMember.query.filter_by(workspace_id=workspace_id, role="admin").count()
        if admin_count <= 1:
            flash("Cannot remove yourself. You are the only admin.", "danger")
            return redirect(url_for("view_workspace", workspace_id=workspace_id))
    
    # Can't remove the owner
    if member_id == workspace.owner_id:
        flash("Cannot remove the workspace owner.", "danger")
        return redirect(url_for("view_workspace", workspace_id=workspace_id))
    
    membership = WorkspaceMember.query.filter_by(workspace_id=workspace_id, user_id=member_id).first()
    if membership:
        member = db.session.get(User, member_id)
        db.session.delete(membership)
        db.session.commit()
        log_activity(f"Removed {member.username} from workspace {workspace.name}")
        flash(f"Removed {member.username} from workspace.", "success")
    
    return redirect(url_for("view_workspace", workspace_id=workspace_id))


@login_required
@app.route("/workspaces/<int:workspace_id>/member/<int:member_id>/promote", methods=["POST"])
def promote_workspace_member(workspace_id, member_id):
    """Promote a member to admin"""
    workspace = db.session.get(Workspace, workspace_id)
    if not workspace:
        flash("Workspace not found.", "warning")
        return redirect(url_for("workspaces"))
    
    if not workspace.is_admin(current_user.id):
        flash("Only workspace admins can promote members.", "danger")
        return redirect(url_for("view_workspace", workspace_id=workspace_id))
    
    membership = WorkspaceMember.query.filter_by(workspace_id=workspace_id, user_id=member_id).first()
    if membership:
        member = db.session.get(User, member_id)
        membership.role = "admin"
        db.session.commit()
        log_activity(f"Promoted {member.username} to admin in {workspace.name}")
        flash(f"Promoted {member.username} to admin.", "success")
    
    return redirect(url_for("view_workspace", workspace_id=workspace_id))


@login_required
@app.route("/workspaces/<int:workspace_id>/member/<int:member_id>/demote", methods=["POST"])
def demote_workspace_admin(workspace_id, member_id):
    """Demote an admin to member"""
    workspace = db.session.get(Workspace, workspace_id)
    if not workspace:
        flash("Workspace not found.", "warning")
        return redirect(url_for("workspaces"))
    
    if not workspace.is_admin(current_user.id):
        flash("Only workspace admins can demote members.", "danger")
        return redirect(url_for("view_workspace", workspace_id=workspace_id))
    
    if member_id == current_user.id:
        flash("Cannot demote yourself.", "danger")
        return redirect(url_for("view_workspace", workspace_id=workspace_id))
    
    membership = WorkspaceMember.query.filter_by(workspace_id=workspace_id, user_id=member_id).first()
    if membership:
        member = db.session.get(User, member_id)
        membership.role = "member"
        db.session.commit()
        log_activity(f"Demoted {member.username} to member in {workspace.name}")
        flash(f"Demoted {member.username} to member.", "success")
    
    return redirect(url_for("view_workspace", workspace_id=workspace_id))


@login_required
@app.route("/workspaces/<int:workspace_id>/delete", methods=["POST"])
def delete_workspace(workspace_id):
    """Delete a workspace (owner only)"""
    workspace = db.session.get(Workspace, workspace_id)
    if not workspace:
        flash("Workspace not found.", "warning")
        return redirect(url_for("workspaces"))
    
    if workspace.owner_id != current_user.id and current_user.role != "admin":
        flash("Only the owner can delete the workspace.", "danger")
        return redirect(url_for("view_workspace", workspace_id=workspace_id))
    
    workspace_name = workspace.name
    db.session.delete(workspace)
    db.session.commit()
    
    log_activity(f"Deleted workspace: {workspace_name}")
    flash(f"Workspace '{workspace_name}' deleted.", "info")
    return redirect(url_for("workspaces"))


@login_required
@app.route("/workspaces/<int:workspace_id>/leave", methods=["POST"])
def leave_workspace(workspace_id):
    """Leave a workspace"""
    workspace = db.session.get(Workspace, workspace_id)
    if not workspace:
        flash("Workspace not found.", "warning")
        return redirect(url_for("workspaces"))
    
    if workspace.owner_id == current_user.id:
        flash("Owner cannot leave. Transfer ownership or delete the workspace.", "danger")
        return redirect(url_for("view_workspace", workspace_id=workspace_id))
    
    membership = WorkspaceMember.query.filter_by(workspace_id=workspace_id, user_id=current_user.id).first()
    if membership:
        db.session.delete(membership)
        db.session.commit()
        log_activity(f"Left workspace: {workspace.name}")
        flash(f"You've left {workspace.name}.", "info")
    
    return redirect(url_for("workspaces"))


# ==================== FILE ROUTES ====================

@login_required
@app.route("/files")
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


@login_required
@role_required("user", "admin")
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        file = request.files.get("file")
        if not file or not file.filename:
            flash("Please select a file.", "warning")
            return redirect(url_for("upload"))

        filename, original, path = save_uploaded_file(file, app.config["UPLOAD_FOLDER"])
        
        # Check if uploading to a workspace
        workspace_id = request.form.get("workspace_id")
        if workspace_id:
            ws = db.session.get(Workspace, int(workspace_id))
            if not ws or not ws.is_member(current_user.id):
                flash("Invalid workspace.", "danger")
                return redirect(url_for("upload"))
        
        file_record = File(
            filename=filename,
            original_filename=original,
            file_size=os.path.getsize(path),
            file_type=file.content_type,
            decrypted_path=path,
            owner_id=current_user.id,
            encryption_status="raw",
            uploaded_at=datetime.utcnow(),
            workspace_id=int(workspace_id) if workspace_id else None,
        )
        file_record.file_hash = sha256_file(path)
        db.session.add(file_record)
        db.session.commit()
        log_activity("Uploaded file", file_record.id)
        
        if workspace_id:
            flash("File uploaded to workspace.", "success")
        else:
            flash("File uploaded.", "success")
        return redirect(url_for("files"))
    
    # Get user's workspaces for dropdown
    workspaces = current_user.get_workspaces()
    return render_template("files/upload.html", workspaces=workspaces)


@login_required
@role_required("user", "admin")
@app.route("/encrypt/<int:file_id>")
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


@login_required
@role_required("user", "admin")
@app.route("/decrypt/<int:file_id>")
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


@login_required
@app.route("/download/<int:file_id>")
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


@login_required
@app.route("/delete/<int:file_id>")
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


@login_required
@role_required("user", "admin")
@app.route("/share/<int:file_id>", methods=["POST"])
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


@login_required
@app.route("/files/shared")
def shared_files():
    files_list = [f for f in File.query.order_by(File.uploaded_at.desc()).all() if current_user.id in f.shared_user_ids()]
    return render_template("files/shared_files.html", files=files_list)


@login_required
@app.route("/logs")
def logs():
    if current_user.role in {"admin", "auditor"}:
        records = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).all()
    else:
        records = ActivityLog.query.filter_by(user_id=current_user.id).order_by(ActivityLog.timestamp.desc()).all()
    return render_template("files/logs.html", logs=records)


@login_required
@app.route("/profile", methods=["GET", "POST"])
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
