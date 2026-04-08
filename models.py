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
    workspace_memberships = db.relationship("WorkspaceMember", backref="user", lazy=True, cascade="all, delete-orphan")

    def get_id(self):
        return str(self.id)
    
    def get_workspaces(self):
        """Get all workspaces where user is a member"""
        memberships = WorkspaceMember.query.filter_by(user_id=self.id).all()
        return [m.workspace for m in memberships]
    
    def is_workspace_admin(self, workspace_id):
        """Check if user is admin of a specific workspace"""
        membership = WorkspaceMember.query.filter_by(
            user_id=self.id, 
            workspace_id=workspace_id,
            role="admin"
        ).first()
        return membership is not None


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
    workspace_id = db.Column(db.Integer, db.ForeignKey("workspace.id"), nullable=True)  # Workspace sharing
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
    
    def can_access(self, user_obj):
        """Check if user can access this file through workspace or direct sharing"""
        if user_obj.role == "admin":
            return True
        if self.owner_id == user_obj.id:
            return True
        if user_obj.id in self.shared_user_ids():
            return True
        if self.workspace_id:
            membership = WorkspaceMember.query.filter_by(
                user_id=user_obj.id,
                workspace_id=self.workspace_id
            ).first()
            if membership:
                return True
        return False


class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey("file.id"), nullable=True)
    ip_address = db.Column(db.String(50), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    status = db.Column(db.String(20), default="success", nullable=False)


class Workspace(db.Model):
    """Workspace for group collaboration"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    invite_code = db.Column(db.String(20), nullable=True, unique=True)
    
    owner = db.relationship("User", backref="owned_workspaces")
    members = db.relationship("WorkspaceMember", backref="workspace", lazy=True, cascade="all, delete-orphan")
    files = db.relationship("File", backref="workspace", lazy=True)
    
    def get_member_count(self):
        return len(self.members)
    
    def get_file_count(self):
        return len(self.files)
    
    def is_member(self, user_id):
        """Check if user is a member of this workspace"""
        return any(m.user_id == user_id for m in self.members)
    
    def is_admin(self, user_id):
        """Check if user is admin of this workspace"""
        membership = WorkspaceMember.query.filter_by(
            workspace_id=self.id,
            user_id=user_id,
            role="admin"
        ).first()
        return membership is not None


class WorkspaceMember(db.Model):
    """Membership linking users to workspaces"""
    id = db.Column(db.Integer, primary_key=True)
    workspace_id = db.Column(db.Integer, db.ForeignKey("workspace.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    role = db.Column(db.String(20), default="member", nullable=False)  # admin, member, viewer
    joined_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    __table_args__ = (
        db.UniqueConstraint('workspace_id', 'user_id', name='unique_workspace_member'),
    )


class WorkspaceInvite(db.Model):
    """Pending invites to workspaces"""
    id = db.Column(db.Integer, primary_key=True)
    workspace_id = db.Column(db.Integer, db.ForeignKey("workspace.id"), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    invited_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    workspace = db.relationship("Workspace", backref="invites")
    inviter = db.relationship("User", backref="sent_invites")
    
    __table_args__ = (
        db.UniqueConstraint('workspace_id', 'email', name='unique_workspace_invite'),
    )
