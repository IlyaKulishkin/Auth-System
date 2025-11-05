from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


role_permissions = db.Table(
    'role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permission.id'), primary_key=True)
)


class Role(db.Model):
    __tablename__ = 'role'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    permissions = db.relationship('Permission', secondary=role_permissions, back_populates='roles')
    users = db.relationship('User', back_populates='role')

    def __repr__(self):
        return f"<Role {self.name}>"


class Permission(db.Model):
    __tablename__ = 'permission'
    id = db.Column(db.Integer, primary_key=True)
    resource = db.Column(db.String(50), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    roles = db.relationship('Role', secondary=role_permissions, back_populates='permissions')

    def matches(self, resource: str, action: str) -> bool:
        return self.resource == resource and self.action == action


class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    role = db.relationship('Role', back_populates='users')

    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "role": self.role.name if self.role else None
        }


class TokenBlocklist(db.Model):
    __tablename__ = 'token_blocklist'
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)