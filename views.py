from flask import request, jsonify, send_from_directory
from models import User, Role, db, TokenBlocklist, Permission
from auth import (
    authenticate, generate_jwt_token, require_auth, require_permission,
    hash_password
)


def register():
    data = request.json
    email = data.get("email")
    password = data.get("password")
    password2 = data.get("password2")
    first_name = data.get("first_name")
    last_name = data.get("last_name")

    if password != password2:
        return jsonify({"error": "Passwords do not match"}), 400
    if not all([email, password, first_name, last_name]):
        return jsonify({"error": "Missing fields"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "User already exists"}), 409

    default_role = Role.query.filter_by(name="viewer").first()
    if not default_role:
        return jsonify({"error": "Default role not configured"}), 500

    user = User(
        email=email,
        password_hash=hash_password(password),
        first_name=first_name,
        last_name=last_name,
        role_id=default_role.id
    )
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User created", "user_id": user.id}), 201


def login():
    data = request.json
    email = data.get("email")
    password = data.get("password")
    user = authenticate(email, password)
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401
    token = generate_jwt_token(user.id)
    return jsonify({
        "access_token": token,
        "user": user.to_dict()
    })


@require_auth
def get_current_user(user_id, jti):
    user = User.query.get(user_id)
    if not user or not user.is_active:
        return jsonify({"error": "User not found"}), 404
    return jsonify(user.to_dict())


@require_auth
def update_profile(user_id, jti):
    user = User.query.get(user_id)
    if not user or not user.is_active:
        return jsonify({"error": "User not found"}), 404
    data = request.json
    if "first_name" in data:
        user.first_name = data["first_name"]
    if "last_name" in data:
        user.last_name = data["last_name"]
    db.session.commit()
    return jsonify(user.to_dict())


@require_auth
def delete_account(user_id, jti):
    user = User.query.get(user_id)
    if not user or not user.is_active:
        return jsonify({"error": "User not found"}), 404
    user.is_active = False
    db.session.commit()
    return jsonify({"message": "Account deactivated"})


@require_auth
def logout(user_id, jti):
    block_entry = TokenBlocklist(jti=jti)
    db.session.add(block_entry)
    db.session.commit()
    return jsonify({"message": "Successfully logged out"})


@require_permission("document", "read")
def get_documents(user_id, jti):
    return jsonify({"documents": ["Q3_Report.pdf", "Budget_2025.xlsx"]})


@require_permission("document", "write")
def create_document(user_id, jti):
    return jsonify({"message": "Document 'new_doc.txt' created"})


@require_permission("permission", "manage")
def assign_role(user_id, jti):
    data = request.json
    target_user_id = data.get("user_id")
    role_id = data.get("role_id")

    if not target_user_id or not role_id:
        return jsonify({"error": "Missing user_id or role_id"}), 400

    target_user = User.query.get(target_user_id)
    role = Role.query.get(role_id)

    if not target_user or not role:
        return jsonify({"error": "User or role not found"}), 404

    target_user.role_id = role.id
    db.session.commit()

    return jsonify({
        "success": True,
        "message": f"User {target_user.email} now has role: {role.name}"
    })


@require_permission("user", "read")
def list_users(user_id, jti):
    users = User.query.filter_by(is_active=True).all()
    return jsonify({"users": [u.to_dict() for u in users]})


@require_permission("permission", "manage")
def get_roles(user_id, jti):
    roles = Role.query.all()
    result = []
    for role in roles:
        result.append({
            "id": role.id,
            "name": role.name,
            "permissions": [
                {"id": p.id, "resource": p.resource, "action": p.action}
                for p in role.permissions
            ]
        })
    return jsonify({"roles": result})


@require_permission("permission", "manage")
def create_role(user_id, jti):
    data = request.json
    name = data.get("name")
    permission_ids = data.get("permission_ids", [])

    if not name:
        return jsonify({"error": "Role name is required"}), 400

    if Role.query.filter_by(name=name).first():
        return jsonify({"error": "Role with this name already exists"}), 409

    permissions = Permission.query.filter(Permission.id.in_(permission_ids)).all()
    if len(permissions) != len(permission_ids):
        return jsonify({"error": "One or more permission IDs are invalid"}), 400

    role = Role(name=name)
    role.permissions = permissions
    db.session.add(role)
    db.session.commit()

    return jsonify({
        "id": role.id,
        "name": role.name,
        "permissions": [{"id": p.id, "resource": p.resource, "action": p.action} for p in permissions]
    }), 201


@require_permission("permission", "manage")
def update_role(user_id, jti, role_id):
    role = Role.query.get(role_id)
    if not role:
        return jsonify({"error": "Role not found"}), 404

    data = request.json
    name = data.get("name")
    permission_ids = data.get("permission_ids")

    if name:
        if Role.query.filter(Role.name == name, Role.id != role_id).first():
            return jsonify({"error": "Role with this name already exists"}), 409
        role.name = name

    if permission_ids is not None:
        permissions = Permission.query.filter(Permission.id.in_(permission_ids)).all()
        if len(permissions) != len(permission_ids):
            return jsonify({"error": "One or more permission IDs are invalid"}), 400
        role.permissions = permissions

    db.session.commit()
    return jsonify({
        "id": role.id,
        "name": role.name,
        "permissions": [
            {"id": p.id, "resource": p.resource, "action": p.action}
            for p in role.permissions
        ]
    })


@require_permission("permission", "manage")
def delete_role(user_id, jti, role_id):
    role = Role.query.get(role_id)
    if not role:
        return jsonify({"error": "Role not found"}), 404

    user_with_role = User.query.filter_by(role_id=role_id, is_active=True).first()
    if user_with_role:
        return jsonify({"error": "Cannot delete role assigned to active users"}), 400

    db.session.delete(role)
    db.session.commit()
    return jsonify({"message": "Role deleted"})


@require_permission("permission", "manage")
def get_permissions(user_id, jti):
    permissions = Permission.query.all()
    return jsonify({
        "permissions": [
            {"id": p.id, "resource": p.resource, "action": p.action}
            for p in permissions
        ]
    })
