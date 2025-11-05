# auth.py
import jwt
import bcrypt
import uuid
from functools import wraps
from datetime import datetime, timedelta, timezone
from flask import request, jsonify
from models import User, TokenBlocklist, db

JWT_SECRET = "super-secret-jwt-key"
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION = 3600


def init_auth(app):
    pass


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))


def authenticate(email: str, password: str):
    user = User.query.filter_by(email=email, is_active=True).first()
    if user and verify_password(password, user.password_hash):
        return user
    return None


def generate_jwt_token(user_id: int) -> str:
    payload = {
        "user_id": user_id,
        "jti": str(uuid.uuid4()),
        "exp": datetime.now(timezone.utc) + timedelta(seconds=JWT_EXPIRATION)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def is_token_revoked(jti: str) -> bool:
    return TokenBlocklist.query.filter_by(jti=jti).first() is not None


def verify_jwt_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        jti = payload.get("jti")
        user_id = payload.get("user_id")
        if not jti or not user_id:
            return None
        if is_token_revoked(jti):
            return None
        return user_id, jti
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


def get_current_user_id():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None, None
    token = auth_header.split(" ")[1]
    result = verify_jwt_token(token)
    return result if result else (None, None)


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user_id, jti = get_current_user_id()
        if user_id is None:
            return jsonify({"error": "Unauthorized"}), 401
        return f(user_id, jti, *args, **kwargs)

    return decorated


def require_permission(resource: str, action: str):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user_id, jti = get_current_user_id()
            if user_id is None:
                return jsonify({"error": "Unauthorized"}), 401

            user = User.query.get(user_id)
            if not user or not user.is_active:
                return jsonify({"error": "Unauthorized"}), 401

            has_perm = False
            if user.role:
                for perm in user.role.permissions:
                    if perm.matches(resource, action):
                        has_perm = True
                        break

            if not has_perm:
                return jsonify({"error": "Forbidden"}), 403

            return f(user_id, jti, *args, **kwargs)

        return decorated

    return decorator
