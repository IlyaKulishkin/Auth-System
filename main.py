from flask import Flask
from config import Config
from models import db
from auth import init_auth
from init_db import init_db as init_database
from views import (
    register, login, get_current_user, update_profile, delete_account,
    get_documents, create_document, assign_role, list_users, send_from_directory, logout, get_roles, create_role,
    update_role, delete_role, get_permissions
)


def create_app():
    app = Flask(__name__, static_folder='static')
    app.config.from_object(Config)

    db.init_app(app)
    init_auth(app)
    init_database(app)

    app.add_url_rule("/register", "register", register, methods=["POST"])
    app.add_url_rule("/login", "login", login, methods=["POST"])
    app.add_url_rule("/me", "me", get_current_user, methods=["GET"])
    app.add_url_rule("/profile", "update_profile", update_profile, methods=["PUT"])
    app.add_url_rule("/delete-account", "delete_account", delete_account, methods=["POST"])
    app.add_url_rule("/documents", "get_documents", get_documents, methods=["GET"])
    app.add_url_rule("/documents", "create_document", create_document, methods=["POST"])
    app.add_url_rule("/admin/assign-role", "assign_role", assign_role, methods=["POST"])
    app.add_url_rule("/admin/users", "list_users", list_users, methods=["GET"])
    app.add_url_rule("/", "index", lambda: send_from_directory('static', 'index.html'), methods=["GET"])
    app.add_url_rule("/logout", "logout", logout, methods=["POST"])
    app.add_url_rule("/admin/roles", "get_roles", get_roles, methods=["GET"])
    app.add_url_rule("/admin/roles", "create_role", create_role, methods=["POST"])
    app.add_url_rule("/admin/roles/<int:role_id>", "update_role", update_role, methods=["PUT"])
    app.add_url_rule("/admin/roles/<int:role_id>", "delete_role", delete_role, methods=["DELETE"])
    app.add_url_rule("/admin/permissions", "get_permissions", get_permissions, methods=["GET"])

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=True)
