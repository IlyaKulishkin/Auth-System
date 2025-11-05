from models import db, User, Role, Permission
from auth import hash_password


def init_db(app):
    with app.app_context():
        db.create_all()

        if User.query.filter_by(email="admin@example.com").first():
            return

        admin_role = Role(name="admin")
        editor_role = Role(name="editor")
        viewer_role = Role(name="viewer")
        db.session.add_all([admin_role, editor_role, viewer_role])
        db.session.commit()

        perms = [
            Permission(resource="document", action="read"),
            Permission(resource="document", action="write"),
            Permission(resource="document", action="delete"),
            Permission(resource="user", action="read"),
            Permission(resource="user", action="write"),
            Permission(resource="user", action="delete"),
            Permission(resource="permission", action="manage"),
        ]
        db.session.add_all(perms)
        db.session.commit()

        admin_role.permissions = perms
        editor_role.permissions = [
            p for p in perms if (p.resource == "document" and p.action in ("read", "write"))
            or (p.resource == "user" and p.action in ("read", "write"))
        ]
        viewer_role.permissions = [p for p in perms if p.action == "read"]
        db.session.commit()

        admin = User(
            email="admin@example.com",
            password_hash=hash_password("admin123"),
            first_name="Admin",
            last_name="User",
            role_id=admin_role.id
        )
        editor = User(
            email="editor@example.com",
            password_hash=hash_password("editor123"),
            first_name="Editor",
            last_name="User",
            role_id=editor_role.id
        )
        db.session.add_all([admin, editor])
        db.session.commit()
        print("Тестовые данные созданы")