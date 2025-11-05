from datetime import datetime, timedelta
from models import TokenBlocklist, db


def cleanup_expired_tokens():
    JWT_EXPIRATION = 3600
    expiry_threshold = datetime.utcnow() - timedelta(seconds=JWT_EXPIRATION)

    deleted_count = db.session.query(TokenBlocklist).filter(
        TokenBlocklist.created_at < expiry_threshold
    ).delete()

    db.session.commit()
    return deleted_count