import os


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "super-secret-jwt-key-for-demo-only")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///auth_demo.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False