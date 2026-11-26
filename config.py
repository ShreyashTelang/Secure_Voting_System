"""
SecureVote Configuration Module.
"""
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "securevote-enterprise-production-key-2026")
    DATABASE = os.path.join(INSTANCE_DIR, "securevote.db")
    DEBUG = False
    TESTING = False

class DevelopmentConfig(Config):
    DEBUG = True

class TestingConfig(Config):
    TESTING = True
    DATABASE = os.path.join(INSTANCE_DIR, "test_securevote.db")
