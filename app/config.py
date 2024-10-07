"""configuration for the flask server"""

import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base config."""

    SECRET_KEY = os.environ.get("SECRET_KEY")
    SESSION_COOKIE_NAME = os.environ.get("SESSION_COOKIE_NAME")


class ProdConfig(Config):
    ENV = "production"
    DEBUG = False
    TESTING = False


class DevConfig(Config):
    ENV = "development"
    DEBUG = True
    TESTING = True
