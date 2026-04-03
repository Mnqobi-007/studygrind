import os
from dotenv import load_dotenv
import sys

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # Database configuration
    DATABASE_URL = os.environ.get('DATABASE_URL')
    
    if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
        # Render uses postgres://, SQLAlchemy needs postgresql://
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
    
    if DATABASE_URL:
        # Use PostgreSQL (production)
        SQLALCHEMY_DATABASE_URI = DATABASE_URL
        print(f"📊 Using PostgreSQL database")
    else:
        # Use SQLite (local development)
        SQLALCHEMY_DATABASE_URI = 'sqlite:///database.db'
        print(f"📁 Using SQLite database (local development)")
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }
    
    # File uploads
    if os.environ.get('RENDER') or os.environ.get('RENDER_GIT_COMMIT'):
        # On Render, use /tmp for ephemeral storage
        UPLOAD_FOLDER = '/tmp/uploads'
        print(f"📁 Using /tmp/uploads for file storage (Render)")
    else:
        UPLOAD_FOLDER = 'uploads'
    
    MAX_CONTENT_LENGTH = 25 * 1024 * 1024
    
    # Google OAuth Configuration
    GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '')
    GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '')
    
    # App Domain
    APP_DOMAIN = os.environ.get('APP_DOMAIN', 'http://localhost:5000')
    
    # Session
    REMEMBER_COOKIE_DURATION = int(os.environ.get('REMEMBER_COOKIE_DURATION', 2592000))
    
    # Environment detection
    IS_PRODUCTION = bool(DATABASE_URL) or os.environ.get('RENDER')

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    
    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        
        # Production logging
        if not app.debug:
            import logging
            from logging import StreamHandler
            stream_handler = StreamHandler()
            stream_handler.setLevel(logging.INFO)
            app.logger.addHandler(stream_handler)
            app.logger.setLevel(logging.INFO)
            app.logger.info('StudyGrind startup on Render')

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
