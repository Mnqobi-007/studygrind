import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # Database - Use PostgreSQL on Render, SQLite locally
    if os.environ.get('RENDER', 'false').lower() == 'true' or os.environ.get('DATABASE_URL'):
        # On Render, use PostgreSQL
        DATABASE_URL = os.environ.get('DATABASE_URL')
        if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
            # Render uses postgres://, SQLAlchemy 1.4+ needs postgresql://
            DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
        SQLALCHEMY_DATABASE_URI = DATABASE_URL or 'postgresql://localhost/studygrind'
    else:
        # Local development with SQLite
        SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///database.db')
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'pool_size': 10,
        'max_overflow': 20
    }
    
    # File uploads - Use /tmp for Render (ephemeral storage)
    UPLOAD_FOLDER = '/tmp/uploads' if os.environ.get('RENDER') else 'uploads'
    MAX_CONTENT_LENGTH = 25 * 1024 * 1024
    
    # Google OAuth Configuration
    GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '')
    GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '')
    
    # App Domain
    APP_DOMAIN = os.environ.get('APP_DOMAIN', 'http://localhost:5000')
    
    # Session
    REMEMBER_COOKIE_DURATION = int(os.environ.get('REMEMBER_COOKIE_DURATION', 2592000))
    
    # Render specific
    RENDER = os.environ.get('RENDER', 'false').lower() == 'true'

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
