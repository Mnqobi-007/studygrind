import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # Database - Use Supabase PostgreSQL on Vercel
    if os.environ.get('VERCEL', 'false').lower() == 'true':
        # On Vercel, use Supabase PostgreSQL
        DATABASE_URL = os.environ.get('DATABASE_URL')
        if not DATABASE_URL:
            raise ValueError("DATABASE_URL is required for Vercel deployment")
        SQLALCHEMY_DATABASE_URI = DATABASE_URL
    else:
        # Local development with SQLite
        SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///database.db')
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'pool_size': 5,
        'max_overflow': 10
    }
    
    # Supabase Storage (for file uploads)
    SUPABASE_URL = os.environ.get('SUPABASE_URL', '')
    SUPABASE_KEY = os.environ.get('SUPABASE_KEY', '')
    SUPABASE_BUCKET = os.environ.get('SUPABASE_BUCKET', 'studygrind')
    
    # File uploads - Use /tmp for Vercel, local for development
    if os.environ.get('VERCEL', 'false').lower() == 'true':
        UPLOAD_FOLDER = '/tmp/uploads'
    else:
        UPLOAD_FOLDER = 'uploads'
    
    MAX_CONTENT_LENGTH = 25 * 1024 * 1024
    
    # Google OAuth Configuration
    GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '')
    GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '')
    
    # App Domain (for OAuth redirects)
    APP_DOMAIN = os.environ.get('APP_DOMAIN', 'http://localhost:5000')
    
    # Session
    REMEMBER_COOKIE_DURATION = int(os.environ.get('REMEMBER_COOKIE_DURATION', 2592000))
    
    # Vercel specific
    VERCEL = os.environ.get('VERCEL', 'false').lower() == 'true'

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
            app.logger.info('StudyGrind startup on Vercel with Supabase')

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
