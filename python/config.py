"""
Configuration settings for the Phishing Detection Platform
"""

import os
from datetime import timedelta

class Config:
    """Application configuration"""
    
    # Flask configuration
    SECRET_KEY = os.getenv('SECRET_KEY', 'REDACTED')
    DEBUG = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    # Database configuration (PostgreSQL)
    DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://user:password@localhost:5432/phishing_detection')
    DATABASE_CONFIG = {
        'host': os.getenv('PGHOST', 'localhost'),
        'database': os.getenv('PGDATABASE', 'phishing_detection'),
        'user': os.getenv('PGUSER', 'postgres'),
        'password': os.getenv('PGPASSWORD', 'password'),
        'port': int(os.getenv('PGPORT', 5432))
    }
    
    # Redis configuration
    REDIS_CONFIG = {
        'host': os.getenv('REDIS_HOST', 'localhost'),
        'port': int(os.getenv('REDIS_PORT', 6379)),
        'db': int(os.getenv('REDIS_DB', 0)),
        'decode_responses': True
    }
    
    # File upload configuration
    UPLOAD_FOLDER = '../uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    ALLOWED_EXTENSIONS = {'eml', 'msg', 'txt', 'csv', 'xlsx', 'xls', 'json'}
    
    # Logging configuration
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = '../logs/app.log'
    
    # Security configuration
    BCRYPT_LOG_ROUNDS = 12
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'REDACTED')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    
    # API configuration
    API_HOST = '0.0.0.0'
    API_PORT = 8000
    API_PREFIX = '/api'
    
    # Machine Learning configuration
    ML_MODEL_PATH = '../models'
    ML_RETRAIN_INTERVAL = timedelta(days=7)
    
    # Threat detection configuration
    THREAT_SCORE_THRESHOLDS = {
        'LOW': 30,
        'MEDIUM': 50,
        'HIGH': 70
    }
    
    # Email analysis configuration
    MAX_EMAIL_SIZE = 10 * 1024 * 1024  # 10MB
    ANALYSIS_TIMEOUT = 60  # seconds
    
    # Report generation configuration
    REPORT_FORMATS = ['pdf', 'excel', 'csv']
    REPORT_STORAGE_PATH = '../reports'
    
    # Cache configuration
    CACHE_DEFAULT_TIMEOUT = 300  # 5 minutes
    CACHE_LONG_TIMEOUT = 3600    # 1 hour
    
    # Monitoring configuration
    HEALTH_CHECK_INTERVAL = 30  # seconds
    METRICS_RETENTION_DAYS = 30
    
    @staticmethod
    def init_app(app):
        """Initialize application with configuration"""
        # Create required directories
        directories = [
            Config.UPLOAD_FOLDER,
            '../logs',
            Config.ML_MODEL_PATH,
            Config.REPORT_STORAGE_PATH
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
