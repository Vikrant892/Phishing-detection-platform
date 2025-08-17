"""
Configuration Settings for Phishing Detection Platform
"""

import os
from datetime import timedelta

class Config:
    """Base configuration class"""
    
    # Flask Configuration
    SECRET_KEY = os.getenv('SECRET_KEY', 'REDACTED')
    DEBUG = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    TESTING = False
    
    # Database Configuration
    DATABASE_URL = os.getenv('DATABASE_URL', 'mysql://root:password@localhost/phishing_detector')
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # MySQL Specific Settings
    MYSQL_HOST = os.getenv('PGHOST', 'localhost')
    MYSQL_PORT = int(os.getenv('PGPORT', 3306))
    MYSQL_DATABASE = os.getenv('PGDATABASE', 'phishing_detector')
    MYSQL_USER = os.getenv('PGUSER', 'root')
    MYSQL_PASSWORD = os.getenv('PGPASSWORD', 'password')
    
    # File Upload Configuration
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB max file size
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
    TEMP_FOLDER = os.path.join(os.getcwd(), 'temp')
    EXPORTS_FOLDER = os.path.join(os.getcwd(), 'exports')
    
    # Supported file types
    ALLOWED_EXTENSIONS = {'.eml', '.msg', '.txt', '.mbox', '.zip', '.rar', '.7z'}
    
    # Email Analysis Configuration
    ANALYSIS_TIMEOUT = 300  # 5 minutes per email
    BATCH_PROCESSING_MAX_WORKERS = 4
    MAX_BATCH_SIZE = 100
    
    # Threat Detection Configuration
    DEFAULT_RISK_THRESHOLD = 40.0
    QUARANTINE_THRESHOLD = 80.0
    AUTO_QUARANTINE_ENABLED = True
    
    # Security Configuration
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', SECRET_KEY)
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    
    # API Rate Limiting
    RATELIMIT_STORAGE_URL = os.getenv('REDIS_URL', 'memory://')
    RATELIMIT_DEFAULT = "1000 per hour"
    
    # Logging Configuration
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = os.path.join(os.getcwd(), 'logs', 'phishing_detector.log')
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    LOG_MAX_BYTES = 10 * 1024 * 1024  # 10MB
    LOG_BACKUP_COUNT = 5
    
    # Cache Configuration
    CACHE_TYPE = "simple"
    CACHE_DEFAULT_TIMEOUT = 300  # 5 minutes
    
    # Background Task Configuration
    CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', 'memory://')
    CELERY_RESULT_BACKEND = os.getenv('CELERY_RESULT_BACKEND', 'cache+memory://')
    
    # Email Processing Configuration
    EMAIL_ENCODING_DETECTION = True
    EMAIL_CONTENT_MAX_SIZE = 50 * 1024 * 1024  # 50MB
    EMAIL_ATTACHMENT_MAX_SIZE = 25 * 1024 * 1024  # 25MB
    
    # Threat Pattern Configuration
    THREAT_PATTERNS_AUTO_UPDATE = True
    THREAT_PATTERNS_UPDATE_INTERVAL = 3600  # 1 hour
    
    # Machine Learning Configuration
    ML_MODEL_PATH = os.path.join(os.getcwd(), 'models')
    ML_FEATURE_EXTRACTION_ENABLED = True
    ML_PREDICTION_CONFIDENCE_THRESHOLD = 0.7
    
    # Export Configuration
    EXPORT_MAX_RECORDS = 10000
    EXPORT_FORMATS = ['json', 'csv', 'excel', 'pdf']
    EXPORT_RETENTION_DAYS = 7
    
    # Cleanup Configuration
    CLEANUP_INTERVAL = 86400  # 24 hours
    TEMP_FILE_RETENTION_HOURS = 24
    UPLOAD_FILE_RETENTION_DAYS = 30
    LOG_RETENTION_DAYS = 90
    
    # Performance Configuration
    MAX_CONCURRENT_ANALYSES = 10
    DATABASE_POOL_SIZE = 20
    DATABASE_POOL_RECYCLE = 3600
    
    # Monitoring Configuration
    METRICS_ENABLED = True
    HEALTH_CHECK_INTERVAL = 60  # 1 minute
    
    # Feature Flags
    FEATURES = {
        'batch_processing': True,
        'real_time_scanning': True,
        'ml_predictions': True,
        'auto_quarantine': True,
        'export_reports': True,
        'threat_intelligence': True,
        'sender_reputation': True,
        'ip_reputation': True,
        'url_analysis': True,
        'attachment_scanning': True,
        'social_engineering_detection': True,
        'phishing_detection': True,
        'malware_detection': True
    }

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False
    
    # Use SQLite for development
    SQLALCHEMY_DATABASE_URI = 'sqlite:///phishing_detector_dev.db'
    
    # Relaxed settings for development
    MAX_CONTENT_LENGTH = 200 * 1024 * 1024  # 200MB for dev
    ANALYSIS_TIMEOUT = 600  # 10 minutes for dev
    
    # Development logging
    LOG_LEVEL = 'DEBUG'
    
    # Development cache
    CACHE_TYPE = "simple"

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DEBUG = True
    
    # Use in-memory SQLite for testing
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    
    # Fast settings for testing
    ANALYSIS_TIMEOUT = 30
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=5)
    
    # Testing logging
    LOG_LEVEL = 'WARNING'
    
    # Disable external services in testing
    FEATURES = {
        'batch_processing': True,
        'real_time_scanning': False,
        'ml_predictions': False,
        'auto_quarantine': False,
        'export_reports': True,
        'threat_intelligence': False,
        'sender_reputation': True,
        'ip_reputation': False,
        'url_analysis': True,
        'attachment_scanning': True,
        'social_engineering_detection': True,
        'phishing_detection': True,
        'malware_detection': True
    }

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    
    # Production security
    SECRET_KEY = os.getenv('SECRET_KEY')
    if not SECRET_KEY:
        raise ValueError("SECRET_KEY environment variable must be set in production")
    
    # Production database
    DATABASE_URL = os.getenv('DATABASE_URL')
    if not DATABASE_URL:
        raise ValueError("DATABASE_URL environment variable must be set in production")
    
    # Production file limits
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB for production
    MAX_BATCH_SIZE = 50
    
    # Production timeouts
    ANALYSIS_TIMEOUT = 180  # 3 minutes
    
    # Production logging
    LOG_LEVEL = 'INFO'
    
    # Production cache with Redis
    CACHE_TYPE = "redis"
    CACHE_REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379')
    
    # Production rate limiting
    RATELIMIT_STORAGE_URL = os.getenv('REDIS_URL', 'redis://localhost:6379')
    RATELIMIT_DEFAULT = "500 per hour"
    
    # Production security headers
    SECURITY_HEADERS = {
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'"
    }

# Configuration mapping
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}

def get_config():
    """Get configuration based on environment"""
    env = os.getenv('FLASK_ENV', 'development')
    return config.get(env, config['default'])

# Threat Detection Patterns
THREAT_PATTERNS = {
    'phishing_keywords': [
        'verify your account', 'click here to update', 'suspend your account',
        'urgent action required', 'confirm your identity', 'security alert',
        'account verification', 'update payment method', 'expire soon',
        'immediate response required', 'validate your information'
    ],
    
    'social_engineering': [
        'congratulations you have won', 'limited time offer', 'act now',
        'claim your prize', 'exclusive deal', 'urgent response',
        'you have been selected', 'free gift', 'special promotion',
        'don\'t miss out', 'incredible opportunity'
    ],
    
    'urgency_indicators': [
        'urgent', 'immediate', 'asap', 'expire', 'deadline',
        'limited time', 'act now', 'hurry', 'quick', 'fast'
    ],
    
    'financial_terms': [
        'bank account', 'credit card', 'payment', 'transfer money',
        'wire transfer', 'refund', 'billing', 'invoice',
        'tax refund', 'financial', 'money', 'cash'
    ],
    
    'suspicious_domains': [
        r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',  # IP addresses
        r'[a-z0-9-]+\.tk\b', r'[a-z0-9-]+\.ml\b', r'[a-z0-9-]+\.ga\b',
        r'[a-z0-9-]+\.cf\b', r'bit\.ly', r'tinyurl\.com', r't\.co'
    ],
    
    'attachment_threats': [
        '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs',
        '.js', '.jar', '.zip', '.rar', '.7z'
    ]
}

# Security Configuration
SECURITY_CONFIG = {
    'max_login_attempts': 5,
    'login_lockout_duration': 900,  # 15 minutes
    'session_timeout': 3600,  # 1 hour
    'password_min_length': 8,
    'require_https': True,
    'secure_cookies': True,
    'csrf_protection': True,
    'xss_protection': True
}

# Email Analysis Weights
ANALYSIS_WEIGHTS = {
    'header_analysis': 0.25,
    'content_analysis': 0.35,
    'attachment_analysis': 0.20,
    'url_analysis': 0.15,
    'reputation_analysis': 0.05
}

# Risk Score Thresholds
RISK_THRESHOLDS = {
    'minimal': (0, 20),
    'low': (20, 40),
    'medium': (40, 60),
    'high': (60, 80),
    'critical': (80, 100)
}
