"""
Logger utility for consistent logging across the application
"""

import logging
import os
from datetime import datetime
from logging.handlers import RotatingFileHandler
import sys

def setup_logger(name: str = None, level: str = 'INFO') -> logging.Logger:
    """Setup and configure logger with file and console handlers"""
    
    logger_name = name or __name__
    logger = logging.getLogger(logger_name)
    
    # Prevent duplicate handlers
    if logger.handlers:
        return logger
    
    # Set log level
    log_levels = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL
    }
    
    logger.setLevel(log_levels.get(level.upper(), logging.INFO))
    
    # Create logs directory if it doesn't exist
    logs_dir = 'logs'
    os.makedirs(logs_dir, exist_ok=True)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler with rotation
    log_filename = os.path.join(logs_dir, 'phishing_detector.log')
    file_handler = RotatingFileHandler(
        log_filename,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # Error file handler
    error_log_filename = os.path.join(logs_dir, 'errors.log')
    error_handler = RotatingFileHandler(
        error_log_filename,
        maxBytes=5 * 1024 * 1024,  # 5MB
        backupCount=3
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(formatter)
    logger.addHandler(error_handler)
    
    return logger

def get_logger(name: str = None) -> logging.Logger:
    """Get logger instance"""
    return setup_logger(name)

class SecurityLogger:
    """Security-focused logger for threat detection events"""
    
    def __init__(self):
        self.logger = setup_logger('security')
        
        # Create security log file
        logs_dir = 'logs'
        security_log = os.path.join(logs_dir, 'security.log')
        
        security_handler = RotatingFileHandler(
            security_log,
            maxBytes=20 * 1024 * 1024,  # 20MB
            backupCount=10
        )
        
        security_formatter = logging.Formatter(
            '%(asctime)s - SECURITY - %(levelname)s - %(message)s'
        )
        
        security_handler.setFormatter(security_formatter)
        self.logger.addHandler(security_handler)
    
    def log_threat_detected(self, email_id: str, threat_type: str, severity: str, details: dict):
        """Log threat detection event"""
        message = f"THREAT_DETECTED - Email: {email_id}, Type: {threat_type}, Severity: {severity}, Details: {details}"
        self.logger.warning(message)
    
    def log_email_analyzed(self, email_id: str, risk_level: str, threat_score: int):
        """Log email analysis completion"""
        message = f"EMAIL_ANALYZED - Email: {email_id}, Risk: {risk_level}, Score: {threat_score}"
        self.logger.info(message)
    
    def log_quarantine_action(self, email_id: str, action: str, reason: str, user: str):
        """Log quarantine action"""
        message = f"QUARANTINE_{action.upper()} - Email: {email_id}, Reason: {reason}, User: {user}"
        self.logger.warning(message)
    
    def log_rule_applied(self, rule_name: str, email_id: str, matched: bool):
        """Log rule application"""
        status = "MATCHED" if matched else "NO_MATCH"
        message = f"RULE_APPLIED - Rule: {rule_name}, Email: {email_id}, Status: {status}"
        self.logger.debug(message)
    
    def log_system_event(self, event_type: str, message: str, level: str = 'INFO'):
        """Log system event"""
        log_message = f"SYSTEM_{event_type.upper()} - {message}"
        
        if level.upper() == 'ERROR':
            self.logger.error(log_message)
        elif level.upper() == 'WARNING':
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)

class PerformanceLogger:
    """Performance monitoring logger"""
    
    def __init__(self):
        self.logger = setup_logger('performance')
        
        # Create performance log file
        logs_dir = 'logs'
        perf_log = os.path.join(logs_dir, 'performance.log')
        
        perf_handler = RotatingFileHandler(
            perf_log,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
        
        perf_formatter = logging.Formatter(
            '%(asctime)s - PERFORMANCE - %(message)s'
        )
        
        perf_handler.setFormatter(perf_formatter)
        self.logger.addHandler(perf_handler)
    
    def log_analysis_time(self, email_id: str, duration: float, file_size: int):
        """Log email analysis performance"""
        message = f"ANALYSIS_TIME - Email: {email_id}, Duration: {duration:.3f}s, Size: {file_size} bytes"
        self.logger.info(message)
    
    def log_database_query(self, query_type: str, duration: float, record_count: int = None):
        """Log database query performance"""
        records = f", Records: {record_count}" if record_count is not None else ""
        message = f"DB_QUERY - Type: {query_type}, Duration: {duration:.3f}s{records}"
        self.logger.debug(message)
    
    def log_api_request(self, endpoint: str, method: str, duration: float, status_code: int):
        """Log API request performance"""
        message = f"API_REQUEST - {method} {endpoint}, Duration: {duration:.3f}s, Status: {status_code}"
        self.logger.info(message)

class AuditLogger:
    """Audit logger for compliance and tracking"""
    
    def __init__(self):
        self.logger = setup_logger('audit')
        
        # Create audit log file
        logs_dir = 'logs'
        audit_log = os.path.join(logs_dir, 'audit.log')
        
        audit_handler = RotatingFileHandler(
            audit_log,
            maxBytes=50 * 1024 * 1024,  # 50MB
            backupCount=20  # Keep more audit logs
        )
        
        audit_formatter = logging.Formatter(
            '%(asctime)s - AUDIT - %(message)s'
        )
        
        audit_handler.setFormatter(audit_formatter)
        self.logger.addHandler(audit_handler)
    
    def log_user_action(self, user_id: str, action: str, resource: str, details: dict = None):
        """Log user action for audit trail"""
        details_str = f", Details: {details}" if details else ""
        message = f"USER_ACTION - User: {user_id}, Action: {action}, Resource: {resource}{details_str}"
        self.logger.info(message)
    
    def log_data_access(self, user_id: str, data_type: str, record_id: str, action: str):
        """Log data access for compliance"""
        message = f"DATA_ACCESS - User: {user_id}, Type: {data_type}, ID: {record_id}, Action: {action}"
        self.logger.info(message)
    
    def log_configuration_change(self, user_id: str, setting: str, old_value: str, new_value: str):
        """Log configuration changes"""
        message = f"CONFIG_CHANGE - User: {user_id}, Setting: {setting}, From: {old_value}, To: {new_value}"
        self.logger.warning(message)
    
    def log_system_access(self, user_id: str, ip_address: str, user_agent: str, action: str):
        """Log system access attempts"""
        message = f"SYSTEM_ACCESS - User: {user_id}, IP: {ip_address}, Agent: {user_agent}, Action: {action}"
        self.logger.info(message)

# Global logger instances
security_logger = SecurityLogger()
performance_logger = PerformanceLogger()
audit_logger = AuditLogger()

# Context manager for performance timing
class TimingContext:
    """Context manager for timing operations"""
    
    def __init__(self, operation_name: str, logger_instance = None):
        self.operation_name = operation_name
        self.logger = logger_instance or performance_logger
        self.start_time = None
        self.end_time = None
    
    def __enter__(self):
        self.start_time = datetime.now()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()
        
        if exc_type is None:
            self.logger.log_api_request(self.operation_name, 'INTERNAL', duration, 200)
        else:
            self.logger.log_api_request(self.operation_name, 'INTERNAL', duration, 500)

def log_function_call(func):
    """Decorator to log function calls"""
    def wrapper(*args, **kwargs):
        logger = get_logger(func.__module__)
        logger.debug(f"Calling function: {func.__name__}")
        
        try:
            result = func(*args, **kwargs)
            logger.debug(f"Function {func.__name__} completed successfully")
            return result
        except Exception as e:
            logger.error(f"Function {func.__name__} failed: {str(e)}")
            raise
    
    return wrapper

