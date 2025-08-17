"""
Database Manager - Comprehensive database operations for threat management
"""

import os
import logging
import mysql.connector
from mysql.connector import Error
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import hashlib

class DatabaseManager:
    """Advanced database manager for threat detection platform"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.connection = None
        self.connection_config = {
            'host': os.getenv('PGHOST', 'localhost'),
            'port': int(os.getenv('PGPORT', 3306)),
            'user': os.getenv('PGUSER', 'root'),
            'password': os.getenv('PGPASSWORD', ''),
            'database': os.getenv('PGDATABASE', 'phishing_detector'),
            'charset': 'utf8mb4',
            'collation': 'utf8mb4_unicode_ci'
        }
        
    def connect(self):
        """Establish database connection"""
        try:
            if self.connection and self.connection.is_connected():
                return self.connection
            
            self.connection = mysql.connector.connect(**self.connection_config)
            self.logger.info("Database connection established")
            return self.connection
            
        except Error as e:
            self.logger.error(f"Database connection error: {str(e)}")
            raise
    
    def disconnect(self):
        """Close database connection"""
        try:
            if self.connection and self.connection.is_connected():
                self.connection.close()
                self.logger.info("Database connection closed")
        except Error as e:
            self.logger.error(f"Database disconnection error: {str(e)}")
    
    def test_connection(self) -> bool:
        """Test database connection"""
        try:
            conn = self.connect()
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchone()
            cursor.close()
            return True
        except Exception as e:
            self.logger.error(f"Connection test failed: {str(e)}")
            return False
    
    def initialize_tables(self):
        """Initialize database tables"""
        try:
            conn = self.connect()
            cursor = conn.cursor()
            
            # Create database if not exists
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {self.connection_config['database']} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
            cursor.execute(f"USE {self.connection_config['database']}")
            
            # Email analysis results table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS email_analysis (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    email_id VARCHAR(32) UNIQUE NOT NULL,
                    filename VARCHAR(255),
                    analysis_date DATETIME NOT NULL,
                    threat_score INT DEFAULT 0,
                    risk_level ENUM('low', 'medium', 'high', 'critical') DEFAULT 'low',
                    email_format VARCHAR(10),
                    sender_address VARCHAR(255),
                    subject TEXT,
                    headers JSON,
                    body_content LONGTEXT,
                    attachments JSON,
                    analysis_result JSON,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_analysis_date (analysis_date),
                    INDEX idx_risk_level (risk_level),
                    INDEX idx_threat_score (threat_score)
                )
            """)
            
            # Detected threats table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS detected_threats (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    email_id VARCHAR(32) NOT NULL,
                    threat_type VARCHAR(100) NOT NULL,
                    severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
                    category VARCHAR(100),
                    description TEXT,
                    evidence TEXT,
                    location VARCHAR(255),
                    line_number INT DEFAULT NULL,
                    pattern_matched TEXT,
                    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (email_id) REFERENCES email_analysis(email_id) ON DELETE CASCADE,
                    INDEX idx_threat_type (threat_type),
                    INDEX idx_severity (severity),
                    INDEX idx_category (category),
                    INDEX idx_detected_at (detected_at)
                )
            """)
            
            # Setup rules table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS setup_rules (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    rule_name VARCHAR(255) NOT NULL,
                    start_segment VARCHAR(100) NOT NULL,
                    end_segment VARCHAR(100),
                    phrase TEXT NOT NULL,
                    rule_type ENUM('single_line', 'multi_line', 'regex', 'html_segment') DEFAULT 'single_line',
                    severity ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_active (is_active),
                    INDEX idx_severity (severity)
                )
            """)
            
            # Threat statistics table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_statistics (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    stat_date DATE NOT NULL,
                    emails_processed INT DEFAULT 0,
                    threats_detected INT DEFAULT 0,
                    critical_threats INT DEFAULT 0,
                    high_threats INT DEFAULT 0,
                    medium_threats INT DEFAULT 0,
                    low_threats INT DEFAULT 0,
                    avg_threat_score DECIMAL(5,2) DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY unique_date (stat_date)
                )
            """)
            
            # Quarantine table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS quarantine (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    email_id VARCHAR(32) NOT NULL,
                    quarantine_reason TEXT,
                    quarantined_by VARCHAR(100),
                    quarantine_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    release_date TIMESTAMP NULL,
                    status ENUM('quarantined', 'released', 'deleted') DEFAULT 'quarantined',
                    FOREIGN KEY (email_id) REFERENCES email_analysis(email_id) ON DELETE CASCADE,
                    INDEX idx_status (status),
                    INDEX idx_quarantine_date (quarantine_date)
                )
            """)
            
            # User sessions table (for PHP integration)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_sessions (
                    id VARCHAR(128) PRIMARY KEY,
                    user_id VARCHAR(100),
                    session_data JSON,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    INDEX idx_expires (expires_at),
                    INDEX idx_user_id (user_id)
                )
            """)
            
            conn.commit()
            cursor.close()
            self.logger.info("Database tables initialized successfully")
            
        except Error as e:
            self.logger.error(f"Table initialization error: {str(e)}")
            raise
    
    def save_email_analysis(self, email_data: Dict[str, Any], analysis_result: Dict[str, Any]) -> str:
        """Save email analysis results to database"""
        try:
            conn = self.connect()
            cursor = conn.cursor()
            
            # Extract email metadata
            email_id = analysis_result.get('email_id')
            filename = email_data.get('filename', 'unknown')
            sender_address = email_data.get('headers', {}).get('from', '')
            subject = email_data.get('headers', {}).get('subject', '')
            
            # Insert email analysis
            insert_query = """
                INSERT INTO email_analysis (
                    email_id, filename, analysis_date, threat_score, risk_level,
                    email_format, sender_address, subject, headers, body_content,
                    attachments, analysis_result
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    analysis_date = VALUES(analysis_date),
                    threat_score = VALUES(threat_score),
                    risk_level = VALUES(risk_level),
                    analysis_result = VALUES(analysis_result)
            """
            
            cursor.execute(insert_query, (
                email_id,
                filename,
                datetime.utcnow(),
                analysis_result.get('threat_score', 0),
                analysis_result.get('risk_level', 'low'),
                email_data.get('format', 'unknown'),
                sender_address,
                subject,
                json.dumps(email_data.get('headers', {})),
                json.dumps(email_data.get('body', {})),
                json.dumps(email_data.get('attachments', [])),
                json.dumps(analysis_result)
            ))
            
            # Save detected threats
            for threat in analysis_result.get('threats_detected', []):
                threat_query = """
                    INSERT INTO detected_threats (
                        email_id, threat_type, severity, category, description,
                        evidence, location, line_number, pattern_matched
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                
                cursor.execute(threat_query, (
                    email_id,
                    threat.get('type', 'unknown'),
                    threat.get('severity', 'low'),
                    threat.get('category', 'general'),
                    threat.get('description', ''),
                    threat.get('evidence', ''),
                    threat.get('location', ''),
                    threat.get('line_number'),
                    threat.get('pattern', '')
                ))
            
            conn.commit()
            cursor.close()
            
            # Update statistics
            self.update_daily_statistics()
            
            self.logger.info(f"Email analysis saved: {email_id}")
            return email_id
            
        except Error as e:
            self.logger.error(f"Save analysis error: {str(e)}")
            conn.rollback()
            raise
    
    def get_email_analysis(self, email_id: str) -> Optional[Dict[str, Any]]:
        """Get email analysis by ID"""
        try:
            conn = self.connect()
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute("""
                SELECT * FROM email_analysis WHERE email_id = %s
            """, (email_id,))
            
            result = cursor.fetchone()
            cursor.close()
            
            if result:
                # Parse JSON fields
                result['headers'] = json.loads(result['headers']) if result['headers'] else {}
                result['body_content'] = json.loads(result['body_content']) if result['body_content'] else {}
                result['attachments'] = json.loads(result['attachments']) if result['attachments'] else []
                result['analysis_result'] = json.loads(result['analysis_result']) if result['analysis_result'] else {}
            
            return result
            
        except Error as e:
            self.logger.error(f"Get analysis error: {str(e)}")
            return None
    
    def get_threat_history(self, limit: int = 100, offset: int = 0, 
                          risk_level: str = None, date_from: str = None, 
                          date_to: str = None) -> List[Dict[str, Any]]:
        """Get threat detection history with filters"""
        try:
            conn = self.connect()
            cursor = conn.cursor(dictionary=True)
            
            query = """
                SELECT ea.*, COUNT(dt.id) as threat_count
                FROM email_analysis ea
                LEFT JOIN detected_threats dt ON ea.email_id = dt.email_id
            """
            
            conditions = []
            params = []
            
            if risk_level:
                conditions.append("ea.risk_level = %s")
                params.append(risk_level)
            
            if date_from:
                conditions.append("ea.analysis_date >= %s")
                params.append(date_from)
            
            if date_to:
                conditions.append("ea.analysis_date <= %s")
                params.append(date_to)
            
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            
            query += """
                GROUP BY ea.id
                ORDER BY ea.analysis_date DESC
                LIMIT %s OFFSET %s
            """
            
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            results = cursor.fetchall()
            cursor.close()
            
            # Parse JSON fields
            for result in results:
                result['headers'] = json.loads(result['headers']) if result['headers'] else {}
                result['analysis_result'] = json.loads(result['analysis_result']) if result['analysis_result'] else {}
            
            return results
            
        except Error as e:
            self.logger.error(f"Get threat history error: {str(e)}")
            return []
    
    def get_threat_details(self, email_id: str) -> List[Dict[str, Any]]:
        """Get detailed threat information for an email"""
        try:
            conn = self.connect()
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute("""
                SELECT * FROM detected_threats 
                WHERE email_id = %s 
                ORDER BY severity DESC, detected_at DESC
            """, (email_id,))
            
            results = cursor.fetchall()
            cursor.close()
            
            return results
            
        except Error as e:
            self.logger.error(f"Get threat details error: {str(e)}")
            return []
    
    def get_platform_statistics(self) -> Dict[str, Any]:
        """Get comprehensive platform statistics"""
        try:
            conn = self.connect()
            cursor = conn.cursor(dictionary=True)
            
            stats = {}
            
            # Total counts
            cursor.execute("SELECT COUNT(*) as total_emails FROM email_analysis")
            stats['total_emails'] = cursor.fetchone()['total_emails']
            
            cursor.execute("SELECT COUNT(*) as total_threats FROM detected_threats")
            stats['total_threats'] = cursor.fetchone()['total_threats']
            
            # Risk level distribution
            cursor.execute("""
                SELECT risk_level, COUNT(*) as count 
                FROM email_analysis 
                GROUP BY risk_level
            """)
            stats['risk_distribution'] = {row['risk_level']: row['count'] for row in cursor.fetchall()}
            
            # Threat categories
            cursor.execute("""
                SELECT category, COUNT(*) as count 
                FROM detected_threats 
                GROUP BY category 
                ORDER BY count DESC 
                LIMIT 10
            """)
            stats['threat_categories'] = cursor.fetchall()
            
            # Daily statistics for the last 30 days
            cursor.execute("""
                SELECT stat_date, emails_processed, threats_detected, avg_threat_score
                FROM threat_statistics 
                WHERE stat_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
                ORDER BY stat_date DESC
            """)
            stats['daily_stats'] = cursor.fetchall()
            
            # Recent activity
            cursor.execute("""
                SELECT DATE(analysis_date) as date, COUNT(*) as count
                FROM email_analysis 
                WHERE analysis_date >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                GROUP BY DATE(analysis_date)
                ORDER BY date DESC
            """)
            stats['recent_activity'] = cursor.fetchall()
            
            # Top threat types
            cursor.execute("""
                SELECT threat_type, severity, COUNT(*) as count
                FROM detected_threats 
                GROUP BY threat_type, severity
                ORDER BY count DESC
                LIMIT 15
            """)
            stats['top_threats'] = cursor.fetchall()
            
            cursor.close()
            return stats
            
        except Error as e:
            self.logger.error(f"Get statistics error: {str(e)}")
            return {}
    
    def save_setup_rules(self, rules: List[Dict[str, Any]]) -> bool:
        """Save setup rules to database"""
        try:
            conn = self.connect()
            cursor = conn.cursor()
            
            # Clear existing rules (optional - based on requirements)
            # cursor.execute("DELETE FROM setup_rules WHERE is_active = TRUE")
            
            for rule in rules:
                insert_query = """
                    INSERT INTO setup_rules (
                        rule_name, start_segment, end_segment, phrase,
                        rule_type, severity, is_active
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        start_segment = VALUES(start_segment),
                        end_segment = VALUES(end_segment),
                        phrase = VALUES(phrase),
                        rule_type = VALUES(rule_type),
                        severity = VALUES(severity)
                """
                
                cursor.execute(insert_query, (
                    rule.get('name', f'Rule_{datetime.now().strftime("%Y%m%d_%H%M%S")}'),
                    rule.get('start_segment', '<body'),
                    rule.get('end_segment', '</body>'),
                    rule.get('phrase', ''),
                    rule.get('type', 'single_line'),
                    rule.get('severity', 'medium'),
                    rule.get('is_active', True)
                ))
            
            conn.commit()
            cursor.close()
            
            self.logger.info(f"Saved {len(rules)} setup rules")
            return True
            
        except Error as e:
            self.logger.error(f"Save setup rules error: {str(e)}")
            conn.rollback()
            return False
    
    def get_setup_rules(self, active_only: bool = True) -> List[Dict[str, Any]]:
        """Get setup rules from database"""
        try:
            conn = self.connect()
            cursor = conn.cursor(dictionary=True)
            
            query = "SELECT * FROM setup_rules"
            if active_only:
                query += " WHERE is_active = TRUE"
            query += " ORDER BY severity DESC, created_at DESC"
            
            cursor.execute(query)
            results = cursor.fetchall()
            cursor.close()
            
            return results
            
        except Error as e:
            self.logger.error(f"Get setup rules error: {str(e)}")
            return []
    
    def quarantine_email(self, email_id: str, reason: str, quarantined_by: str = 'system') -> bool:
        """Quarantine suspicious email"""
        try:
            conn = self.connect()
            cursor = conn.cursor()
            
            insert_query = """
                INSERT INTO quarantine (email_id, quarantine_reason, quarantined_by)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    quarantine_reason = VALUES(quarantine_reason),
                    quarantined_by = VALUES(quarantined_by),
                    quarantine_date = CURRENT_TIMESTAMP,
                    status = 'quarantined'
            """
            
            cursor.execute(insert_query, (email_id, reason, quarantined_by))
            conn.commit()
            cursor.close()
            
            self.logger.info(f"Email quarantined: {email_id}")
            return True
            
        except Error as e:
            self.logger.error(f"Quarantine error: {str(e)}")
            return False
    
    def update_daily_statistics(self):
        """Update daily threat statistics"""
        try:
            conn = self.connect()
            cursor = conn.cursor()
            
            today = datetime.now().date()
            
            # Get today's statistics
            cursor.execute("""
                SELECT 
                    COUNT(*) as emails_processed,
                    COUNT(CASE WHEN threat_score > 0 THEN 1 END) as threats_detected,
                    COUNT(CASE WHEN risk_level = 'critical' THEN 1 END) as critical_threats,
                    COUNT(CASE WHEN risk_level = 'high' THEN 1 END) as high_threats,
                    COUNT(CASE WHEN risk_level = 'medium' THEN 1 END) as medium_threats,
                    COUNT(CASE WHEN risk_level = 'low' THEN 1 END) as low_threats,
                    AVG(threat_score) as avg_threat_score
                FROM email_analysis 
                WHERE DATE(analysis_date) = %s
            """, (today,))
            
            stats = cursor.fetchone()
            
            # Insert or update statistics
            update_query = """
                INSERT INTO threat_statistics (
                    stat_date, emails_processed, threats_detected,
                    critical_threats, high_threats, medium_threats, low_threats,
                    avg_threat_score
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    emails_processed = VALUES(emails_processed),
                    threats_detected = VALUES(threats_detected),
                    critical_threats = VALUES(critical_threats),
                    high_threats = VALUES(high_threats),
                    medium_threats = VALUES(medium_threats),
                    low_threats = VALUES(low_threats),
                    avg_threat_score = VALUES(avg_threat_score)
            """
            
            cursor.execute(update_query, (today,) + stats)
            conn.commit()
            cursor.close()
            
        except Error as e:
            self.logger.error(f"Update statistics error: {str(e)}")
    
    def cleanup_old_data(self, days_to_keep: int = 90):
        """Clean up old data beyond retention period"""
        try:
            conn = self.connect()
            cursor = conn.cursor()
            
            cutoff_date = datetime.now() - timedelta(days=days_to_keep)
            
            # Clean up old analysis data
            cursor.execute("""
                DELETE FROM email_analysis 
                WHERE analysis_date < %s
            """, (cutoff_date,))
            
            # Clean up old statistics
            cursor.execute("""
                DELETE FROM threat_statistics 
                WHERE stat_date < %s
            """, (cutoff_date.date(),))
            
            # Clean up expired sessions
            cursor.execute("""
                DELETE FROM user_sessions 
                WHERE expires_at < NOW()
            """)
            
            conn.commit()
            cursor.close()
            
            self.logger.info(f"Cleaned up data older than {days_to_keep} days")
            
        except Error as e:
            self.logger.error(f"Cleanup error: {str(e)}")
    
    def __del__(self):
        """Destructor to ensure connection cleanup"""
        self.disconnect()
