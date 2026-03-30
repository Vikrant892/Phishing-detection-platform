"""
Database models and operations for the Phishing Detection Platform
"""

import mysql.connector
from mysql.connector import Error
import json
import logging
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Any
import os

logger = logging.getLogger(__name__)

@dataclass
class EmailAnalysis:
    """Email analysis data model"""
    analysis_id: str
    email_subject: str
    email_sender: str
    threat_score: float
    risk_level: str
    threats_found: int
    analysis_data: str
    created_at: datetime
    is_quarantined: bool = False
    quarantine_reason: Optional[str] = None

@dataclass
class ThreatPattern:
    """Threat pattern data model"""
    segment_start: str
    segment_end: str
    pattern: str
    description: str = ""
    severity: str = "MEDIUM"
    is_active: bool = True
    created_at: Optional[datetime] = None

class Database:
    """Database operations class"""
    
    def __init__(self):
        self.connection = None
        self.connect()
    
    def connect(self):
        """Establish database connection"""
        try:
            self.connection = mysql.connector.connect(
                host=os.getenv('PGHOST', 'localhost'),
                database=os.getenv('PGDATABASE', 'phishing_detection'),
                user=os.getenv('PGUSER', 'root'),
                password=os.getenv('PGPASSWORD'),
                port=os.getenv('PGPORT', 3306),
                autocommit=True,
                charset='utf8mb4',
                collation='utf8mb4_unicode_ci'
            )
            
            if self.connection.is_connected():
                logger.info("Database connection established")
                self._create_tables()
            
        except Error as e:
            logger.error(f"Database connection error: {e}")
            raise
    
    def _create_tables(self):
        """Create database tables if they don't exist"""
        try:
            cursor = self.connection.cursor()
            
            # Email analyses table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS email_analyses (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    analysis_id VARCHAR(36) UNIQUE NOT NULL,
                    email_subject TEXT,
                    email_sender VARCHAR(255),
                    email_recipient VARCHAR(255),
                    threat_score DECIMAL(5,2) DEFAULT 0.00,
                    risk_level ENUM('LOW', 'MEDIUM', 'HIGH') DEFAULT 'LOW',
                    threats_found INT DEFAULT 0,
                    analysis_data JSON,
                    is_quarantined BOOLEAN DEFAULT FALSE,
                    quarantine_reason TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_analysis_id (analysis_id),
                    INDEX idx_created_at (created_at),
                    INDEX idx_risk_level (risk_level),
                    INDEX idx_threat_score (threat_score)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            
            # Threat patterns table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_patterns (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    segment_start VARCHAR(255) NOT NULL,
                    segment_end VARCHAR(255) NOT NULL,
                    pattern TEXT NOT NULL,
                    description TEXT,
                    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') DEFAULT 'MEDIUM',
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_segment (segment_start, segment_end),
                    INDEX idx_severity (severity),
                    INDEX idx_active (is_active)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            
            # Detection statistics table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS detection_stats (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    stat_date DATE NOT NULL,
                    total_analyses INT DEFAULT 0,
                    high_risk_count INT DEFAULT 0,
                    medium_risk_count INT DEFAULT 0,
                    low_risk_count INT DEFAULT 0,
                    quarantined_count INT DEFAULT 0,
                    avg_threat_score DECIMAL(5,2) DEFAULT 0.00,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE KEY unique_date (stat_date)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            
            # System logs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    log_level ENUM('INFO', 'WARNING', 'ERROR', 'CRITICAL') DEFAULT 'INFO',
                    message TEXT NOT NULL,
                    component VARCHAR(100),
                    user_id VARCHAR(100),
                    ip_address VARCHAR(45),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_log_level (log_level),
                    INDEX idx_created_at (created_at),
                    INDEX idx_component (component)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            
            cursor.close()
            logger.info("Database tables created/verified successfully")
            
        except Error as e:
            logger.error(f"Table creation error: {e}")
            raise
    
    def test_connection(self):
        """Test database connection"""
        if not self.connection or not self.connection.is_connected():
            self.connect()
        
        cursor = self.connection.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        cursor.close()
        return True
    
    def save_analysis(self, analysis: EmailAnalysis) -> bool:
        """Save email analysis to database"""
        try:
            cursor = self.connection.cursor()
            
            query = """
                INSERT INTO email_analyses 
                (analysis_id, email_subject, email_sender, threat_score, risk_level, 
                 threats_found, analysis_data, is_quarantined, quarantine_reason)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            
            values = (
                analysis.analysis_id,
                analysis.email_subject,
                analysis.email_sender,
                analysis.threat_score,
                analysis.risk_level,
                analysis.threats_found,
                analysis.analysis_data,
                analysis.is_quarantined,
                analysis.quarantine_reason
            )
            
            cursor.execute(query, values)
            cursor.close()
            
            # Update daily statistics
            self._update_daily_stats()
            
            logger.info(f"Analysis saved: {analysis.analysis_id}")
            return True
            
        except Error as e:
            logger.error(f"Save analysis error: {e}")
            return False
    
    def get_analysis(self, analysis_id: str) -> Optional[Dict]:
        """Get analysis by ID"""
        try:
            cursor = self.connection.cursor(dictionary=True)
            
            query = """
                SELECT * FROM email_analyses 
                WHERE analysis_id = %s
            """
            
            cursor.execute(query, (analysis_id,))
            result = cursor.fetchone()
            cursor.close()
            
            if result and result['analysis_data']:
                result['analysis_data'] = json.loads(result['analysis_data'])
            
            return result
            
        except Error as e:
            logger.error(f"Get analysis error: {e}")
            return None
    
    def get_analysis_history(self, page: int = 1, per_page: int = 20, risk_level: Optional[str] = None) -> List[Dict]:
        """Get paginated analysis history"""
        try:
            cursor = self.connection.cursor(dictionary=True)
            offset = (page - 1) * per_page
            
            where_clause = ""
            params = []
            
            if risk_level:
                where_clause = "WHERE risk_level = %s"
                params.append(risk_level)
            
            query = f"""
                SELECT analysis_id, email_subject, email_sender, threat_score, 
                       risk_level, threats_found, is_quarantined, created_at
                FROM email_analyses 
                {where_clause}
                ORDER BY created_at DESC 
                LIMIT %s OFFSET %s
            """
            
            params.extend([per_page, offset])
            cursor.execute(query, params)
            results = cursor.fetchall()
            cursor.close()
            
            return results
            
        except Error as e:
            logger.error(f"Get analysis history error: {e}")
            return []
    
    def get_total_analyses_count(self, risk_level: Optional[str] = None) -> int:
        """Get total count of analyses"""
        try:
            cursor = self.connection.cursor()
            
            where_clause = ""
            params = []
            
            if risk_level:
                where_clause = "WHERE risk_level = %s"
                params.append(risk_level)
            
            query = f"SELECT COUNT(*) FROM email_analyses {where_clause}"
            cursor.execute(query, params)
            count = cursor.fetchone()[0]
            cursor.close()
            
            return count
            
        except Error as e:
            logger.error(f"Get total analyses count error: {e}")
            return 0
    
    def get_dashboard_stats(self) -> Dict:
        """Get dashboard statistics"""
        try:
            cursor = self.connection.cursor(dictionary=True)
            
            # Total analyses
            cursor.execute("SELECT COUNT(*) as total FROM email_analyses")
            total_analyses = cursor.fetchone()['total']
            
            # Risk level distribution
            cursor.execute("""
                SELECT risk_level, COUNT(*) as count 
                FROM email_analyses 
                GROUP BY risk_level
            """)
            risk_distribution = {row['risk_level']: row['count'] for row in cursor.fetchall()}
            
            # Recent 24 hours
            cursor.execute("""
                SELECT COUNT(*) as count 
                FROM email_analyses 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            """)
            recent_24h = cursor.fetchone()['count']
            
            # Average threat score
            cursor.execute("SELECT AVG(threat_score) as avg_score FROM email_analyses")
            avg_threat_score = cursor.fetchone()['avg_score'] or 0
            
            # Quarantined emails
            cursor.execute("SELECT COUNT(*) as count FROM email_analyses WHERE is_quarantined = TRUE")
            quarantined_count = cursor.fetchone()['count']
            
            # Top threats by hour (last 24 hours)
            cursor.execute("""
                SELECT HOUR(created_at) as hour, COUNT(*) as count
                FROM email_analyses 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
                GROUP BY HOUR(created_at)
                ORDER BY hour
            """)
            hourly_threats = cursor.fetchall()
            
            cursor.close()
            
            return {
                'total_analyses': total_analyses,
                'risk_distribution': risk_distribution,
                'recent_24h': recent_24h,
                'avg_threat_score': float(avg_threat_score),
                'quarantined_count': quarantined_count,
                'hourly_threats': hourly_threats
            }
            
        except Error as e:
            logger.error(f"Get dashboard stats error: {e}")
            return {}
    
    def get_threat_patterns(self) -> List[Dict]:
        """Get all active threat patterns"""
        try:
            cursor = self.connection.cursor(dictionary=True)
            
            query = """
                SELECT * FROM threat_patterns 
                WHERE is_active = TRUE 
                ORDER BY severity DESC, created_at DESC
            """
            
            cursor.execute(query)
            results = cursor.fetchall()
            cursor.close()
            
            return results
            
        except Error as e:
            logger.error(f"Get threat patterns error: {e}")
            return []
    
    def add_threat_pattern(self, pattern: ThreatPattern) -> Optional[int]:
        """Add new threat pattern"""
        try:
            cursor = self.connection.cursor()
            
            query = """
                INSERT INTO threat_patterns 
                (segment_start, segment_end, pattern, description, severity, is_active)
                VALUES (%s, %s, %s, %s, %s, %s)
            """
            
            values = (
                pattern.segment_start,
                pattern.segment_end,
                pattern.pattern,
                pattern.description,
                pattern.severity,
                pattern.is_active
            )
            
            cursor.execute(query, values)
            pattern_id = cursor.lastrowid
            cursor.close()
            
            logger.info(f"Threat pattern added: {pattern_id}")
            return pattern_id
            
        except Error as e:
            logger.error(f"Add threat pattern error: {e}")
            return None
    
    def quarantine_email(self, analysis_id: str, reason: str) -> bool:
        """Quarantine an email analysis"""
        try:
            cursor = self.connection.cursor()
            
            query = """
                UPDATE email_analyses 
                SET is_quarantined = TRUE, quarantine_reason = %s, updated_at = CURRENT_TIMESTAMP
                WHERE analysis_id = %s
            """
            
            cursor.execute(query, (reason, analysis_id))
            success = cursor.rowcount > 0
            cursor.close()
            
            if success:
                logger.info(f"Email quarantined: {analysis_id}")
            
            return success
            
        except Error as e:
            logger.error(f"Quarantine email error: {e}")
            return False
    
    def search_analyses(self, query: str, search_type: str, page: int = 1, per_page: int = 20) -> List[Dict]:
        """Search through email analyses"""
        try:
            cursor = self.connection.cursor(dictionary=True)
            offset = (page - 1) * per_page
            
            search_conditions = {
                'all': "email_subject LIKE %s OR email_sender LIKE %s",
                'subject': "email_subject LIKE %s",
                'sender': "email_sender LIKE %s",
                'content': "JSON_SEARCH(analysis_data, 'all', %s) IS NOT NULL"
            }
            
            where_clause = search_conditions.get(search_type, search_conditions['all'])
            search_term = f"%{query}%"
            
            sql_query = f"""
                SELECT analysis_id, email_subject, email_sender, threat_score, 
                       risk_level, threats_found, is_quarantined, created_at
                FROM email_analyses 
                WHERE {where_clause}
                ORDER BY created_at DESC 
                LIMIT %s OFFSET %s
            """
            
            if search_type in ['subject', 'sender', 'content']:
                params = [search_term, per_page, offset]
            else:
                params = [search_term, search_term, per_page, offset]
            
            cursor.execute(sql_query, params)
            results = cursor.fetchall()
            cursor.close()
            
            return results
            
        except Error as e:
            logger.error(f"Search analyses error: {e}")
            return []
    
    def get_search_count(self, query: str, search_type: str) -> int:
        """Get count of search results"""
        try:
            cursor = self.connection.cursor()
            
            search_conditions = {
                'all': "email_subject LIKE %s OR email_sender LIKE %s",
                'subject': "email_subject LIKE %s",
                'sender': "email_sender LIKE %s",
                'content': "JSON_SEARCH(analysis_data, 'all', %s) IS NOT NULL"
            }
            
            where_clause = search_conditions.get(search_type, search_conditions['all'])
            search_term = f"%{query}%"
            
            sql_query = f"SELECT COUNT(*) FROM email_analyses WHERE {where_clause}"
            
            if search_type in ['subject', 'sender', 'content']:
                params = [search_term]
            else:
                params = [search_term, search_term]
            
            cursor.execute(sql_query, params)
            count = cursor.fetchone()[0]
            cursor.close()
            
            return count
            
        except Error as e:
            logger.error(f"Get search count error: {e}")
            return 0
    
    def get_active_threats_count(self) -> int:
        """Get count of active high-risk threats in last 24 hours"""
        try:
            cursor = self.connection.cursor()
            
            query = """
                SELECT COUNT(*) FROM email_analyses 
                WHERE risk_level = 'HIGH' 
                AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            """
            
            cursor.execute(query)
            count = cursor.fetchone()[0]
            cursor.close()
            
            return count
            
        except Error as e:
            logger.error(f"Get active threats count error: {e}")
            return 0
    
    def get_recent_analyses(self, limit: int = 10) -> List[Dict]:
        """Get recent analyses"""
        try:
            cursor = self.connection.cursor(dictionary=True)
            
            query = """
                SELECT analysis_id, email_subject, email_sender, threat_score, 
                       risk_level, created_at
                FROM email_analyses 
                ORDER BY created_at DESC 
                LIMIT %s
            """
            
            cursor.execute(query, (limit,))
            results = cursor.fetchall()
            cursor.close()
            
            return results
            
        except Error as e:
            logger.error(f"Get recent analyses error: {e}")
            return []
    
    def _update_daily_stats(self):
        """Update daily statistics"""
        try:
            cursor = self.connection.cursor()
            today = datetime.now().date()
            
            # Get today's stats
            cursor.execute("""
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN risk_level = 'HIGH' THEN 1 ELSE 0 END) as high_risk,
                    SUM(CASE WHEN risk_level = 'MEDIUM' THEN 1 ELSE 0 END) as medium_risk,
                    SUM(CASE WHEN risk_level = 'LOW' THEN 1 ELSE 0 END) as low_risk,
                    SUM(CASE WHEN is_quarantined = TRUE THEN 1 ELSE 0 END) as quarantined,
                    AVG(threat_score) as avg_score
                FROM email_analyses 
                WHERE DATE(created_at) = %s
            """, (today,))
            
            stats = cursor.fetchone()
            
            # Insert or update daily stats
            cursor.execute("""
                INSERT INTO detection_stats 
                (stat_date, total_analyses, high_risk_count, medium_risk_count, 
                 low_risk_count, quarantined_count, avg_threat_score)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                total_analyses = VALUES(total_analyses),
                high_risk_count = VALUES(high_risk_count),
                medium_risk_count = VALUES(medium_risk_count),
                low_risk_count = VALUES(low_risk_count),
                quarantined_count = VALUES(quarantined_count),
                avg_threat_score = VALUES(avg_threat_score)
            """, (today, stats[0], stats[1], stats[2], stats[3], stats[4], stats[5] or 0))
            
            cursor.close()
            
        except Error as e:
            logger.error(f"Update daily stats error: {e}")
    
    def close(self):
        """Close database connection"""
        if self.connection and self.connection.is_connected():
            self.connection.close()
            logger.info("Database connection closed")
