#!/usr/bin/env python3
"""
Database schema for enhanced phishing detection platform (SQLite edition).

Originally targeted PostgreSQL via psycopg2; refactored to use SQLite so the
app can run on platforms without managed Postgres (e.g. Hugging Face Spaces
free tier). Row access is preserved via ``sqlite3.Row`` (mapping-style access),
so callers that previously used ``RealDictCursor`` continue to work unchanged.
"""

import json
import logging
import os
import sqlite3
from pathlib import Path

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manages database operations for the phishing detection platform (SQLite)."""

    def __init__(self):
        # Source path from env; default to a project-local path.
        self.db_path = os.getenv('SQLITE_PATH', 'data/phishing.sqlite')
        # Ensure the parent directory exists; do NOT raise if env is missing.
        try:
            parent = Path(self.db_path).parent
            if str(parent):
                parent.mkdir(parents=True, exist_ok=True)
        except Exception as e:  # pragma: no cover - defensive
            logger.warning(f"Could not create SQLite parent directory: {e}")

    def _configure_connection(self, conn):
        """Apply SQLite pragmas for better concurrency/durability."""
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=5000")
        except Exception as e:  # pragma: no cover - defensive
            logger.warning(f"Could not configure SQLite pragmas: {e}")

    def get_connection(self):
        """Get a SQLite connection with mapping-style row access."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        self._configure_connection(conn)
        return conn

    def create_tables(self):
        """Create all required database tables."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                # Email Analysis Results table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS email_analyses (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        analysis_id TEXT UNIQUE NOT NULL,
                        filename TEXT NOT NULL,
                        email_subject TEXT,
                        sender TEXT,
                        recipient TEXT,
                        email_date TIMESTAMP,
                        threat_score INTEGER DEFAULT 0,
                        threat_level TEXT DEFAULT 'LOW',
                        overall_status TEXT DEFAULT 'PASS',
                        analysis_type TEXT DEFAULT 'basic',
                        total_segments INTEGER DEFAULT 0,
                        total_threats INTEGER DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)

                # Email Headers table for detailed header analysis
                # threat_patterns was a PostgreSQL TEXT[]; stored as JSON TEXT here.
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS email_headers (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        analysis_id TEXT REFERENCES email_analyses(analysis_id) ON DELETE CASCADE,
                        header_name TEXT NOT NULL,
                        header_value TEXT,
                        is_suspicious INTEGER DEFAULT 0,
                        threat_patterns TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)

                # HTML Segments table for detailed segment analysis
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS html_segments (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        analysis_id TEXT REFERENCES email_analyses(analysis_id) ON DELETE CASCADE,
                        segment_number INTEGER NOT NULL,
                        start_line INTEGER NOT NULL,
                        end_line INTEGER NOT NULL,
                        segment_type TEXT NOT NULL,
                        content TEXT NOT NULL,
                        is_single_line INTEGER NOT NULL,
                        is_html_segment INTEGER NOT NULL,
                        is_multiline INTEGER NOT NULL,
                        threat_count INTEGER DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)

                # Threat Detections table for individual threats found
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS threat_detections (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        analysis_id TEXT REFERENCES email_analyses(analysis_id) ON DELETE CASCADE,
                        segment_id INTEGER REFERENCES html_segments(id) ON DELETE CASCADE,
                        threat_category TEXT NOT NULL,
                        threat_pattern TEXT NOT NULL,
                        threat_context TEXT,
                        threat_type TEXT NOT NULL,
                        line_number INTEGER,
                        severity_level TEXT DEFAULT 'MEDIUM',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)

                # Failure Tracking table for emails that fail analysis
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS analysis_failures (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        filename TEXT NOT NULL,
                        failure_reason TEXT NOT NULL,
                        failure_location TEXT,
                        error_details TEXT,
                        stack_trace TEXT,
                        failure_type TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)

                # Threat Statistics table for aggregated reporting
                # severity_distribution was JSON in PG; stored as TEXT (JSON-encoded) here.
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS threat_statistics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        threat_category TEXT NOT NULL,
                        threat_pattern TEXT NOT NULL,
                        occurrence_count INTEGER DEFAULT 1,
                        last_detected TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        severity_distribution TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(threat_category, threat_pattern)
                    )
                """)

                # Create indexes for better performance
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_email_analyses_analysis_id ON email_analyses(analysis_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_email_analyses_created_at ON email_analyses(created_at)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_email_analyses_threat_level ON email_analyses(threat_level)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_detections_category ON threat_detections(threat_category)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_detections_pattern ON threat_detections(threat_pattern)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_analysis_failures_failure_type ON analysis_failures(failure_type)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_statistics_category ON threat_statistics(threat_category)")

                conn.commit()
                logger.info("Database tables created successfully")

        except Exception as e:
            logger.error(f"Error creating database tables: {e}")
            raise

    def save_email_analysis(self, analysis_data):
        """Save complete email analysis results to database."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                # Insert main analysis record
                cursor.execute("""
                    INSERT INTO email_analyses (
                        analysis_id, filename, email_subject, sender, recipient,
                        email_date, threat_score, threat_level, overall_status,
                        analysis_type, total_segments, total_threats
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    analysis_data['analysis_id'],
                    analysis_data['filename'],
                    analysis_data.get('subject'),
                    analysis_data.get('sender'),
                    analysis_data.get('recipient'),
                    analysis_data.get('email_date'),
                    analysis_data.get('threat_score', 0),
                    analysis_data.get('threat_level', 'LOW'),
                    analysis_data.get('overall_status', 'PASS'),
                    analysis_data.get('analysis_type', 'basic'),
                    analysis_data.get('total_segments', 0),
                    analysis_data.get('total_threats', 0)
                ))

                # Save email headers if present
                if 'headers' in analysis_data:
                    for header_name, header_data in analysis_data['headers'].items():
                        cursor.execute("""
                            INSERT INTO email_headers (
                                analysis_id, header_name, header_value,
                                is_suspicious, threat_patterns
                            ) VALUES (?, ?, ?, ?, ?)
                        """, (
                            analysis_data['analysis_id'],
                            header_name,
                            header_data.get('value'),
                            1 if header_data.get('is_suspicious', False) else 0,
                            json.dumps(header_data.get('threat_patterns', []))
                        ))

                # Save HTML segments if present
                if 'html_segments' in analysis_data:
                    for i, segment_analysis in enumerate(analysis_data['html_segments']):
                        segment = segment_analysis['segment']

                        cursor.execute("""
                            INSERT INTO html_segments (
                                analysis_id, segment_number, start_line, end_line,
                                segment_type, content, is_single_line, is_html_segment,
                                is_multiline, threat_count
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            analysis_data['analysis_id'],
                            i + 1,
                            segment['start_line'],
                            segment['end_line'],
                            segment['type'],
                            segment['content'],
                            1 if segment['start_line'] == segment['end_line'] else 0,
                            1 if 'html' in segment['type'].lower() else 0,
                            1 if segment['start_line'] != segment['end_line'] else 0,
                            len(segment_analysis.get('threats', []))
                        ))

                        segment_id = cursor.lastrowid

                        # Save threats for this segment
                        for threat in segment_analysis.get('threats', []):
                            cursor.execute("""
                                INSERT INTO threat_detections (
                                    analysis_id, segment_id, threat_category, threat_pattern,
                                    threat_context, threat_type, line_number, severity_level
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            """, (
                                analysis_data['analysis_id'],
                                segment_id,
                                threat['category'],
                                threat['pattern'],
                                threat.get('context'),
                                threat.get('type', 'phrase_match'),
                                segment['start_line'],
                                threat.get('severity_level', 'MEDIUM')
                            ))

                            # Update threat statistics
                            self._update_threat_statistics(cursor, threat['category'], threat['pattern'])

                conn.commit()
                logger.info(f"Saved analysis results for {analysis_data['filename']}")

        except Exception as e:
            logger.error(f"Error saving email analysis: {e}")
            raise

    def save_analysis_failure(self, filename, failure_reason, failure_location=None,
                              error_details=None, stack_trace=None, failure_type="PARSING_ERROR"):
        """Save analysis failure details to database."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO analysis_failures (
                        filename, failure_reason, failure_location,
                        error_details, stack_trace, failure_type
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    filename, failure_reason, failure_location,
                    error_details, stack_trace, failure_type
                ))
                conn.commit()
                logger.info(f"Saved failure record for {filename}")

        except Exception as e:
            logger.error(f"Error saving analysis failure: {e}")

    def _update_threat_statistics(self, cursor, category, pattern):
        """Update threat occurrence statistics (UPSERT)."""
        # SQLite supports ON CONFLICT (UPSERT) since 3.24.0 (2018).
        cursor.execute("""
            INSERT INTO threat_statistics (threat_category, threat_pattern, occurrence_count)
            VALUES (?, ?, 1)
            ON CONFLICT (threat_category, threat_pattern)
            DO UPDATE SET
                occurrence_count = threat_statistics.occurrence_count + 1,
                last_detected = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
        """, (category, pattern))

    def get_threat_statistics(self):
        """Get threat occurrence statistics."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT
                        threat_category,
                        threat_pattern,
                        occurrence_count,
                        last_detected
                    FROM threat_statistics
                    ORDER BY occurrence_count DESC, last_detected DESC
                """)
                return [dict(row) for row in cursor.fetchall()]

        except Exception as e:
            logger.error(f"Error fetching threat statistics: {e}")
            return []

    def get_failure_statistics(self):
        """Get analysis failure statistics."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT
                        failure_type,
                        COUNT(*) as occurrence_count,
                        MAX(created_at) as last_occurrence
                    FROM analysis_failures
                    GROUP BY failure_type
                    ORDER BY occurrence_count DESC
                """)
                return [dict(row) for row in cursor.fetchall()]

        except Exception as e:
            logger.error(f"Error fetching failure statistics: {e}")
            return []

    def get_dashboard_stats(self):
        """Get comprehensive dashboard statistics."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                # Total analyses
                cursor.execute("SELECT COUNT(*) as total FROM email_analyses")
                total_analyses = cursor.fetchone()['total']

                # Risk distribution
                cursor.execute("""
                    SELECT threat_level, COUNT(*) as count
                    FROM email_analyses
                    GROUP BY threat_level
                """)
                risk_distribution = {row['threat_level']: row['count'] for row in cursor.fetchall()}

                # Average threat score
                cursor.execute("SELECT AVG(threat_score) as avg_score FROM email_analyses")
                avg_score = cursor.fetchone()['avg_score'] or 0

                # Recent analyses
                cursor.execute("""
                    SELECT email_subject, sender, threat_score, threat_level, created_at
                    FROM email_analyses
                    ORDER BY created_at DESC
                    LIMIT 10
                """)
                recent_analyses = [dict(row) for row in cursor.fetchall()]

                return {
                    'total_analyses': total_analyses,
                    'risk_distribution': risk_distribution,
                    'avg_threat_score': round(float(avg_score), 1),
                    'quarantined_count': risk_distribution.get('HIGH', 0),
                    'recent_analyses': recent_analyses
                }

        except Exception as e:
            logger.error(f"Error fetching dashboard stats: {e}")
            return {
                'total_analyses': 0,
                'risk_distribution': {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0},
                'avg_threat_score': 0.0,
                'quarantined_count': 0,
                'recent_analyses': []
            }


# Initialize database manager (module-level singleton).
db_manager = DatabaseManager()
