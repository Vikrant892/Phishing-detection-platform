"""
Threat API - RESTful endpoints for threat management and statistics
"""

from flask import Blueprint, request, jsonify
import logging
from datetime import datetime, timedelta
import json

from models.database_manager import DatabaseManager
from models.threat_detector import ThreatDetector

# Create blueprint
threat_bp = Blueprint('threat_api', __name__)

# Initialize components
db_manager = DatabaseManager()
threat_detector = ThreatDetector()

logger = logging.getLogger(__name__)

@threat_bp.route('/scan', methods=['POST'])
def scan_content():
    """Scan arbitrary content for threats"""
    try:
        data = request.get_json()
        
        if not data or 'content' not in data:
            return jsonify({'error': 'No content provided'}), 400
        
        content = data['content']
        content_type = data.get('content_type', 'text')
        setup_rules = data.get('setup_rules', [])
        
        # Create mock email data for analysis
        mock_email_data = {
            'body': {
                'plain': content if content_type == 'text' else '',
                'html': content if content_type == 'html' else '',
                'parts': [{'content_type': f'text/{content_type}', 'content': content}]
            },
            'headers': {},
            'attachments': [],
            'raw_content': content,
            'format': 'text'
        }
        
        # Analyze content
        analysis_result = threat_detector.analyze_email(mock_email_data, setup_rules)
        
        return jsonify({
            'status': 'success',
            'message': 'Content scanned successfully',
            'data': analysis_result
        })
        
    except Exception as e:
        logger.error(f"Content scan error: {str(e)}")
        return jsonify({'error': 'Failed to scan content'}), 500

@threat_bp.route('/history', methods=['GET'])
def get_threat_history():
    """Get comprehensive threat detection history"""
    try:
        # Get query parameters
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))
        risk_level = request.args.get('risk_level')
        category = request.args.get('category')
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        
        # Get threat history
        history = db_manager.get_threat_history(
            limit=limit,
            offset=offset,
            risk_level=risk_level,
            date_from=date_from,
            date_to=date_to
        )
        
        # Add threat details for each email
        for email in history:
            threats = db_manager.get_threat_details(email['email_id'])
            email['threats'] = threats
        
        return jsonify({
            'status': 'success',
            'message': 'Threat history retrieved',
            'data': {
                'threats': history,
                'count': len(history),
                'pagination': {
                    'limit': limit,
                    'offset': offset,
                    'has_more': len(history) == limit
                },
                'filters': {
                    'risk_level': risk_level,
                    'category': category,
                    'date_from': date_from,
                    'date_to': date_to
                }
            }
        })
        
    except Exception as e:
        logger.error(f"Threat history error: {str(e)}")
        return jsonify({'error': 'Failed to get threat history'}), 500

@threat_bp.route('/statistics', methods=['GET'])
def get_threat_statistics():
    """Get comprehensive threat statistics"""
    try:
        # Get time period
        period = request.args.get('period', '30d')  # 7d, 30d, 90d, 1y
        
        # Get platform statistics
        stats = db_manager.get_platform_statistics()
        
        # Calculate additional metrics
        if stats.get('daily_stats'):
            # Calculate trends
            recent_stats = stats['daily_stats'][:7]  # Last 7 days
            if len(recent_stats) > 1:
                current_avg = sum(day.get('threats_detected', 0) for day in recent_stats[:3]) / 3
                previous_avg = sum(day.get('threats_detected', 0) for day in recent_stats[3:6]) / 3
                
                if previous_avg > 0:
                    trend_percentage = ((current_avg - previous_avg) / previous_avg) * 100
                    stats['threat_trend'] = {
                        'percentage': round(trend_percentage, 2),
                        'direction': 'up' if trend_percentage > 0 else 'down' if trend_percentage < 0 else 'stable'
                    }
        
        # Add real-time metrics
        stats['realtime_metrics'] = {
            'active_quarantine_count': len(db_manager.get_quarantined_emails()),
            'alerts_today': db_manager.get_daily_alert_count(),
            'system_status': 'operational'
        }
        
        return jsonify({
            'status': 'success',
            'message': 'Statistics retrieved successfully',
            'data': stats
        })
        
    except Exception as e:
        logger.error(f"Statistics error: {str(e)}")
        return jsonify({'error': 'Failed to get statistics'}), 500

@threat_bp.route('/patterns', methods=['GET'])
def get_threat_patterns():
    """Get threat pattern analysis"""
    try:
        # Get threat patterns from database
        conn = db_manager.connect()
        cursor = conn.cursor(dictionary=True)
        
        # Most common threat types by time period
        cursor.execute("""
            SELECT 
                threat_type,
                severity,
                category,
                COUNT(*) as occurrence_count,
                AVG(CASE WHEN severity = 'critical' THEN 4
                         WHEN severity = 'high' THEN 3
                         WHEN severity = 'medium' THEN 2
                         ELSE 1 END) as avg_severity_score
            FROM detected_threats 
            WHERE detected_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
            GROUP BY threat_type, severity, category
            ORDER BY occurrence_count DESC
            LIMIT 20
        """)
        
        threat_patterns = cursor.fetchall()
        
        # Temporal patterns (threats by hour of day)
        cursor.execute("""
            SELECT 
                HOUR(detected_at) as hour,
                COUNT(*) as threat_count,
                AVG(CASE WHEN severity = 'critical' THEN 4
                         WHEN severity = 'high' THEN 3
                         WHEN severity = 'medium' THEN 2
                         ELSE 1 END) as avg_severity
            FROM detected_threats 
            WHERE detected_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            GROUP BY HOUR(detected_at)
            ORDER BY hour
        """)
        
        hourly_patterns = cursor.fetchall()
        
        # Sender domain analysis
        cursor.execute("""
            SELECT 
                SUBSTRING_INDEX(SUBSTRING_INDEX(sender_address, '@', -1), '>', 1) as domain,
                COUNT(*) as email_count,
                AVG(threat_score) as avg_threat_score,
                COUNT(CASE WHEN risk_level IN ('high', 'critical') THEN 1 END) as high_risk_count
            FROM email_analysis 
            WHERE sender_address != '' AND analysis_date >= DATE_SUB(NOW(), INTERVAL 30 DAY)
            GROUP BY domain
            HAVING email_count > 1
            ORDER BY avg_threat_score DESC
            LIMIT 15
        """)
        
        domain_patterns = cursor.fetchall()
        
        cursor.close()
        
        return jsonify({
            'status': 'success',
            'message': 'Threat patterns retrieved',
            'data': {
                'threat_patterns': threat_patterns,
                'hourly_patterns': hourly_patterns,
                'domain_patterns': domain_patterns,
                'analysis_period': '30 days',
                'generated_at': datetime.utcnow().isoformat()
            }
        })
        
    except Exception as e:
        logger.error(f"Pattern analysis error: {str(e)}")
        return jsonify({'error': 'Failed to get threat patterns'}), 500

@threat_bp.route('/alerts', methods=['GET'])
def get_threat_alerts():
    """Get active threat alerts"""
    try:
        # Get recent high-priority threats
        conn = db_manager.connect()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT 
                ea.email_id,
                ea.filename,
                ea.sender_address,
                ea.subject,
                ea.threat_score,
                ea.risk_level,
                ea.analysis_date,
                COUNT(dt.id) as threat_count,
                GROUP_CONCAT(DISTINCT dt.category) as categories
            FROM email_analysis ea
            LEFT JOIN detected_threats dt ON ea.email_id = dt.email_id
            WHERE ea.risk_level IN ('high', 'critical')
            AND ea.analysis_date >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            GROUP BY ea.email_id
            ORDER BY ea.threat_score DESC, ea.analysis_date DESC
            LIMIT 50
        """)
        
        alerts = cursor.fetchall()
        
        # Get system alerts
        cursor.execute("""
            SELECT 
                'pattern_spike' as alert_type,
                threat_type as alert_subject,
                COUNT(*) as occurrence_count,
                'High frequency of specific threat pattern detected' as alert_message,
                MAX(detected_at) as last_occurrence
            FROM detected_threats 
            WHERE detected_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
            GROUP BY threat_type
            HAVING COUNT(*) > 5
        """)
        
        system_alerts = cursor.fetchall()
        
        cursor.close()
        
        return jsonify({
            'status': 'success',
            'message': 'Threat alerts retrieved',
            'data': {
                'email_alerts': alerts,
                'system_alerts': system_alerts,
                'total_alerts': len(alerts) + len(system_alerts),
                'generated_at': datetime.utcnow().isoformat()
            }
        })
        
    except Exception as e:
        logger.error(f"Alerts retrieval error: {str(e)}")
        return jsonify({'error': 'Failed to get threat alerts'}), 500

@threat_bp.route('/quarantine', methods=['GET'])
def get_quarantine_status():
    """Get quarantine management information"""
    try:
        conn = db_manager.connect()
        cursor = conn.cursor(dictionary=True)
        
        # Get quarantined emails
        cursor.execute("""
            SELECT 
                q.*,
                ea.filename,
                ea.sender_address,
                ea.subject,
                ea.threat_score,
                ea.risk_level
            FROM quarantine q
            JOIN email_analysis ea ON q.email_id = ea.email_id
            WHERE q.status = 'quarantined'
            ORDER BY q.quarantine_date DESC
        """)
        
        quarantined_emails = cursor.fetchall()
        
        # Get quarantine statistics
        cursor.execute("""
            SELECT 
                status,
                COUNT(*) as count
            FROM quarantine
            GROUP BY status
        """)
        
        status_counts = {row['status']: row['count'] for row in cursor.fetchall()}
        
        # Get recent quarantine activity
        cursor.execute("""
            SELECT 
                DATE(quarantine_date) as date,
                COUNT(*) as quarantined_count
            FROM quarantine
            WHERE quarantine_date >= DATE_SUB(NOW(), INTERVAL 30 DAY)
            GROUP BY DATE(quarantine_date)
            ORDER BY date DESC
        """)
        
        quarantine_activity = cursor.fetchall()
        
        cursor.close()
        
        return jsonify({
            'status': 'success',
            'message': 'Quarantine status retrieved',
            'data': {
                'quarantined_emails': quarantined_emails,
                'statistics': {
                    'total_quarantined': status_counts.get('quarantined', 0),
                    'total_released': status_counts.get('released', 0),
                    'total_deleted': status_counts.get('deleted', 0)
                },
                'recent_activity': quarantine_activity
            }
        })
        
    except Exception as e:
        logger.error(f"Quarantine status error: {str(e)}")
        return jsonify({'error': 'Failed to get quarantine status'}), 500

@threat_bp.route('/export', methods=['POST'])
def export_threat_data():
    """Export threat data in various formats"""
    try:
        data = request.get_json()
        export_format = data.get('format', 'json')  # json, csv, pdf
        date_from = data.get('date_from')
        date_to = data.get('date_to')
        risk_level = data.get('risk_level')
        include_details = data.get('include_details', False)
        
        # Get threat data
        threats = db_manager.get_threat_history(
            limit=10000,  # Large limit for export
            offset=0,
            risk_level=risk_level,
            date_from=date_from,
            date_to=date_to
        )
        
        if export_format == 'csv':
            import csv
            import io
            
            output = io.StringIO()
            fieldnames = ['email_id', 'filename', 'sender_address', 'subject', 
                         'threat_score', 'risk_level', 'analysis_date']
            
            if include_details:
                fieldnames.extend(['threat_count', 'categories'])
            
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            
            for threat in threats:
                row = {field: threat.get(field, '') for field in fieldnames}
                writer.writerow(row)
            
            csv_content = output.getvalue()
            output.close()
            
            return jsonify({
                'status': 'success',
                'message': 'Data exported as CSV',
                'data': {
                    'content': csv_content,
                    'filename': f'threat_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv',
                    'record_count': len(threats)
                }
            })
        
        else:  # JSON format
            return jsonify({
                'status': 'success',
                'message': 'Data exported as JSON',
                'data': {
                    'threats': threats,
                    'metadata': {
                        'export_date': datetime.utcnow().isoformat(),
                        'record_count': len(threats),
                        'filters': {
                            'date_from': date_from,
                            'date_to': date_to,
                            'risk_level': risk_level
                        }
                    }
                }
            })
        
    except Exception as e:
        logger.error(f"Export error: {str(e)}")
        return jsonify({'error': 'Failed to export data'}), 500

@threat_bp.route('/rules', methods=['GET'])
def get_detection_rules():
    """Get active detection rules"""
    try:
        rules = db_manager.get_setup_rules(active_only=True)
        
        return jsonify({
            'status': 'success',
            'message': 'Detection rules retrieved',
            'data': {
                'rules': rules,
                'count': len(rules)
            }
        })
        
    except Exception as e:
        logger.error(f"Rules retrieval error: {str(e)}")
        return jsonify({'error': 'Failed to get detection rules'}), 500

@threat_bp.route('/rules', methods=['POST'])
def create_detection_rule():
    """Create new detection rule"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No rule data provided'}), 400
        
        # Validate required fields
        required_fields = ['phrase', 'severity']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Create rule
        rule = {
            'name': data.get('name', f'Custom Rule {datetime.now().strftime("%Y%m%d_%H%M%S")}'),
            'start_segment': data.get('start_segment', '<body'),
            'end_segment': data.get('end_segment', '</body>'),
            'phrase': data['phrase'],
            'type': data.get('type', 'single_line'),
            'severity': data['severity'],
            'is_active': data.get('is_active', True)
        }
        
        # Save rule
        success = db_manager.save_setup_rules([rule])
        
        if success:
            return jsonify({
                'status': 'success',
                'message': 'Detection rule created successfully',
                'data': rule
            })
        else:
            return jsonify({'error': 'Failed to create rule'}), 500
        
    except Exception as e:
        logger.error(f"Rule creation error: {str(e)}")
        return jsonify({'error': 'Failed to create detection rule'}), 500

@threat_bp.route('/test-rule', methods=['POST'])
def test_detection_rule():
    """Test detection rule against sample content"""
    try:
        data = request.get_json()
        
        if not data or 'rule' not in data or 'content' not in data:
            return jsonify({'error': 'Rule and content required'}), 400
        
        rule = data['rule']
        content = data['content']
        
        # Create mock email data
        mock_email_data = {
            'body': {'plain': content, 'html': '', 'parts': []},
            'headers': {},
            'attachments': [],
            'raw_content': content,
            'format': 'text'
        }
        
        # Test rule
        threats = threat_detector._apply_setup_rules(mock_email_data, [rule])
        
        return jsonify({
            'status': 'success',
            'message': 'Rule tested successfully',
            'data': {
                'matches': len(threats) > 0,
                'threats_detected': threats,
                'rule': rule
            }
        })
        
    except Exception as e:
        logger.error(f"Rule test error: {str(e)}")
        return jsonify({'error': 'Failed to test rule'}), 500

