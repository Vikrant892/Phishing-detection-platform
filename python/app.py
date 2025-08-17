#!/usr/bin/env python3
"""
Advanced Cybersecurity Phishing Detection Platform - Python Backend API
Main Flask application with comprehensive email analysis and threat detection
"""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os
import json
import logging
from datetime import datetime, timedelta
import pandas as pd
import mysql.connector
from mysql.connector import Error
import redis
import hashlib
import uuid
from email_parser import EmailParser
from threat_detector import ThreatDetector
from models import Database, EmailAnalysis, ThreatPattern
from config import Config
from utils import generate_report, validate_file_type, sanitize_input
import traceback

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)
CORS(app)

# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('../logs/app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize components
db = Database()
email_parser = EmailParser()
threat_detector = ThreatDetector()

# Initialize Redis for caching
try:
    redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
    redis_client.ping()
    logger.info("Redis connection established")
except Exception as e:
    logger.warning(f"Redis connection failed: {e}")
    redis_client = None

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        db.test_connection()
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'services': {
                'database': 'connected',
                'redis': 'connected' if redis_client else 'disconnected'
            }
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500

@app.route('/api/upload-setup', methods=['POST'])
def upload_setup_file():
    """Upload and process setup file with threat patterns"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not validate_file_type(file.filename, ['csv', 'xlsx', 'json']):
            return jsonify({'error': 'Invalid file type. Supported: CSV, Excel, JSON'}), 400
        
        filename = secure_filename(file.filename)
        filepath = os.path.join('../uploads', filename)
        file.save(filepath)
        
        # Process the setup file
        patterns_added = threat_detector.load_patterns_from_file(filepath)
        
        # Cache the patterns
        if redis_client:
            redis_client.setex('threat_patterns_updated', 3600, datetime.now().isoformat())
        
        logger.info(f"Setup file processed: {patterns_added} patterns added")
        
        return jsonify({
            'success': True,
            'message': f'Setup file processed successfully. {patterns_added} patterns added.',
            'patterns_count': patterns_added
        })
        
    except Exception as e:
        logger.error(f"Setup file upload error: {e}")
        return jsonify({'error': f'Failed to process setup file: {str(e)}'}), 500

@app.route('/api/analyze-email', methods=['POST'])
def analyze_email():
    """Analyze a single email for phishing threats"""
    try:
        analysis_id = str(uuid.uuid4())
        
        if 'file' in request.files:
            # File upload
            file = request.files['file']
            if not validate_file_type(file.filename, ['eml', 'msg', 'txt']):
                return jsonify({'error': 'Invalid file type. Supported: EML, MSG, TXT'}), 400
            
            filename = secure_filename(file.filename)
            filepath = os.path.join('../uploads', filename)
            file.save(filepath)
            
            # Parse email from file
            email_data = email_parser.parse_file(filepath)
            
        elif 'email_content' in request.json:
            # Raw email content
            email_content = sanitize_input(request.json['email_content'])
            email_data = email_parser.parse_content(email_content)
            
        else:
            return jsonify({'error': 'No email provided'}), 400
        
        if not email_data:
            return jsonify({'error': 'Failed to parse email'}), 400
        
        # Perform threat analysis
        analysis_result = threat_detector.analyze_email(email_data)
        
        # Calculate threat score
        threat_score = threat_detector.calculate_threat_score(analysis_result)
        
        # Determine risk level
        risk_level = 'LOW'
        if threat_score >= 70:
            risk_level = 'HIGH'
        elif threat_score >= 40:
            risk_level = 'MEDIUM'
        
        # Store analysis in database
        analysis_record = EmailAnalysis(
            analysis_id=analysis_id,
            email_subject=email_data.get('subject', ''),
            email_sender=email_data.get('from', ''),
            threat_score=threat_score,
            risk_level=risk_level,
            threats_found=len(analysis_result['threats']),
            analysis_data=json.dumps(analysis_result),
            created_at=datetime.now()
        )
        
        db.save_analysis(analysis_record)
        
        # Cache recent analysis
        if redis_client:
            redis_client.setex(f'analysis:{analysis_id}', 3600, json.dumps({
                'threat_score': threat_score,
                'risk_level': risk_level,
                'timestamp': datetime.now().isoformat()
            }))
        
        logger.info(f"Email analysis completed: {analysis_id}, Score: {threat_score}")
        
        return jsonify({
            'analysis_id': analysis_id,
            'threat_score': threat_score,
            'risk_level': risk_level,
            'threats_found': len(analysis_result['threats']),
            'analysis_details': analysis_result,
            'email_metadata': {
                'subject': email_data.get('subject', ''),
                'sender': email_data.get('from', ''),
                'recipient': email_data.get('to', ''),
                'date': email_data.get('date', '')
            }
        })
        
    except Exception as e:
        logger.error(f"Email analysis error: {e}")
        traceback.print_exc()
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

@app.route('/api/bulk-analyze', methods=['POST'])
def bulk_analyze_emails():
    """Bulk analyze multiple emails"""
    try:
        if 'files' not in request.files:
            return jsonify({'error': 'No files provided'}), 400
        
        files = request.files.getlist('files')
        results = []
        processed = 0
        failed = 0
        
        for file in files:
            try:
                if not validate_file_type(file.filename, ['eml', 'msg', 'txt']):
                    failed += 1
                    continue
                
                filename = secure_filename(file.filename)
                filepath = os.path.join('../uploads', filename)
                file.save(filepath)
                
                # Parse and analyze email
                email_data = email_parser.parse_file(filepath)
                if email_data:
                    analysis_result = threat_detector.analyze_email(email_data)
                    threat_score = threat_detector.calculate_threat_score(analysis_result)
                    
                    results.append({
                        'filename': filename,
                        'threat_score': threat_score,
                        'threats_found': len(analysis_result['threats']),
                        'risk_level': 'HIGH' if threat_score >= 70 else 'MEDIUM' if threat_score >= 40 else 'LOW'
                    })
                    processed += 1
                else:
                    failed += 1
                    
            except Exception as e:
                logger.error(f"Failed to process {file.filename}: {e}")
                failed += 1
        
        return jsonify({
            'processed': processed,
            'failed': failed,
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Bulk analysis error: {e}")
        return jsonify({'error': f'Bulk analysis failed: {str(e)}'}), 500

@app.route('/api/dashboard-stats', methods=['GET'])
def get_dashboard_stats():
    """Get real-time dashboard statistics"""
    try:
        # Check cache first
        cache_key = 'dashboard_stats'
        if redis_client:
            cached_stats = redis_client.get(cache_key)
            if cached_stats:
                return jsonify(json.loads(cached_stats))
        
        # Get statistics from database
        stats = db.get_dashboard_stats()
        
        # Add real-time metrics
        current_time = datetime.now()
        stats.update({
            'last_updated': current_time.isoformat(),
            'system_status': 'operational',
            'active_threats': db.get_active_threats_count(),
            'recent_analyses': db.get_recent_analyses(limit=10)
        })
        
        # Cache for 5 minutes
        if redis_client:
            redis_client.setex(cache_key, 300, json.dumps(stats))
        
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"Dashboard stats error: {e}")
        return jsonify({'error': 'Failed to fetch dashboard statistics'}), 500

@app.route('/api/threat-patterns', methods=['GET'])
def get_threat_patterns():
    """Get all threat patterns"""
    try:
        patterns = db.get_threat_patterns()
        return jsonify({
            'patterns': patterns,
            'total_count': len(patterns)
        })
    except Exception as e:
        logger.error(f"Get threat patterns error: {e}")
        return jsonify({'error': 'Failed to fetch threat patterns'}), 500

@app.route('/api/threat-patterns', methods=['POST'])
def add_threat_pattern():
    """Add new threat pattern"""
    try:
        data = request.json
        pattern = ThreatPattern(
            segment_start=sanitize_input(data['segment_start']),
            segment_end=sanitize_input(data['segment_end']),
            pattern=sanitize_input(data['pattern']),
            description=sanitize_input(data.get('description', '')),
            severity=sanitize_input(data.get('severity', 'MEDIUM')),
            is_active=data.get('is_active', True)
        )
        
        pattern_id = db.add_threat_pattern(pattern)
        
        # Invalidate cache
        if redis_client:
            redis_client.delete('threat_patterns_updated')
        
        return jsonify({
            'success': True,
            'pattern_id': pattern_id,
            'message': 'Threat pattern added successfully'
        })
        
    except Exception as e:
        logger.error(f"Add threat pattern error: {e}")
        return jsonify({'error': f'Failed to add threat pattern: {str(e)}'}), 500

@app.route('/api/analysis-history', methods=['GET'])
def get_analysis_history():
    """Get analysis history with pagination"""
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
        risk_level = request.args.get('risk_level', None)
        
        history = db.get_analysis_history(page, per_page, risk_level)
        total_count = db.get_total_analyses_count(risk_level)
        
        return jsonify({
            'analyses': history,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total_count,
                'pages': (total_count + per_page - 1) // per_page
            }
        })
        
    except Exception as e:
        logger.error(f"Analysis history error: {e}")
        return jsonify({'error': 'Failed to fetch analysis history'}), 500

@app.route('/api/export-report', methods=['POST'])
def export_report():
    """Export analysis report in various formats"""
    try:
        data = request.json
        format_type = data.get('format', 'pdf').lower()
        date_from = data.get('date_from')
        date_to = data.get('date_to')
        risk_levels = data.get('risk_levels', [])
        
        # Generate report
        report_path = generate_report(format_type, date_from, date_to, risk_levels, db)
        
        if os.path.exists(report_path):
            return send_file(
                report_path,
                as_attachment=True,
                download_name=f'phishing_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.{format_type}'
            )
        else:
            return jsonify({'error': 'Failed to generate report'}), 500
            
    except Exception as e:
        logger.error(f"Export report error: {e}")
        return jsonify({'error': f'Failed to export report: {str(e)}'}), 500

@app.route('/api/quarantine', methods=['POST'])
def quarantine_email():
    """Quarantine suspicious email"""
    try:
        data = request.json
        analysis_id = sanitize_input(data['analysis_id'])
        reason = sanitize_input(data.get('reason', 'Suspicious content detected'))
        
        success = db.quarantine_email(analysis_id, reason)
        
        if success:
            logger.info(f"Email quarantined: {analysis_id}")
            return jsonify({
                'success': True,
                'message': 'Email quarantined successfully'
            })
        else:
            return jsonify({'error': 'Failed to quarantine email'}), 500
            
    except Exception as e:
        logger.error(f"Quarantine error: {e}")
        return jsonify({'error': f'Failed to quarantine email: {str(e)}'}), 500

@app.route('/api/search', methods=['GET'])
def search_analyses():
    """Search through email analyses"""
    try:
        query = sanitize_input(request.args.get('q', ''))
        search_type = request.args.get('type', 'all')  # all, subject, sender, content
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
        
        if not query:
            return jsonify({'error': 'Search query required'}), 400
        
        results = db.search_analyses(query, search_type, page, per_page)
        total_count = db.get_search_count(query, search_type)
        
        return jsonify({
            'results': results,
            'query': query,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total_count,
                'pages': (total_count + per_page - 1) // per_page
            }
        })
        
    except Exception as e:
        logger.error(f"Search error: {e}")
        return jsonify({'error': f'Search failed: {str(e)}'}), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # Create upload and log directories
    os.makedirs('../uploads', exist_ok=True)
    os.makedirs('../logs', exist_ok=True)
    
    logger.info("Starting Phishing Detection Platform API")
    app.run(host='0.0.0.0', port=8000, debug=False)
