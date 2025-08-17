#!/usr/bin/env python3
"""
Simplified Phishing Detection Platform - Python Backend API
Basic Flask application with email analysis capabilities
"""

from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os
import json
import logging
from datetime import datetime
import hashlib
import uuid
import email
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import traceback
import psycopg2
from psycopg2.extras import RealDictCursor
import re
from email_html_analyzer import EmailHTMLAnalyzer
from database_schema import db_manager
import traceback

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'REDACTED'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
CORS(app)

# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Database configuration
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://user:password@localhost:5432/phishing_detection')

# Allowed file extensions
ALLOWED_EXTENSIONS = {'eml', 'msg', 'txt', 'csv', 'xlsx', 'xls', 'json'}

# Initialize enhanced email analyzer
html_analyzer = EmailHTMLAnalyzer()

# Initialize database
try:
    db_manager.create_tables()
    logger.info("Database initialized successfully")
except Exception as e:
    logger.error(f"Database initialization failed: {e}")

def get_db_connection():
    """Get database connection"""
    try:
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        return None

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def analyze_email_content(content):
    """Simple email analysis function"""
    threat_score = 0
    threats_found = []
    
    # Basic threat patterns
    threat_patterns = {
        'urgent_words': ['urgent', 'immediate', 'act now', 'limited time', 'expires today'],
        'financial_words': ['wire transfer', 'bank account', 'credit card', 'payment', 'invoice'],
        'suspicious_links': [r'bit\.ly', r'tinyurl', r'shortened'],
        'phishing_indicators': ['verify your account', 'suspended', 'click here', 'update payment']
    }
    
    content_lower = content.lower()
    
    # Check for threat patterns
    for category, patterns in threat_patterns.items():
        for pattern in patterns:
            if isinstance(pattern, str):
                if pattern in content_lower:
                    threat_score += 15
                    threats_found.append(f"{category}: {pattern}")
            else:
                if re.search(pattern, content_lower):
                    threat_score += 20
                    threats_found.append(f"{category}: regex match")
    
    # Determine threat level
    if threat_score >= 70:
        threat_level = 'HIGH'
    elif threat_score >= 40:
        threat_level = 'MEDIUM'
    else:
        threat_level = 'LOW'
    
    return {
        'threat_score': min(threat_score, 100),
        'threat_level': threat_level,
        'threats_found': threats_found
    }

def parse_email_file(file_path):
    """Parse email file and extract content"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
        
        # Try to parse as email
        try:
            msg = email.message_from_string(content)
            subject = msg.get('Subject', 'No Subject')
            sender = msg.get('From', 'Unknown Sender')
            body = ""
            
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
            else:
                body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
        except:
            # If not a valid email, treat as plain text
            subject = "Plain Text File"
            sender = "Unknown"
            body = content
        
        return {
            'subject': subject,
            'sender': sender,
            'body': body,
            'raw_content': content
        }
    except Exception as e:
        logger.error(f"Error parsing email file: {e}")
        return None

@app.route('/')
def index():
    """Serve the main HTML interface"""
    return send_from_directory('static', 'index.html')

@app.route('/test_phishing_email.eml')
def download_test_phishing():
    """Serve test phishing email sample"""
    return send_from_directory('..', 'test_phishing_email.eml', as_attachment=True)

@app.route('/test_safe_email.eml')
def download_test_safe():
    """Serve test safe email sample"""
    return send_from_directory('..', 'test_safe_email.eml', as_attachment=True)

@app.route('/test_enhanced_phishing_email.eml')
def download_test_enhanced():
    """Serve enhanced test phishing email sample with headers"""
    return send_from_directory('..', 'test_enhanced_phishing_email.eml', as_attachment=True)

@app.route('/documentation.pdf')
def download_documentation():
    """Serve comprehensive PDF documentation"""
    return send_from_directory('.', 'Phishing_Detection_Platform_Documentation.pdf', as_attachment=True)

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        conn = get_db_connection()
        if conn:
            conn.close()
            db_status = 'connected'
        else:
            db_status = 'disconnected'
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'services': {
                'database': db_status,
                'api': 'running'
            }
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Upload and analyze email file with enhanced HTML analysis"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '' or not file.filename:
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed'}), 400
        
        # Save uploaded file
        filename = secure_filename(file.filename)
        upload_dir = '../uploads'
        os.makedirs(upload_dir, exist_ok=True)
        file_path = os.path.join(upload_dir, filename)
        file.save(file_path)
        
        try:
            # Check if it's an .eml file for enhanced analysis
            if filename.lower().endswith('.eml'):
                try:
                    # Use enhanced HTML analyzer for .eml files
                    analysis_results = html_analyzer.analyze_email_file(file_path)
                    
                    if not analysis_results['success']:
                        # Save failure to database
                        db_manager.save_analysis_failure(
                            filename=filename,
                            failure_reason=analysis_results['error'],
                            failure_location="HTML Analysis",
                            failure_type="ANALYSIS_ERROR"
                        )
                        return jsonify({'error': analysis_results['error']}), 400
                    
                    # Format result for frontend
                    analysis_id = str(uuid.uuid4())
                    result = {
                        'analysis_id': analysis_id,
                        'filename': filename,
                        'subject': analysis_results['email_info']['subject'],
                        'sender': analysis_results['email_info']['sender'],
                        'recipient': analysis_results['email_info']['recipient'],
                        'date': analysis_results['email_info']['date'],
                        'threat_score': analysis_results['threat_score'],
                        'threat_level': 'HIGH' if analysis_results['threat_score'] >= 70 else 
                                       'MEDIUM' if analysis_results['threat_score'] >= 40 else 'LOW',
                        'overall_status': analysis_results['overall_status'],
                        'threats_found': [f"{t['category']}: {t['pattern']}" for t in analysis_results['threats_found']],
                        'html_segments': analysis_results['html_segments'],
                        'analyzed_at': datetime.now().isoformat(),
                        'status': 'completed',
                        'analysis_type': 'enhanced_html'
                    }
                    
                    # Save complete analysis to database
                    db_data = {
                        'analysis_id': analysis_id,
                        'filename': filename,
                        'subject': analysis_results['email_info']['subject'],
                        'sender': analysis_results['email_info']['sender'],
                        'recipient': analysis_results['email_info']['recipient'],
                        'email_date': analysis_results['email_info']['date'],
                        'threat_score': analysis_results['threat_score'],
                        'threat_level': result['threat_level'],
                        'overall_status': analysis_results['overall_status'],
                        'analysis_type': 'enhanced_html',
                        'total_segments': len(analysis_results['html_segments']),
                        'total_threats': len(analysis_results['threats_found']),
                        'headers': analysis_results.get('headers', {}),
                        'html_segments': analysis_results['html_segments']
                    }
                    
                    try:
                        db_manager.save_email_analysis(db_data)
                        logger.info(f"Saved analysis results to database for {filename}")
                    except Exception as db_e:
                        logger.error(f"Failed to save to database: {db_e}")
                        # Continue even if database save fails
                
                except Exception as analysis_e:
                    # Save detailed failure information
                    db_manager.save_analysis_failure(
                        filename=filename,
                        failure_reason=str(analysis_e),
                        failure_location="Enhanced HTML Analysis",
                        error_details=str(analysis_e),
                        stack_trace=traceback.format_exc(),
                        failure_type="ANALYSIS_EXCEPTION"
                    )
                    logger.error(f"Enhanced analysis failed for {filename}: {analysis_e}")
                    
                    # Fall back to basic analysis
                    email_data = parse_email_file(file_path)
                    if not email_data:
                        return jsonify({'error': 'Failed to parse email file'}), 400
                    
                    analysis = analyze_email_content(email_data['body'])
                    
                    result = {
                        'analysis_id': str(uuid.uuid4()),
                        'filename': filename,
                        'subject': email_data['subject'],
                        'sender': email_data['sender'],
                        'threat_score': analysis['threat_score'],
                        'threat_level': analysis['threat_level'],
                        'threats_found': analysis['threats_found'],
                        'analyzed_at': datetime.now().isoformat(),
                        'status': 'completed',
                        'analysis_type': 'basic_fallback'
                    }
            else:
                # Use basic analysis for other file types
                email_data = parse_email_file(file_path)
                if not email_data:
                    return jsonify({'error': 'Failed to parse email file'}), 400
                
                analysis = analyze_email_content(email_data['body'])
                
                result = {
                    'analysis_id': str(uuid.uuid4()),
                    'filename': filename,
                    'subject': email_data['subject'],
                    'sender': email_data['sender'],
                    'threat_score': analysis['threat_score'],
                    'threat_level': analysis['threat_level'],
                    'threats_found': analysis['threats_found'],
                    'analyzed_at': datetime.now().isoformat(),
                    'status': 'completed',
                    'analysis_type': 'basic'
                }
        
        finally:
            # Clean up uploaded file
            try:
                os.remove(file_path)
            except:
                pass
        
        return jsonify({
            'success': True,
            'data': result
        })
    
    except Exception as e:
        logger.error(f"Upload analysis failed: {e}")
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

@app.route('/api/dashboard-stats', methods=['GET'])
def dashboard_stats():
    """Get dashboard statistics from database"""
    try:
        stats = db_manager.get_dashboard_stats()
        return jsonify({
            'success': True,
            'data': stats
        })
    
    except Exception as e:
        logger.error(f"Dashboard stats failed: {e}")
        return jsonify({'error': 'Failed to retrieve dashboard statistics'}), 500

@app.route('/api/threat-statistics', methods=['GET'])
def threat_statistics():
    """Get threat occurrence statistics"""
    try:
        threat_stats = db_manager.get_threat_statistics()
        return jsonify({
            'success': True,
            'data': threat_stats
        })
    
    except Exception as e:
        logger.error(f"Threat statistics failed: {e}")
        return jsonify({'error': 'Failed to retrieve threat statistics'}), 500

@app.route('/api/failure-statistics', methods=['GET'])
def failure_statistics():
    """Get analysis failure statistics"""
    try:
        failure_stats = db_manager.get_failure_statistics()
        return jsonify({
            'success': True,
            'data': failure_stats
        })
    
    except Exception as e:
        logger.error(f"Failure statistics failed: {e}")
        return jsonify({'error': 'Failed to retrieve failure statistics'}), 500

@app.route('/api/threat-patterns', methods=['GET'])
def get_threat_patterns():
    """Get threat patterns"""
    patterns = [
        {
            'id': 1,
            'name': 'Urgent Action Required',
            'pattern': 'urgent|immediate|act now',
            'risk_level': 'HIGH',
            'active': True
        },
        {
            'id': 2,
            'name': 'Financial Information Request',
            'pattern': 'bank account|credit card|payment',
            'risk_level': 'MEDIUM',
            'active': True
        }
    ]
    
    return jsonify({
        'success': True,
        'data': patterns
    })

@app.route('/api/detailed-report', methods=['POST'])
def get_detailed_report():
    """Get detailed HTML analysis report for an .eml file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if not file.filename or not file.filename.lower().endswith('.eml'):
            return jsonify({'error': 'Please provide a .eml email file'}), 400
        
        # Save uploaded file temporarily
        filename = secure_filename(file.filename)
        upload_dir = '../uploads'
        os.makedirs(upload_dir, exist_ok=True)
        file_path = os.path.join(upload_dir, filename)
        file.save(file_path)
        
        try:
            # Analyze the email file
            analysis_results = html_analyzer.analyze_email_file(file_path)
            
            if not analysis_results['success']:
                return jsonify({'error': analysis_results['error']}), 400
            
            # Generate detailed report
            report = html_analyzer.format_analysis_report(analysis_results)
            
            return jsonify({
                'success': True,
                'data': {
                    'filename': filename,
                    'report': report,
                    'analysis_results': analysis_results
                }
            })
        
        finally:
            # Clean up
            try:
                os.remove(file_path)
            except:
                pass
    
    except Exception as e:
        logger.error(f"Detailed report generation failed: {e}")
        return jsonify({'error': f'Report generation failed: {str(e)}'}), 500

@app.route('/api/analyze-text', methods=['POST'])
def analyze_text():
    """Analyze text content directly"""
    try:
        data = request.get_json()
        if not data or 'content' not in data:
            return jsonify({'error': 'No content provided'}), 400
        
        content = data['content']
        analysis = analyze_email_content(content)
        
        result = {
            'analysis_id': str(uuid.uuid4()),
            'threat_score': analysis['threat_score'],
            'threat_level': analysis['threat_level'],
            'threats_found': analysis['threats_found'],
            'analyzed_at': datetime.now().isoformat()
        }
        
        return jsonify({
            'success': True,
            'data': result
        })
    
    except Exception as e:
        logger.error(f"Text analysis failed: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Ensure upload directory exists
    os.makedirs('../uploads', exist_ok=True)
    os.makedirs('../logs', exist_ok=True)
    
    logger.info("Starting Phishing Detection Platform API...")
    app.run(host='0.0.0.0', port=5000, debug=True)