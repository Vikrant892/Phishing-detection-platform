"""
Email API - RESTful endpoints for email analysis and management
"""

from flask import Blueprint, request, jsonify, current_app
import os
import logging
from werkzeug.utils import secure_filename
from datetime import datetime
import json

from models.email_parser import EmailParser
from models.threat_detector import ThreatDetector
from models.database_manager import DatabaseManager
from models.setup_file_manager import SetupFileManager

# Create blueprint
email_bp = Blueprint('email_api', __name__)

# Initialize components
email_parser = EmailParser()
threat_detector = ThreatDetector()
db_manager = DatabaseManager()
setup_manager = SetupFileManager()

logger = logging.getLogger(__name__)

@email_bp.route('/upload', methods=['POST'])
def upload_email():
    """Upload and parse email file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Validate file extension
        filename = secure_filename(file.filename)
        file_extension = os.path.splitext(filename)[1].lower()
        
        if file_extension not in ['.eml', '.msg', '.txt']:
            return jsonify({'error': f'Unsupported file format: {file_extension}'}), 400
        
        # Save uploaded file
        upload_dir = current_app.config.get('UPLOAD_FOLDER', 'uploads')
        os.makedirs(upload_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        unique_filename = f"{timestamp}_{filename}"
        filepath = os.path.join(upload_dir, unique_filename)
        
        file.save(filepath)
        
        # Parse email
        email_data = email_parser.parse_email_file(filepath)
        email_data['filename'] = filename
        email_data['filepath'] = filepath
        
        logger.info(f"Email uploaded and parsed: {filename}")
        
        return jsonify({
            'status': 'success',
            'message': 'Email uploaded and parsed successfully',
            'data': {
                'filename': filename,
                'email_id': email_data.get('email_id'),
                'format': email_data.get('format'),
                'parsed_date': email_data.get('parsed_date'),
                'metadata': email_data.get('metadata', {})
            }
        })
        
    except Exception as e:
        logger.error(f"Email upload error: {str(e)}")
        return jsonify({'error': 'Failed to upload email'}), 500

@email_bp.route('/analyze', methods=['POST'])
def analyze_email():
    """Analyze uploaded email for threats"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Get email data
        if 'filepath' in data:
            # Parse from file path
            email_data = email_parser.parse_email_file(data['filepath'])
        elif 'email_data' in data:
            # Use provided email data
            email_data = data['email_data']
        else:
            return jsonify({'error': 'No email data or filepath provided'}), 400
        
        # Get custom setup rules if provided
        setup_rules = data.get('setup_rules', [])
        use_database_rules = data.get('use_database_rules', True)
        
        # Load rules from database if requested
        if use_database_rules:
            db_rules = db_manager.get_setup_rules(active_only=True)
            setup_rules.extend(db_rules)
        
        # Perform threat analysis
        analysis_result = threat_detector.analyze_email(email_data, setup_rules)
        
        # Save to database
        try:
            email_id = db_manager.save_email_analysis(email_data, analysis_result)
            analysis_result['database_saved'] = True
        except Exception as db_error:
            logger.error(f"Database save error: {str(db_error)}")
            analysis_result['database_saved'] = False
        
        # Auto-quarantine if critical risk
        if analysis_result.get('risk_level') == 'critical':
            try:
                db_manager.quarantine_email(
                    analysis_result['email_id'],
                    'Auto-quarantined due to critical threat level',
                    'system'
                )
                analysis_result['quarantined'] = True
            except Exception as q_error:
                logger.error(f"Auto-quarantine error: {str(q_error)}")
                analysis_result['quarantined'] = False
        
        logger.info(f"Email analyzed: {analysis_result['email_id']}, Risk: {analysis_result['risk_level']}")
        
        return jsonify({
            'status': 'success',
            'message': 'Email analysis completed',
            'data': analysis_result
        })
        
    except Exception as e:
        logger.error(f"Email analysis error: {str(e)}")
        return jsonify({'error': 'Failed to analyze email'}), 500

@email_bp.route('/bulk-analyze', methods=['POST'])
def bulk_analyze_emails():
    """Analyze multiple emails in bulk"""
    try:
        data = request.get_json()
        
        if not data or 'filepaths' not in data:
            return jsonify({'error': 'No filepaths provided'}), 400
        
        filepaths = data['filepaths']
        setup_rules = data.get('setup_rules', [])
        use_database_rules = data.get('use_database_rules', True)
        
        # Load rules from database if requested
        if use_database_rules:
            db_rules = db_manager.get_setup_rules(active_only=True)
            setup_rules.extend(db_rules)
        
        results = []
        processed_count = 0
        error_count = 0
        
        for filepath in filepaths:
            try:
                # Parse email
                email_data = email_parser.parse_email_file(filepath)
                email_data['filename'] = os.path.basename(filepath)
                
                # Analyze threats
                analysis_result = threat_detector.analyze_email(email_data, setup_rules)
                
                # Save to database
                try:
                    db_manager.save_email_analysis(email_data, analysis_result)
                    analysis_result['database_saved'] = True
                except Exception as db_error:
                    logger.error(f"Database save error for {filepath}: {str(db_error)}")
                    analysis_result['database_saved'] = False
                
                results.append({
                    'filepath': filepath,
                    'status': 'success',
                    'analysis': analysis_result
                })
                
                processed_count += 1
                
            except Exception as e:
                logger.error(f"Bulk analysis error for {filepath}: {str(e)}")
                results.append({
                    'filepath': filepath,
                    'status': 'error',
                    'error': str(e)
                })
                error_count += 1
        
        return jsonify({
            'status': 'completed',
            'message': f'Bulk analysis completed. Processed: {processed_count}, Errors: {error_count}',
            'summary': {
                'total_files': len(filepaths),
                'processed': processed_count,
                'errors': error_count
            },
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Bulk analysis error: {str(e)}")
        return jsonify({'error': 'Bulk analysis failed'}), 500

@email_bp.route('/parse-segment', methods=['POST'])
def parse_email_segment():
    """Parse specific segment of email"""
    try:
        data = request.get_json()
        
        if not data or 'content' not in data:
            return jsonify({'error': 'No content provided'}), 400
        
        content = data['content']
        start_tag = data.get('start_tag', '<body')
        end_tag = data.get('end_tag', '</body>')
        
        # Extract segment content
        segments = email_parser.extract_segment_content(content, start_tag, end_tag)
        
        return jsonify({
            'status': 'success',
            'message': 'Segment parsed successfully',
            'data': {
                'segments': segments,
                'segment_count': len(segments)
            }
        })
        
    except Exception as e:
        logger.error(f"Segment parsing error: {str(e)}")
        return jsonify({'error': 'Failed to parse segment'}), 500

@email_bp.route('/validate-email', methods=['POST'])
def validate_email_format():
    """Validate email file format and structure"""
    try:
        data = request.get_json()
        
        if not data or 'filepath' not in data:
            return jsonify({'error': 'No filepath provided'}), 400
        
        filepath = data['filepath']
        
        if not os.path.exists(filepath):
            return jsonify({'error': 'File not found'}), 404
        
        validation_result = {
            'is_valid': False,
            'errors': [],
            'warnings': [],
            'file_info': {}
        }
        
        try:
            # Get file info
            validation_result['file_info'] = {
                'filename': os.path.basename(filepath),
                'size': os.path.getsize(filepath),
                'extension': os.path.splitext(filepath)[1].lower(),
                'modified': datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat()
            }
            
            # Try to parse email
            email_data = email_parser.parse_email_file(filepath)
            
            # Validate email structure
            if not email_data.get('headers'):
                validation_result['warnings'].append('No email headers found')
            
            if not email_data.get('body'):
                validation_result['warnings'].append('No email body found')
            
            if not email_data.get('headers', {}).get('from'):
                validation_result['errors'].append('No sender information found')
            
            if not email_data.get('headers', {}).get('subject'):
                validation_result['warnings'].append('No subject found')
            
            # Validation passed if no critical errors
            if len(validation_result['errors']) == 0:
                validation_result['is_valid'] = True
            
            validation_result['parsed_data'] = {
                'format': email_data.get('format'),
                'header_count': len(email_data.get('headers', {})),
                'body_parts': len(email_data.get('body', {}).get('parts', [])),
                'attachment_count': len(email_data.get('attachments', []))
            }
            
        except Exception as parse_error:
            validation_result['errors'].append(f'Parse error: {str(parse_error)}')
        
        return jsonify({
            'status': 'success',
            'message': 'Email validation completed',
            'data': validation_result
        })
        
    except Exception as e:
        logger.error(f"Email validation error: {str(e)}")
        return jsonify({'error': 'Failed to validate email'}), 500

@email_bp.route('/extract-content', methods=['POST'])
def extract_email_content():
    """Extract specific content from email"""
    try:
        data = request.get_json()
        
        if not data or 'filepath' not in data:
            return jsonify({'error': 'No filepath provided'}), 400
        
        filepath = data['filepath']
        content_type = data.get('content_type', 'all')  # all, headers, body, attachments
        
        # Parse email
        email_data = email_parser.parse_email_file(filepath)
        
        extracted_content = {}
        
        if content_type in ['all', 'headers']:
            extracted_content['headers'] = email_data.get('headers', {})
        
        if content_type in ['all', 'body']:
            extracted_content['body'] = email_data.get('body', {})
        
        if content_type in ['all', 'attachments']:
            extracted_content['attachments'] = email_data.get('attachments', [])
        
        if content_type in ['all', 'metadata']:
            extracted_content['metadata'] = email_data.get('metadata', {})
        
        if content_type in ['all', 'segments']:
            extracted_content['segments'] = email_data.get('segments', {})
        
        return jsonify({
            'status': 'success',
            'message': 'Content extracted successfully',
            'data': extracted_content
        })
        
    except Exception as e:
        logger.error(f"Content extraction error: {str(e)}")
        return jsonify({'error': 'Failed to extract content'}), 500

@email_bp.route('/search-content', methods=['POST'])
def search_email_content():
    """Search for specific patterns in email content"""
    try:
        data = request.get_json()
        
        if not data or 'filepath' not in data or 'pattern' not in data:
            return jsonify({'error': 'Filepath and pattern required'}), 400
        
        filepath = data['filepath']
        pattern = data['pattern']
        search_type = data.get('search_type', 'simple')  # simple, regex
        case_sensitive = data.get('case_sensitive', False)
        
        # Parse email
        email_data = email_parser.parse_email_file(filepath)
        
        search_results = []
        
        # Search in different parts of email
        content_parts = [
            ('headers', json.dumps(email_data.get('headers', {}))),
            ('plain_body', email_data.get('body', {}).get('plain', '')),
            ('html_body', email_data.get('body', {}).get('html', '')),
            ('raw_content', email_data.get('raw_content', ''))
        ]
        
        for part_name, content in content_parts:
            if not content:
                continue
            
            try:
                if search_type == 'regex':
                    import re
                    flags = 0 if case_sensitive else re.IGNORECASE
                    matches = list(re.finditer(pattern, content, flags))
                    
                    for match in matches:
                        # Find line number
                        line_num = content[:match.start()].count('\n') + 1
                        search_results.append({
                            'part': part_name,
                            'line_number': line_num,
                            'match': match.group(),
                            'start_pos': match.start(),
                            'end_pos': match.end(),
                            'context': content[max(0, match.start()-50):match.end()+50]
                        })
                
                else:  # Simple string search
                    search_content = content if case_sensitive else content.lower()
                    search_pattern = pattern if case_sensitive else pattern.lower()
                    
                    start = 0
                    while True:
                        pos = search_content.find(search_pattern, start)
                        if pos == -1:
                            break
                        
                        # Find line number
                        line_num = content[:pos].count('\n') + 1
                        search_results.append({
                            'part': part_name,
                            'line_number': line_num,
                            'match': content[pos:pos+len(pattern)],
                            'start_pos': pos,
                            'end_pos': pos + len(pattern),
                            'context': content[max(0, pos-50):pos+len(pattern)+50]
                        })
                        
                        start = pos + 1
            
            except Exception as search_error:
                logger.warning(f"Search error in {part_name}: {str(search_error)}")
        
        return jsonify({
            'status': 'success',
            'message': f'Search completed. Found {len(search_results)} matches.',
            'data': {
                'pattern': pattern,
                'search_type': search_type,
                'case_sensitive': case_sensitive,
                'match_count': len(search_results),
                'matches': search_results
            }
        })
        
    except Exception as e:
        logger.error(f"Content search error: {str(e)}")
        return jsonify({'error': 'Failed to search content'}), 500

@email_bp.route('/history', methods=['GET'])
def get_email_history():
    """Get email analysis history"""
    try:
        # Get query parameters
        limit = int(request.args.get('limit', 50))
        offset = int(request.args.get('offset', 0))
        risk_level = request.args.get('risk_level')
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        
        # Get history from database
        history = db_manager.get_threat_history(
            limit=limit,
            offset=offset,
            risk_level=risk_level,
            date_from=date_from,
            date_to=date_to
        )
        
        return jsonify({
            'status': 'success',
            'message': 'Email history retrieved',
            'data': {
                'emails': history,
                'count': len(history),
                'limit': limit,
                'offset': offset,
                'filters': {
                    'risk_level': risk_level,
                    'date_from': date_from,
                    'date_to': date_to
                }
            }
        })
        
    except Exception as e:
        logger.error(f"History retrieval error: {str(e)}")
        return jsonify({'error': 'Failed to get email history'}), 500

@email_bp.route('/details/<email_id>', methods=['GET'])
def get_email_details(email_id):
    """Get detailed email analysis"""
    try:
        # Get email analysis
        email_analysis = db_manager.get_email_analysis(email_id)
        if not email_analysis:
            return jsonify({'error': 'Email not found'}), 404
        
        # Get threat details
        threats = db_manager.get_threat_details(email_id)
        
        return jsonify({
            'status': 'success',
            'message': 'Email details retrieved',
            'data': {
                'email': email_analysis,
                'threats': threats
            }
        })
        
    except Exception as e:
        logger.error(f"Email details error: {str(e)}")
        return jsonify({'error': 'Failed to get email details'}), 500

@email_bp.route('/quarantine/<email_id>', methods=['POST'])
def quarantine_email(email_id):
    """Quarantine specific email"""
    try:
        data = request.get_json() or {}
        reason = data.get('reason', 'Manual quarantine')
        quarantined_by = data.get('quarantined_by', 'user')
        
        success = db_manager.quarantine_email(email_id, reason, quarantined_by)
        
        if success:
            return jsonify({
                'status': 'success',
                'message': 'Email quarantined successfully'
            })
        else:
            return jsonify({'error': 'Failed to quarantine email'}), 500
        
    except Exception as e:
        logger.error(f"Quarantine error: {str(e)}")
        return jsonify({'error': 'Failed to quarantine email'}), 500

@email_bp.route('/setup-rules/upload', methods=['POST'])
def upload_setup_rules():
    """Upload setup rules file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Save uploaded file
        filename = secure_filename(file.filename)
        upload_dir = current_app.config.get('UPLOAD_FOLDER', 'uploads')
        filepath = os.path.join(upload_dir, f"setup_{filename}")
        
        file.save(filepath)
        
        # Validate setup file
        validation = setup_manager.validate_setup_file(filepath)
        
        if not validation['is_valid']:
            return jsonify({
                'status': 'error',
                'message': 'Invalid setup file',
                'validation': validation
            }), 400
        
        # Load rules
        rules = setup_manager.load_setup_file(filepath)
        
        # Save to database
        success = db_manager.save_setup_rules(rules)
        
        if success:
            return jsonify({
                'status': 'success',
                'message': f'Setup rules uploaded successfully. {len(rules)} rules loaded.',
                'data': {
                    'rule_count': len(rules),
                    'validation': validation
                }
            })
        else:
            return jsonify({'error': 'Failed to save rules to database'}), 500
        
    except Exception as e:
        logger.error(f"Setup rules upload error: {str(e)}")
        return jsonify({'error': 'Failed to upload setup rules'}), 500
