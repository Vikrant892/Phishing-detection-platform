"""
API Routes - RESTful endpoints for the phishing detection platform
"""

from flask import Blueprint, request, jsonify, send_file, current_app
import os
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List

from services.file_processor import FileProcessor
from services.email_parser import EmailParser
from models.email_analyzer import EmailAnalyzer
from models.database_manager import DatabaseManager
from utils.helpers import create_response, validate_request_data, require_auth

logger = logging.getLogger(__name__)

# Create API blueprint
api_bp = Blueprint('api', __name__)

# Initialize services
file_processor = FileProcessor()
email_parser = EmailParser()
db_manager = DatabaseManager()
email_analyzer = EmailAnalyzer(db_manager)

@api_bp.route('/docs', methods=['GET'])
def api_documentation():
    """API documentation endpoint"""
    docs = {
        "api_version": "1.0.0",
        "description": "Advanced Cybersecurity Phishing Detection Platform API",
        "endpoints": {
            "Email Analysis": {
                "/analyze/upload": {
                    "method": "POST",
                    "description": "Upload and analyze email file",
                    "parameters": {
                        "file": "Email file (.eml, .msg, .txt)",
                        "options": "Analysis options (optional)"
                    }
                },
                "/analyze/content": {
                    "method": "POST", 
                    "description": "Analyze email content directly",
                    "parameters": {
                        "content": "Raw email content",
                        "content_type": "Content type (eml, msg, txt)"
                    }
                },
                "/analyze/batch": {
                    "method": "POST",
                    "description": "Batch analyze multiple files",
                    "parameters": {
                        "files": "Array of email files or archive"
                    }
                }
            },
            "Results & Reports": {
                "/results/{analysis_id}": {
                    "method": "GET",
                    "description": "Get analysis result by ID"
                },
                "/results/recent": {
                    "method": "GET",
                    "description": "Get recent analysis results"
                },
                "/statistics": {
                    "method": "GET",
                    "description": "Get threat statistics"
                },
                "/export": {
                    "method": "POST",
                    "description": "Export analysis results"
                }
            },
            "Threat Management": {
                "/threats/patterns": {
                    "method": "GET",
                    "description": "Get threat patterns"
                },
                "/threats/quarantine": {
                    "method": "POST",
                    "description": "Add email to quarantine"
                },
                "/reputation/sender": {
                    "method": "GET",
                    "description": "Get sender reputation"
                }
            }
        }
    }
    return create_response(success=True, message="API Documentation", data=docs)

# Email Analysis Endpoints
@api_bp.route('/analyze/upload', methods=['POST'])
def analyze_upload():
    """Upload and analyze email file"""
    try:
        if 'file' not in request.files:
            return create_response(
                success=False,
                message="No file provided",
                error="File parameter is required"
            ), 400
        
        file = request.files['file']
        if file.filename == '':
            return create_response(
                success=False,
                message="No file selected",
                error="Empty filename"
            ), 400
        
        # Get analysis options
        options = request.form.get('options', '{}')
        try:
            analysis_options = json.loads(options)
        except:
            analysis_options = {}
        
        # Save uploaded file
        file_data = file.read()
        save_result = file_processor.save_uploaded_file(file_data, file.filename)
        
        if not save_result['success']:
            return jsonify(save_result), 400
        
        # Process the file
        file_path = save_result['data']['file_path']
        original_filename = save_result['data']['original_filename']
        
        process_result = file_processor.process_single_file(file_path, original_filename)
        
        # Clean up uploaded file if processing failed
        if not process_result['success']:
            try:
                os.remove(file_path)
            except:
                pass
        
        return jsonify(process_result)
        
    except Exception as e:
        logger.error(f"Upload analysis failed: {str(e)}")
        return create_response(
            success=False,
            message="Upload analysis failed",
            error=str(e)
        ), 500

@api_bp.route('/analyze/content', methods=['POST'])
def analyze_content():
    """Analyze email content directly"""
    try:
        data = request.get_json()
        if not data:
            return create_response(
                success=False,
                message="No data provided",
                error="JSON body is required"
            ), 400
        
        validation = validate_request_data(data, ['content'])
        if not validation['valid']:
            return jsonify(validation['response']), 400
        
        content = data['content']
        content_type = data.get('content_type', 'eml')
        
        # Parse email content
        parsed_email = email_parser.parse_email_content(content, content_type)
        
        # Analyze for threats
        analysis_result = email_analyzer.analyze_email(content)
        
        return create_response(
            success=True,
            message="Email content analysis completed",
            data=analysis_result
        )
        
    except Exception as e:
        logger.error(f"Content analysis failed: {str(e)}")
        return create_response(
            success=False,
            message="Content analysis failed",
            error=str(e)
        ), 500

@api_bp.route('/analyze/batch', methods=['POST'])
def analyze_batch():
    """Batch analyze multiple files or archive"""
    try:
        if 'files' not in request.files and 'archive' not in request.files:
            return create_response(
                success=False,
                message="No files provided",
                error="Either 'files' or 'archive' parameter is required"
            ), 400
        
        # Handle archive upload
        if 'archive' in request.files:
            archive_file = request.files['archive']
            if archive_file.filename == '':
                return create_response(
                    success=False,
                    message="No archive selected",
                    error="Empty archive filename"
                ), 400
            
            # Save archive
            archive_data = archive_file.read()
            save_result = file_processor.save_uploaded_file(archive_data, archive_file.filename)
            
            if not save_result['success']:
                return jsonify(save_result), 400
            
            # Process archive
            archive_path = save_result['data']['file_path']
            result = file_processor.process_archive_file(archive_path)
            
            return jsonify(result)
        
        # Handle multiple files
        files = request.files.getlist('files')
        if not files:
            return create_response(
                success=False,
                message="No files provided",
                error="At least one file is required"
            ), 400
        
        # Save all files and collect paths
        file_paths = []
        saved_files = []
        
        try:
            for file in files:
                if file.filename:
                    file_data = file.read()
                    save_result = file_processor.save_uploaded_file(file_data, file.filename)
                    
                    if save_result['success']:
                        file_paths.append(save_result['data']['file_path'])
                        saved_files.append(save_result['data'])
            
            if not file_paths:
                return create_response(
                    success=False,
                    message="No valid files uploaded",
                    error="All file uploads failed"
                ), 400
            
            # Start batch processing
            job_id = file_processor.process_batch_files(file_paths)
            
            return create_response(
                success=True,
                message=f"Batch processing started with {len(file_paths)} files",
                data={
                    'job_id': job_id,
                    'total_files': len(file_paths),
                    'uploaded_files': saved_files
                }
            )
            
        except Exception as e:
            # Clean up any saved files on error
            for file_data in saved_files:
                try:
                    os.remove(file_data['file_path'])
                except:
                    pass
            raise
        
    except Exception as e:
        logger.error(f"Batch analysis failed: {str(e)}")
        return create_response(
            success=False,
            message="Batch analysis failed",
            error=str(e)
        ), 500

@api_bp.route('/analyze/status/<job_id>', methods=['GET'])
def get_batch_status(job_id):
    """Get batch processing status"""
    try:
        result = file_processor.get_job_status(job_id)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Failed to get job status: {str(e)}")
        return create_response(
            success=False,
            message="Failed to get job status",
            error=str(e)
        ), 500

# Results & Reports Endpoints
@api_bp.route('/results/<email_hash>', methods=['GET'])
def get_analysis_result(email_hash):
    """Get analysis result by email hash"""
    try:
        result = db_manager.get_analysis_by_hash(email_hash)
        
        if not result:
            return create_response(
                success=False,
                message="Analysis not found",
                error=f"No analysis found for hash {email_hash}"
            ), 404
        
        return create_response(
            success=True,
            message="Analysis result retrieved",
            data=result
        )
        
    except Exception as e:
        logger.error(f"Failed to get analysis result: {str(e)}")
        return create_response(
            success=False,
            message="Failed to retrieve analysis result",
            error=str(e)
        ), 500

@api_bp.route('/results/recent', methods=['GET'])
def get_recent_results():
    """Get recent analysis results"""
    try:
        limit = request.args.get('limit', 50, type=int)
        offset = request.args.get('offset', 0, type=int)
        threat_level = request.args.get('threat_level', None)
        
        # Get recent analyses
        analyses = db_manager.get_recent_analyses(limit + offset)
        
        # Apply filters
        if threat_level:
            analyses = [a for a in analyses if a.get('threat_level') == threat_level]
        
        # Apply pagination
        paginated_analyses = analyses[offset:offset + limit]
        
        return create_response(
            success=True,
            message="Recent results retrieved",
            data={
                'analyses': paginated_analyses,
                'total': len(analyses),
                'limit': limit,
                'offset': offset
            }
        )
        
    except Exception as e:
        logger.error(f"Failed to get recent results: {str(e)}")
        return create_response(
            success=False,
            message="Failed to retrieve recent results",
            error=str(e)
        ), 500

@api_bp.route('/statistics', methods=['GET'])
def get_statistics():
    """Get threat statistics"""
    try:
        days = request.args.get('days', 30, type=int)
        
        stats = db_manager.get_threat_statistics(days)
        
        # Add additional calculated metrics
        if stats.get('total_emails', 0) > 0:
            stats['detection_rate'] = (stats.get('threat_emails', 0) / stats['total_emails']) * 100
        else:
            stats['detection_rate'] = 0
        
        # Get top threat types
        stats['top_threat_types'] = self._get_top_threat_types(days)
        
        # Get daily trend
        stats['daily_trend'] = self._get_daily_trend(days)
        
        return create_response(
            success=True,
            message="Statistics retrieved",
            data=stats
        )
        
    except Exception as e:
        logger.error(f"Failed to get statistics: {str(e)}")
        return create_response(
            success=False,
            message="Failed to retrieve statistics",
            error=str(e)
        ), 500

@api_bp.route('/export', methods=['POST'])
def export_results():
    """Export analysis results"""
    try:
        data = request.get_json()
        if not data:
            return create_response(
                success=False,
                message="No data provided",
                error="JSON body is required"
            ), 400
        
        analysis_ids = data.get('analysis_ids', [])
        format_type = data.get('format', 'json')
        
        if not analysis_ids:
            return create_response(
                success=False,
                message="No analysis IDs provided",
                error="analysis_ids parameter is required"
            ), 400
        
        # Export results
        result = file_processor.export_analysis_results(analysis_ids, format_type)
        
        if result['success']:
            export_path = result['data']['export_path']
            filename = result['data']['filename']
            
            return send_file(
                export_path,
                as_attachment=True,
                download_name=filename,
                mimetype='application/octet-stream'
            )
        else:
            return jsonify(result), 400
        
    except Exception as e:
        logger.error(f"Export failed: {str(e)}")
        return create_response(
            success=False,
            message="Export failed",
            error=str(e)
        ), 500

# Threat Management Endpoints
@api_bp.route('/threats/patterns', methods=['GET'])
def get_threat_patterns():
    """Get threat patterns"""
    try:
        patterns = db_manager.get_custom_threat_patterns()
        
        return create_response(
            success=True,
            message="Threat patterns retrieved",
            data={
                'patterns': patterns,
                'total': len(patterns)
            }
        )
        
    except Exception as e:
        logger.error(f"Failed to get threat patterns: {str(e)}")
        return create_response(
            success=False,
            message="Failed to retrieve threat patterns",
            error=str(e)
        ), 500

@api_bp.route('/threats/patterns', methods=['POST'])
def add_threat_pattern():
    """Add new threat pattern"""
    try:
        data = request.get_json()
        if not data:
            return create_response(
                success=False,
                message="No data provided",
                error="JSON body is required"
            ), 400
        
        validation = validate_request_data(data, ['name', 'pattern_text'])
        if not validation['valid']:
            return jsonify(validation['response']), 400
        
        # Add pattern to database
        result = db_manager.add_threat_pattern(data)
        
        return create_response(
            success=True,
            message="Threat pattern added successfully",
            data=result
        )
        
    except Exception as e:
        logger.error(f"Failed to add threat pattern: {str(e)}")
        return create_response(
            success=False,
            message="Failed to add threat pattern",
            error=str(e)
        ), 500

@api_bp.route('/threats/quarantine', methods=['POST'])
def quarantine_email():
    """Add email to quarantine"""
    try:
        data = request.get_json()
        if not data:
            return create_response(
                success=False,
                message="No data provided",
                error="JSON body is required"
            ), 400
        
        validation = validate_request_data(data, ['email_hash', 'reason'])
        if not validation['valid']:
            return jsonify(validation['response']), 400
        
        email_hash = data['email_hash']
        reason = data['reason']
        
        success = db_manager.add_to_quarantine(email_hash, reason)
        
        if success:
            return create_response(
                success=True,
                message="Email added to quarantine",
                data={'email_hash': email_hash}
            )
        else:
            return create_response(
                success=False,
                message="Failed to quarantine email",
                error="Database operation failed"
            ), 500
        
    except Exception as e:
        logger.error(f"Failed to quarantine email: {str(e)}")
        return create_response(
            success=False,
            message="Failed to quarantine email",
            error=str(e)
        ), 500

@api_bp.route('/reputation/sender/<path:sender_email>', methods=['GET'])
def get_sender_reputation(sender_email):
    """Get sender reputation"""
    try:
        threats = db_manager.get_sender_threats(sender_email)
        history = db_manager.get_sender_history(sender_email)
        
        return create_response(
            success=True,
            message="Sender reputation retrieved",
            data={
                'sender': sender_email,
                'threats': threats,
                'history': history[:10],  # Latest 10 emails
                'total_emails': len(history)
            }
        )
        
    except Exception as e:
        logger.error(f"Failed to get sender reputation: {str(e)}")
        return create_response(
            success=False,
            message="Failed to retrieve sender reputation",
            error=str(e)
        ), 500

# Utility Endpoints
@api_bp.route('/cleanup', methods=['POST'])
def cleanup_files():
    """Clean up old files"""
    try:
        data = request.get_json() or {}
        days_old = data.get('days_old', 30)
        
        result = file_processor.cleanup_old_files(days_old)
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Cleanup failed: {str(e)}")
        return create_response(
            success=False,
            message="Cleanup failed",
            error=str(e)
        ), 500

@api_bp.route('/history', methods=['GET'])
def get_processing_history():
    """Get processing history"""
    try:
        limit = request.args.get('limit', 50, type=int)
        result = file_processor.get_processing_history(limit)
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Failed to get processing history: {str(e)}")
        return create_response(
            success=False,
            message="Failed to retrieve processing history",
            error=str(e)
        ), 500

# Error handlers
@api_bp.errorhandler(404)
def api_not_found(error):
    """Handle API 404 errors"""
    return create_response(
        success=False,
        message="API endpoint not found",
        error="The requested API endpoint does not exist"
    ), 404

@api_bp.errorhandler(405)
def method_not_allowed(error):
    """Handle method not allowed errors"""
    return create_response(
        success=False,
        message="Method not allowed",
        error="The HTTP method is not allowed for this endpoint"
    ), 405

@api_bp.errorhandler(413)
def request_entity_too_large(error):
    """Handle file too large errors"""
    return create_response(
        success=False,
        message="File too large",
        error="The uploaded file exceeds the maximum allowed size"
    ), 413

@api_bp.errorhandler(500)
def internal_server_error(error):
    """Handle internal server errors"""
    logger.error(f"Internal server error: {str(error)}")
    return create_response(
        success=False,
        message="Internal server error",
        error="An unexpected error occurred"
    ), 500

# Helper functions
def _get_top_threat_types(days: int) -> List[Dict[str, Any]]:
    """Get top threat types for statistics"""
    try:
        # This would be implemented with proper database queries
        # For now, return sample data structure
        return [
            {"type": "phishing", "count": 0, "percentage": 0},
            {"type": "malware", "count": 0, "percentage": 0},
            {"type": "social_engineering", "count": 0, "percentage": 0}
        ]
    except:
        return []

def _get_daily_trend(days: int) -> List[Dict[str, Any]]:
    """Get daily threat trend for statistics"""
    try:
        # This would be implemented with proper database queries
        # For now, return sample data structure
        dates = []
        for i in range(days):
            date = datetime.now() - timedelta(days=i)
            dates.append({
                "date": date.strftime('%Y-%m-%d'),
                "total_emails": 0,
                "threat_emails": 0,
                "threat_percentage": 0
            })
        return list(reversed(dates))
    except:
        return []
