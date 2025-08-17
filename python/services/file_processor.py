"""
File Processor Service - Handle file uploads and batch processing
"""

import os
import tempfile
import shutil
import zipfile
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import json
import threading
from concurrent.futures import ThreadPoolExecutor
import time

from services.email_parser import EmailParser
from models.email_analyzer import EmailAnalyzer
from models.database_manager import DatabaseManager
from utils.helpers import create_response, sanitize_filename, get_file_hash

logger = logging.getLogger(__name__)

class FileProcessor:
    """Advanced file processor for email analysis with batch processing support"""
    
    def __init__(self):
        self.email_parser = EmailParser()
        self.db_manager = DatabaseManager()
        self.email_analyzer = EmailAnalyzer(self.db_manager)
        
        # Processing status tracking
        self.processing_jobs = {}
        self.job_lock = threading.Lock()
        
        # Supported file types
        self.supported_types = ['.eml', '.msg', '.txt', '.mbox']
        self.supported_archives = ['.zip', '.rar', '.7z', '.tar', '.gz']
        
        # Create upload directories
        self.upload_dir = os.path.join(os.getcwd(), 'uploads')
        self.temp_dir = os.path.join(os.getcwd(), 'temp')
        self.exports_dir = os.path.join(os.getcwd(), 'exports')
        
        for directory in [self.upload_dir, self.temp_dir, self.exports_dir]:
            os.makedirs(directory, exist_ok=True)
    
    def process_single_file(self, file_path: str, original_filename: str = None) -> Dict[str, Any]:
        """
        Process a single email file
        
        Args:
            file_path: Path to the email file
            original_filename: Original filename for reference
            
        Returns:
            Processing result with analysis data
        """
        try:
            start_time = time.time()
            
            # Validate file
            validation_result = self._validate_file(file_path)
            if not validation_result['is_valid']:
                return create_response(
                    success=False,
                    message="File validation failed",
                    error=validation_result['error']
                )
            
            # Parse email
            logger.info(f"Parsing email file: {original_filename or file_path}")
            parsed_email = self.email_parser.parse_email_file(file_path)
            
            # Validate email structure
            email_validation = self.email_parser.validate_email_structure(parsed_email)
            
            # Analyze email for threats
            logger.info(f"Analyzing email for threats: {original_filename or file_path}")
            analysis_result = self.email_analyzer.analyze_email(
                parsed_email['raw_content'],
                source_file=original_filename or file_path
            )
            
            # Calculate processing time
            processing_time = time.time() - start_time
            
            # Add processing metadata
            analysis_result['processing_metadata'] = {
                'processing_time': processing_time,
                'file_size': os.path.getsize(file_path),
                'file_hash': get_file_hash(file_path),
                'original_filename': original_filename,
                'processed_timestamp': datetime.now().isoformat(),
                'email_validation': email_validation
            }
            
            logger.info(f"File processing completed in {processing_time:.2f}s - Risk Score: {analysis_result['risk_score']}")
            
            return create_response(
                success=True,
                message="Email analysis completed successfully",
                data=analysis_result
            )
            
        except Exception as e:
            logger.error(f"Failed to process file {file_path}: {str(e)}")
            return create_response(
                success=False,
                message="File processing failed",
                error=str(e)
            )
    
    def process_batch_files(self, file_paths: List[str], job_id: str = None) -> str:
        """
        Process multiple email files in batch
        
        Args:
            file_paths: List of file paths to process
            job_id: Optional job ID for tracking
            
        Returns:
            Job ID for tracking batch processing
        """
        if not job_id:
            job_id = f"batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{len(file_paths)}"
        
        # Initialize job tracking
        with self.job_lock:
            self.processing_jobs[job_id] = {
                'status': 'started',
                'total_files': len(file_paths),
                'processed_files': 0,
                'successful_files': 0,
                'failed_files': 0,
                'start_time': datetime.now().isoformat(),
                'results': [],
                'errors': []
            }
        
        # Start batch processing in background
        thread = threading.Thread(
            target=self._process_batch_worker,
            args=(job_id, file_paths)
        )
        thread.daemon = True
        thread.start()
        
        logger.info(f"Started batch processing job {job_id} with {len(file_paths)} files")
        return job_id
    
    def get_job_status(self, job_id: str) -> Dict[str, Any]:
        """Get batch processing job status"""
        with self.job_lock:
            job_data = self.processing_jobs.get(job_id)
            if not job_data:
                return create_response(
                    success=False,
                    message="Job not found",
                    error=f"Job ID {job_id} does not exist"
                )
            
            return create_response(
                success=True,
                message="Job status retrieved",
                data=job_data.copy()
            )
    
    def process_archive_file(self, archive_path: str) -> Dict[str, Any]:
        """
        Process archive file containing multiple emails
        
        Args:
            archive_path: Path to archive file
            
        Returns:
            Processing result with job ID
        """
        try:
            # Extract archive
            extract_result = self._extract_archive(archive_path)
            if not extract_result['success']:
                return extract_result
            
            extracted_files = extract_result['data']['files']
            extract_dir = extract_result['data']['extract_dir']
            
            # Filter email files
            email_files = []
            for file_path in extracted_files:
                if any(file_path.lower().endswith(ext) for ext in self.supported_types):
                    email_files.append(file_path)
            
            if not email_files:
                return create_response(
                    success=False,
                    message="No email files found in archive",
                    error="Archive does not contain supported email formats"
                )
            
            # Start batch processing
            job_id = self.process_batch_files(email_files)
            
            return create_response(
                success=True,
                message=f"Archive processing started with {len(email_files)} email files",
                data={
                    'job_id': job_id,
                    'total_files': len(email_files),
                    'extract_dir': extract_dir
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to process archive {archive_path}: {str(e)}")
            return create_response(
                success=False,
                message="Archive processing failed",
                error=str(e)
            )
    
    def save_uploaded_file(self, file_data: bytes, filename: str) -> Dict[str, Any]:
        """
        Save uploaded file to disk
        
        Args:
            file_data: File content as bytes
            filename: Original filename
            
        Returns:
            Result with saved file path
        """
        try:
            # Sanitize filename
            safe_filename = sanitize_filename(filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            final_filename = f"{timestamp}_{safe_filename}"
            
            # Save file
            file_path = os.path.join(self.upload_dir, final_filename)
            with open(file_path, 'wb') as f:
                f.write(file_data)
            
            # Validate saved file
            validation_result = self._validate_file(file_path)
            if not validation_result['is_valid']:
                os.remove(file_path)
                return create_response(
                    success=False,
                    message="Invalid file uploaded",
                    error=validation_result['error']
                )
            
            return create_response(
                success=True,
                message="File uploaded successfully",
                data={
                    'file_path': file_path,
                    'filename': final_filename,
                    'original_filename': filename,
                    'file_size': len(file_data),
                    'file_hash': get_file_hash(file_path)
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to save uploaded file {filename}: {str(e)}")
            return create_response(
                success=False,
                message="File upload failed",
                error=str(e)
            )
    
    def get_processing_history(self, limit: int = 50) -> Dict[str, Any]:
        """Get recent processing history"""
        try:
            analyses = self.db_manager.get_recent_analyses(limit)
            
            # Add file processing metadata
            for analysis in analyses:
                if analysis.get('analysis_data'):
                    metadata = analysis['analysis_data'].get('processing_metadata', {})
                    analysis['processing_time'] = metadata.get('processing_time', 0)
                    analysis['file_size'] = metadata.get('file_size', 0)
                    analysis['original_filename'] = metadata.get('original_filename', 'Unknown')
            
            return create_response(
                success=True,
                message="Processing history retrieved",
                data={
                    'analyses': analyses,
                    'total': len(analyses)
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to get processing history: {str(e)}")
            return create_response(
                success=False,
                message="Failed to retrieve processing history",
                error=str(e)
            )
    
    def export_analysis_results(self, analysis_ids: List[int], format_type: str = 'json') -> Dict[str, Any]:
        """
        Export analysis results in various formats
        
        Args:
            analysis_ids: List of analysis IDs to export
            format_type: Export format (json, csv, excel, pdf)
            
        Returns:
            Export result with file path
        """
        try:
            # Get analysis data
            analyses = []
            for analysis_id in analysis_ids:
                # This would need to be implemented in database_manager
                analysis = self.db_manager.get_analysis_by_id(analysis_id)
                if analysis:
                    analyses.append(analysis)
            
            if not analyses:
                return create_response(
                    success=False,
                    message="No analysis data found",
                    error="Invalid analysis IDs provided"
                )
            
            # Generate export filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"threat_analysis_export_{timestamp}.{format_type}"
            export_path = os.path.join(self.exports_dir, filename)
            
            # Export based on format
            if format_type == 'json':
                export_result = self._export_json(analyses, export_path)
            elif format_type == 'csv':
                export_result = self._export_csv(analyses, export_path)
            elif format_type == 'excel':
                export_result = self._export_excel(analyses, export_path)
            elif format_type == 'pdf':
                export_result = self._export_pdf(analyses, export_path)
            else:
                return create_response(
                    success=False,
                    message="Unsupported export format",
                    error=f"Format {format_type} is not supported"
                )
            
            if export_result['success']:
                return create_response(
                    success=True,
                    message="Export completed successfully",
                    data={
                        'export_path': export_path,
                        'filename': filename,
                        'format': format_type,
                        'record_count': len(analyses),
                        'file_size': os.path.getsize(export_path)
                    }
                )
            else:
                return export_result
                
        except Exception as e:
            logger.error(f"Failed to export analysis results: {str(e)}")
            return create_response(
                success=False,
                message="Export failed",
                error=str(e)
            )
    
    def cleanup_old_files(self, days_old: int = 30) -> Dict[str, Any]:
        """Clean up old uploaded and temporary files"""
        try:
            cutoff_time = time.time() - (days_old * 24 * 60 * 60)
            cleaned_files = []
            
            # Clean upload directory
            for filename in os.listdir(self.upload_dir):
                file_path = os.path.join(self.upload_dir, filename)
                if os.path.isfile(file_path) and os.path.getmtime(file_path) < cutoff_time:
                    os.remove(file_path)
                    cleaned_files.append(file_path)
            
            # Clean temp directory
            for filename in os.listdir(self.temp_dir):
                file_path = os.path.join(self.temp_dir, filename)
                if os.path.isfile(file_path) and os.path.getmtime(file_path) < cutoff_time:
                    if os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                    else:
                        os.remove(file_path)
                    cleaned_files.append(file_path)
            
            return create_response(
                success=True,
                message=f"Cleaned up {len(cleaned_files)} old files",
                data={
                    'cleaned_files': len(cleaned_files),
                    'days_old': days_old
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to cleanup old files: {str(e)}")
            return create_response(
                success=False,
                message="Cleanup failed",
                error=str(e)
            )
    
    # Private methods
    def _validate_file(self, file_path: str) -> Dict[str, Any]:
        """Validate uploaded file"""
        try:
            if not os.path.exists(file_path):
                return {'is_valid': False, 'error': 'File does not exist'}
            
            # Check file size (max 100MB)
            file_size = os.path.getsize(file_path)
            max_size = 100 * 1024 * 1024
            if file_size > max_size:
                return {'is_valid': False, 'error': f'File too large: {file_size} bytes (max {max_size})'}
            
            # Check file extension
            file_ext = os.path.splitext(file_path)[1].lower()
            supported_exts = self.supported_types + self.supported_archives
            if file_ext not in supported_exts:
                return {'is_valid': False, 'error': f'Unsupported file type: {file_ext}'}
            
            # Basic content validation
            try:
                with open(file_path, 'rb') as f:
                    header = f.read(1024)
                    if len(header) == 0:
                        return {'is_valid': False, 'error': 'Empty file'}
            except Exception as e:
                return {'is_valid': False, 'error': f'Cannot read file: {str(e)}'}
            
            return {'is_valid': True, 'error': None}
            
        except Exception as e:
            return {'is_valid': False, 'error': f'Validation error: {str(e)}'}
    
    def _process_batch_worker(self, job_id: str, file_paths: List[str]):
        """Background worker for batch processing"""
        try:
            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = []
                
                for file_path in file_paths:
                    future = executor.submit(self._process_single_file_for_batch, file_path, job_id)
                    futures.append(future)
                
                # Wait for all tasks to complete
                for future in futures:
                    try:
                        result = future.result(timeout=300)  # 5 minute timeout per file
                        self._update_batch_job(job_id, result)
                    except Exception as e:
                        error_result = {
                            'success': False,
                            'file_path': 'unknown',
                            'error': str(e)
                        }
                        self._update_batch_job(job_id, error_result)
            
            # Mark job as completed
            with self.job_lock:
                if job_id in self.processing_jobs:
                    self.processing_jobs[job_id]['status'] = 'completed'
                    self.processing_jobs[job_id]['end_time'] = datetime.now().isoformat()
            
        except Exception as e:
            logger.error(f"Batch processing job {job_id} failed: {str(e)}")
            with self.job_lock:
                if job_id in self.processing_jobs:
                    self.processing_jobs[job_id]['status'] = 'failed'
                    self.processing_jobs[job_id]['error'] = str(e)
                    self.processing_jobs[job_id]['end_time'] = datetime.now().isoformat()
    
    def _process_single_file_for_batch(self, file_path: str, job_id: str) -> Dict[str, Any]:
        """Process single file within batch job"""
        try:
            result = self.process_single_file(file_path, os.path.basename(file_path))
            return {
                'success': result['success'],
                'file_path': file_path,
                'data': result.get('data'),
                'error': result.get('error')
            }
        except Exception as e:
            return {
                'success': False,
                'file_path': file_path,
                'error': str(e)
            }
    
    def _update_batch_job(self, job_id: str, result: Dict[str, Any]):
        """Update batch job progress"""
        with self.job_lock:
            if job_id in self.processing_jobs:
                job = self.processing_jobs[job_id]
                job['processed_files'] += 1
                
                if result['success']:
                    job['successful_files'] += 1
                    job['results'].append(result)
                else:
                    job['failed_files'] += 1
                    job['errors'].append(result)
                
                # Calculate progress
                job['progress'] = (job['processed_files'] / job['total_files']) * 100
    
    def _extract_archive(self, archive_path: str) -> Dict[str, Any]:
        """Extract archive file"""
        try:
            extract_dir = os.path.join(self.temp_dir, f"extract_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
            os.makedirs(extract_dir, exist_ok=True)
            
            extracted_files = []
            
            if archive_path.lower().endswith('.zip'):
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
                    extracted_files = [os.path.join(extract_dir, name) for name in zip_ref.namelist()]
            else:
                return create_response(
                    success=False,
                    message="Unsupported archive format",
                    error="Only ZIP archives are currently supported"
                )
            
            return create_response(
                success=True,
                message="Archive extracted successfully",
                data={
                    'extract_dir': extract_dir,
                    'files': extracted_files
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to extract archive {archive_path}: {str(e)}")
            return create_response(
                success=False,
                message="Archive extraction failed",
                error=str(e)
            )
    
    def _export_json(self, analyses: List[Dict], export_path: str) -> Dict[str, Any]:
        """Export analysis results as JSON"""
        try:
            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(analyses, f, indent=2, default=str)
            
            return create_response(success=True, message="JSON export completed")
        except Exception as e:
            return create_response(success=False, error=str(e))
    
    def _export_csv(self, analyses: List[Dict], export_path: str) -> Dict[str, Any]:
        """Export analysis results as CSV"""
        try:
            import csv
            
            with open(export_path, 'w', newline='', encoding='utf-8') as f:
                if analyses:
                    writer = csv.DictWriter(f, fieldnames=analyses[0].keys())
                    writer.writeheader()
                    for analysis in analyses:
                        # Flatten complex fields
                        flat_analysis = {}
                        for key, value in analysis.items():
                            if isinstance(value, (dict, list)):
                                flat_analysis[key] = json.dumps(value)
                            else:
                                flat_analysis[key] = value
                        writer.writerow(flat_analysis)
            
            return create_response(success=True, message="CSV export completed")
        except Exception as e:
            return create_response(success=False, error=str(e))
    
    def _export_excel(self, analyses: List[Dict], export_path: str) -> Dict[str, Any]:
        """Export analysis results as Excel"""
        try:
            # This would require openpyxl or xlswriter
            # For now, fallback to CSV
            csv_path = export_path.replace('.excel', '.csv')
            return self._export_csv(analyses, csv_path)
        except Exception as e:
            return create_response(success=False, error=str(e))
    
    def _export_pdf(self, analyses: List[Dict], export_path: str) -> Dict[str, Any]:
        """Export analysis results as PDF"""
        try:
            # This would require reportlab or similar
            # For now, create a simple text-based PDF alternative
            txt_path = export_path.replace('.pdf', '.txt')
            with open(txt_path, 'w', encoding='utf-8') as f:
                f.write("Threat Analysis Report\n")
                f.write("=" * 50 + "\n\n")
                
                for i, analysis in enumerate(analyses, 1):
                    f.write(f"Analysis #{i}\n")
                    f.write(f"Email Hash: {analysis.get('email_hash', 'N/A')}\n")
                    f.write(f"Risk Score: {analysis.get('risk_score', 'N/A')}\n")
                    f.write(f"Threat Level: {analysis.get('threat_level', 'N/A')}\n")
                    f.write(f"Timestamp: {analysis.get('analysis_timestamp', 'N/A')}\n")
                    f.write("-" * 30 + "\n\n")
            
            return create_response(success=True, message="Text report export completed")
        except Exception as e:
            return create_response(success=False, error=str(e))
