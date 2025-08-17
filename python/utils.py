"""
Utility functions for the Phishing Detection Platform
"""

import os
import re
import json
import logging
import hashlib
import mimetypes
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import pandas as pd
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
import xlsxwriter

logger = logging.getLogger(__name__)

def validate_file_type(filename: str, allowed_extensions: List[str]) -> bool:
    """Validate file type based on extension"""
    if not filename:
        return False
    
    file_extension = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    return file_extension in allowed_extensions

def sanitize_input(input_string: str) -> str:
    """Sanitize user input to prevent injection attacks"""
    if not input_string:
        return ''
    
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[<>"\';\\]', '', str(input_string))
    
    # Limit length
    sanitized = sanitized[:1000]
    
    return sanitized.strip()

def calculate_file_hash(filepath: str) -> str:
    """Calculate SHA-256 hash of a file"""
    try:
        hash_sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating file hash: {e}")
        return ""

def format_file_size(size_bytes: int) -> str:
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.1f}{size_names[i]}"

def validate_email_address(email: str) -> bool:
    """Validate email address format"""
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_pattern, email))

def extract_domain_from_email(email: str) -> str:
    """Extract domain from email address"""
    if '@' in email:
        return email.split('@')[1].lower()
    return ''

def generate_analysis_id() -> str:
    """Generate unique analysis ID"""
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    random_part = hashlib.md5(str(datetime.now().microsecond).encode()).hexdigest()[:8]
    return f"ANALYSIS_{timestamp}_{random_part}"

def format_threat_score(score: float) -> Dict[str, Any]:
    """Format threat score with risk level and color"""
    if score >= 70:
        risk_level = 'HIGH'
        color = '#dc3545'  # Red
    elif score >= 40:
        risk_level = 'MEDIUM'
        color = '#ffc107'  # Yellow
    else:
        risk_level = 'LOW'
        color = '#28a745'  # Green
    
    return {
        'score': score,
        'risk_level': risk_level,
        'color': color,
        'percentage': min(score, 100)
    }

def parse_datetime_string(datetime_str: str) -> Optional[datetime]:
    """Parse datetime string in various formats"""
    formats = [
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%d',
        '%d/%m/%Y %H:%M:%S',
        '%d/%m/%Y',
        '%m/%d/%Y %H:%M:%S',
        '%m/%d/%Y'
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(datetime_str, fmt)
        except ValueError:
            continue
    
    return None

def generate_report(format_type: str, date_from: str, date_to: str, risk_levels: List[str], db) -> str:
    """Generate analysis report in specified format"""
    try:
        # Create reports directory
        os.makedirs('../reports', exist_ok=True)
        
        # Parse dates
        start_date = parse_datetime_string(date_from) if date_from else datetime.now() - timedelta(days=30)
        end_date = parse_datetime_string(date_to) if date_to else datetime.now()
        
        # Get data from database
        report_data = get_report_data(db, start_date, end_date, risk_levels)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if format_type.lower() == 'pdf':
            filename = f'phishing_report_{timestamp}.pdf'
            filepath = os.path.join('../reports', filename)
            generate_pdf_report(filepath, report_data, start_date, end_date)
        
        elif format_type.lower() == 'excel':
            filename = f'phishing_report_{timestamp}.xlsx'
            filepath = os.path.join('../reports', filename)
            generate_excel_report(filepath, report_data, start_date, end_date)
        
        elif format_type.lower() == 'csv':
            filename = f'phishing_report_{timestamp}.csv'
            filepath = os.path.join('../reports', filename)
            generate_csv_report(filepath, report_data, start_date, end_date)
        
        else:
            raise ValueError(f"Unsupported format: {format_type}")
        
        logger.info(f"Report generated: {filepath}")
        return filepath
        
    except Exception as e:
        logger.error(f"Report generation error: {e}")
        raise

def get_report_data(db, start_date: datetime, end_date: datetime, risk_levels: List[str]) -> Dict[str, Any]:
    """Get data for report generation"""
    try:
        # Get analyses within date range
        analyses = db.get_analysis_history_for_report(start_date, end_date, risk_levels)
        
        # Get summary statistics
        stats = db.get_report_statistics(start_date, end_date, risk_levels)
        
        # Get threat patterns
        patterns = db.get_threat_patterns()
        
        return {
            'analyses': analyses,
            'statistics': stats,
            'patterns': patterns,
            'date_range': {
                'start': start_date,
                'end': end_date
            },
            'risk_levels': risk_levels
        }
        
    except Exception as e:
        logger.error(f"Error getting report data: {e}")
        return {}

def generate_pdf_report(filepath: str, data: Dict[str, Any], start_date: datetime, end_date: datetime):
    """Generate PDF report"""
    try:
        doc = SimpleDocTemplate(filepath, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.darkblue
        )
        
        story.append(Paragraph("Phishing Detection Analysis Report", title_style))
        story.append(Spacer(1, 12))
        
        # Date range
        date_text = f"Analysis Period: {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}"
        story.append(Paragraph(date_text, styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Summary statistics
        story.append(Paragraph("Executive Summary", styles['Heading2']))
        
        stats = data.get('statistics', {})
        summary_data = [
            ['Metric', 'Value'],
            ['Total Emails Analyzed', str(stats.get('total_analyses', 0))],
            ['High Risk Emails', str(stats.get('high_risk_count', 0))],
            ['Medium Risk Emails', str(stats.get('medium_risk_count', 0))],
            ['Low Risk Emails', str(stats.get('low_risk_count', 0))],
            ['Emails Quarantined', str(stats.get('quarantined_count', 0))],
            ['Average Threat Score', f"{stats.get('avg_threat_score', 0):.2f}"]
        ]
        
        summary_table = Table(summary_data)
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Recent analyses
        story.append(Paragraph("Recent High-Risk Analyses", styles['Heading2']))
        
        analyses = data.get('analyses', [])
        high_risk_analyses = [a for a in analyses if a.get('risk_level') == 'HIGH'][:10]
        
        if high_risk_analyses:
            analysis_data = [['Date', 'Subject', 'Sender', 'Threat Score']]
            for analysis in high_risk_analyses:
                analysis_data.append([
                    analysis.get('created_at', '').split(' ')[0],
                    analysis.get('email_subject', '')[:50] + '...' if len(analysis.get('email_subject', '')) > 50 else analysis.get('email_subject', ''),
                    analysis.get('email_sender', ''),
                    str(analysis.get('threat_score', 0))
                ])
            
            analysis_table = Table(analysis_data)
            analysis_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(analysis_table)
        else:
            story.append(Paragraph("No high-risk analyses found in the specified period.", styles['Normal']))
        
        # Build PDF
        doc.build(story)
        
    except Exception as e:
        logger.error(f"PDF generation error: {e}")
        raise

def generate_excel_report(filepath: str, data: Dict[str, Any], start_date: datetime, end_date: datetime):
    """Generate Excel report"""
    try:
        workbook = xlsxwriter.Workbook(filepath)
        
        # Create formats
        header_format = workbook.add_format({
            'bold': True,
            'bg_color': '#4472C4',
            'font_color': 'white',
            'border': 1
        })
        
        cell_format = workbook.add_format({
            'border': 1,
            'text_wrap': True
        })
        
        # Summary worksheet
        summary_ws = workbook.add_worksheet('Summary')
        summary_ws.write('A1', 'Phishing Detection Analysis Report', workbook.add_format({'bold': True, 'font_size': 16}))
        summary_ws.write('A2', f"Period: {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}")
        
        stats = data.get('statistics', {})
        summary_data = [
            ['Metric', 'Value'],
            ['Total Emails Analyzed', stats.get('total_analyses', 0)],
            ['High Risk Emails', stats.get('high_risk_count', 0)],
            ['Medium Risk Emails', stats.get('medium_risk_count', 0)],
            ['Low Risk Emails', stats.get('low_risk_count', 0)],
            ['Emails Quarantined', stats.get('quarantined_count', 0)],
            ['Average Threat Score', f"{stats.get('avg_threat_score', 0):.2f}"]
        ]
        
        for row, data_row in enumerate(summary_data, 4):
            for col, cell_value in enumerate(data_row):
                if row == 4:  # Header row
                    summary_ws.write(row, col, cell_value, header_format)
                else:
                    summary_ws.write(row, col, cell_value, cell_format)
        
        # Analyses worksheet
        analyses_ws = workbook.add_worksheet('Analyses')
        analyses = data.get('analyses', [])
        
        headers = ['Analysis ID', 'Date', 'Subject', 'Sender', 'Threat Score', 'Risk Level', 'Quarantined']
        for col, header in enumerate(headers):
            analyses_ws.write(0, col, header, header_format)
        
        for row, analysis in enumerate(analyses, 1):
            analyses_ws.write(row, 0, analysis.get('analysis_id', ''), cell_format)
            analyses_ws.write(row, 1, str(analysis.get('created_at', '')), cell_format)
            analyses_ws.write(row, 2, analysis.get('email_subject', ''), cell_format)
            analyses_ws.write(row, 3, analysis.get('email_sender', ''), cell_format)
            analyses_ws.write(row, 4, analysis.get('threat_score', 0), cell_format)
            analyses_ws.write(row, 5, analysis.get('risk_level', ''), cell_format)
            analyses_ws.write(row, 6, 'Yes' if analysis.get('is_quarantined') else 'No', cell_format)
        
        # Auto-adjust column widths
        summary_ws.set_column('A:B', 25)
        analyses_ws.set_column('A:A', 20)  # Analysis ID
        analyses_ws.set_column('B:B', 15)  # Date
        analyses_ws.set_column('C:C', 50)  # Subject
        analyses_ws.set_column('D:D', 30)  # Sender
        analyses_ws.set_column('E:G', 15)  # Score, Risk, Quarantined
        
        workbook.close()
        
    except Exception as e:
        logger.error(f"Excel generation error: {e}")
        raise

def generate_csv_report(filepath: str, data: Dict[str, Any], start_date: datetime, end_date: datetime):
    """Generate CSV report"""
    try:
        analyses = data.get('analyses', [])
        
        df = pd.DataFrame(analyses)
        
        # Select and rename columns
        columns_to_keep = {
            'analysis_id': 'Analysis ID',
            'created_at': 'Date',
            'email_subject': 'Subject',
            'email_sender': 'Sender',
            'threat_score': 'Threat Score',
            'risk_level': 'Risk Level',
            'threats_found': 'Threats Found',
            'is_quarantined': 'Quarantined'
        }
        
        if not df.empty:
            df = df[list(columns_to_keep.keys())].rename(columns=columns_to_keep)
        
        df.to_csv(filepath, index=False)
        
    except Exception as e:
        logger.error(f"CSV generation error: {e}")
        raise

def validate_json_structure(json_data: Dict[str, Any], required_fields: List[str]) -> bool:
    """Validate JSON structure has required fields"""
    return all(field in json_data for field in required_fields)

def safe_json_loads(json_string: str) -> Optional[Dict[str, Any]]:
    """Safely load JSON string with error handling"""
    try:
        return json.loads(json_string)
    except (json.JSONDecodeError, TypeError):
        return None

def truncate_text(text: str, max_length: int = 100) -> str:
    """Truncate text to specified length"""
    if not text:
        return ''
    
    if len(text) <= max_length:
        return text
    
    return text[:max_length-3] + '...'

def get_mime_type(filepath: str) -> str:
    """Get MIME type of file"""
    mime_type, _ = mimetypes.guess_type(filepath)
    return mime_type or 'application/octet-stream'

def is_safe_path(basedir: str, path: str) -> bool:
    """Check if path is safe (within basedir)"""
    try:
        basedir = os.path.abspath(basedir)
        path = os.path.abspath(os.path.join(basedir, path))
        return path.startswith(basedir)
    except:
        return False

def cleanup_old_files(directory: str, max_age_days: int = 7):
    """Clean up old files in directory"""
    try:
        cutoff_time = datetime.now() - timedelta(days=max_age_days)
        
        for filename in os.listdir(directory):
            filepath = os.path.join(directory, filename)
            
            if os.path.isfile(filepath):
                file_time = datetime.fromtimestamp(os.path.getmtime(filepath))
                
                if file_time < cutoff_time:
                    os.remove(filepath)
                    logger.info(f"Cleaned up old file: {filepath}")
                    
    except Exception as e:
        logger.error(f"File cleanup error: {e}")

def format_duration(seconds: int) -> str:
    """Format duration in human readable format"""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        minutes = seconds // 60
        return f"{minutes}m {seconds % 60}s"
    else:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours}h {minutes}m"
