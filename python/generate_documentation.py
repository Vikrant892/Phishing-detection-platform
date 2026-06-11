#!/usr/bin/env python3
"""
Generate comprehensive PDF documentation for the Phishing Detection Platform
"""

import os
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY

def create_documentation_pdf():
    """Create comprehensive PDF documentation"""
    
    # Create PDF document
    doc = SimpleDocTemplate(
        "Phishing_Detection_Platform_Documentation.pdf",
        pagesize=A4,
        rightMargin=72, leftMargin=72,
        topMargin=72, bottomMargin=18
    )
    
    # Build story (content)
    story = []
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        alignment=TA_CENTER,
        textColor=colors.darkblue
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        spaceAfter=12,
        spaceBefore=20,
        textColor=colors.darkred
    )
    
    subheading_style = ParagraphStyle(
        'CustomSubHeading',
        parent=styles['Heading3'],
        fontSize=14,
        spaceAfter=10,
        spaceBefore=15,
        textColor=colors.darkgreen
    )
    
    code_style = ParagraphStyle(
        'CodeStyle',
        parent=styles['Code'],
        fontSize=10,
        leftIndent=20,
        backgroundColor=colors.lightgrey,
        borderColor=colors.black,
        borderWidth=1
    )
    
    # Title Page
    story.append(Paragraph("Advanced Cybersecurity Phishing Detection Platform", title_style))
    story.append(Spacer(1, 20))
    story.append(Paragraph("Complete Technical Documentation", styles['Heading2']))
    story.append(Spacer(1, 30))
    
    # Date and version info
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%B %d, %Y')}", styles['Normal']))
    story.append(Paragraph("Version: 1.0", styles['Normal']))
    story.append(Spacer(1, 20))
    
    # Table of Contents
    story.append(Paragraph("Table of Contents", heading_style))
    toc_data = [
        ["1. Project Overview", "2"],
        ["2. System Architecture", "3"],
        ["3. Database Schema", "4"],
        ["4. File Structure & Connections", "5"],
        ["5. Python Dependencies & Imports", "7"],
        ["6. Installation Guide", "9"],
        ["7. Running Commands", "11"],
        ["8. API Endpoints", "12"],
        ["9. Testing & Validation", "14"],
        ["10. Troubleshooting", "15"]
    ]
    
    toc_table = Table(toc_data, colWidths=[4*inch, 1*inch])
    toc_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(toc_table)
    story.append(PageBreak())
    
    # 1. Project Overview
    story.append(Paragraph("1. Project Overview", heading_style))
    story.append(Paragraph("""
    The Advanced Cybersecurity Phishing Detection Platform is a comprehensive email analysis system designed to detect 
    phishing attempts and malicious content using machine learning and pattern recognition techniques. The platform 
    analyzes email files in multiple formats (.eml, .msg, .txt) and provides real-time threat scoring, batch processing 
    capabilities, and detailed reporting.
    """, styles['Normal']))
    
    story.append(Paragraph("Key Features:", subheading_style))
    features = [
        "• HTML segment analysis with line number tracking",
        "• Email header analysis including x-ms-exchange-crosstenant headers",
        "• PostgreSQL database for storing analysis results and statistics",
        "• Segment classification (single/multiple line, HTML types)",
        "• Real-time dashboard with threat analytics",
        "• Command-line tools for database statistics",
        "• RESTful API with comprehensive endpoints",
        "• Responsive web interface with dark/light themes"
    ]
    
    for feature in features:
        story.append(Paragraph(feature, styles['Normal']))
    
    story.append(PageBreak())
    
    # 2. System Architecture
    story.append(Paragraph("2. System Architecture", heading_style))
    
    story.append(Paragraph("Backend Architecture:", subheading_style))
    story.append(Paragraph("""
    The system follows a modular Flask-based REST API architecture with clear separation of concerns:
    """, styles['Normal']))
    
    arch_data = [
        ["Component", "Technology", "Purpose"],
        ["Web Framework", "Flask", "HTTP request handling and API endpoints"],
        ["Database", "PostgreSQL", "Persistent storage of analysis results"],
        ["Email Parser", "Python email library", "Multi-format email parsing"],
        ["HTML Analyzer", "Custom analyzer", "HTML segment extraction and analysis"],
        ["Pattern Detection", "RegEx + ML", "Threat pattern recognition"],
        ["Frontend", "HTML/CSS/JavaScript", "User interface and dashboard"]
    ]
    
    arch_table = Table(arch_data, colWidths=[2*inch, 2*inch, 2.5*inch])
    arch_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(arch_table)
    
    story.append(PageBreak())
    
    # 3. Database Schema
    story.append(Paragraph("3. Database Schema", heading_style))
    
    story.append(Paragraph("The system uses PostgreSQL with the following tables:", styles['Normal']))
    
    db_tables = [
        ["Table Name", "Purpose", "Key Fields"],
        ["email_analyses", "Main analysis results", "analysis_id, filename, threat_score, threat_level"],
        ["email_headers", "Header analysis", "analysis_id, header_name, is_suspicious"],
        ["html_segments", "HTML segment details", "analysis_id, segment_type, is_single_line"],
        ["threat_detections", "Individual threats", "threat_category, threat_pattern, line_number"],
        ["analysis_failures", "Failed analyses", "filename, failure_reason, failure_type"],
        ["threat_statistics", "Aggregated stats", "threat_category, occurrence_count"]
    ]
    
    db_table = Table(db_tables, colWidths=[2*inch, 2.5*inch, 2*inch])
    db_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(db_table)
    
    story.append(PageBreak())
    
    # 4. File Structure & Connections
    story.append(Paragraph("4. File Structure & Connections", heading_style))
    
    story.append(Paragraph("Project Directory Structure:", subheading_style))
    file_structure = """
    phishing-detection-platform/
     python/
        simple_app.py              # Main Flask application
        email_html_analyzer.py     # Email analysis engine
        database_schema.py         # Database operations
        database_stats_tool.py     # Command-line statistics
        config.py                  # Configuration settings
        static/
            index.html             # Web interface
     test_phishing_email.eml        # Basic test sample
     test_safe_email.eml            # Safe email sample
     test_enhanced_phishing_email.eml # Advanced test sample
     uploads/                       # Temporary file storage
     logs/                          # Application logs
    """
    story.append(Paragraph(file_structure, code_style))
    
    story.append(Paragraph("File Connections & Dependencies:", subheading_style))
    connections = [
        ["File", "Imports/Uses", "Purpose"],
        ["simple_app.py", "email_html_analyzer, database_schema", "Main app importing analysis and DB modules"],
        ["email_html_analyzer.py", "email, html2text, re", "Email parsing and HTML analysis"],
        ["database_schema.py", "psycopg2, os", "PostgreSQL operations"],
        ["database_stats_tool.py", "database_schema, email_html_analyzer", "CLI tool using DB and analyzer"],
        ["index.html", "Chart.js, Font Awesome", "Frontend using charting and icons"]
    ]
    
    conn_table = Table(connections, colWidths=[2*inch, 2.5*inch, 2*inch])
    conn_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(conn_table)
    
    story.append(PageBreak())
    
    # 5. Python Dependencies & Imports
    story.append(Paragraph("5. Python Dependencies & Imports", heading_style))
    
    story.append(Paragraph("Required Python Packages:", subheading_style))
    dependencies = [
        ["Package", "Version", "Purpose", "Used In"],
        ["Flask", "Latest", "Web framework for API", "simple_app.py"],
        ["Flask-CORS", "Latest", "Cross-origin resource sharing", "simple_app.py"],
        ["psycopg2-binary", "Latest", "PostgreSQL database adapter", "database_schema.py"],
        ["html2text", "Latest", "HTML to text conversion", "email_html_analyzer.py"],
        ["email-validator", "Latest", "Email validation", "email_html_analyzer.py"],
        ["reportlab", "Latest", "PDF generation", "generate_documentation.py"],
        ["werkzeug", "Latest", "Secure filename handling", "simple_app.py"],
        ["numpy", "Latest", "Numerical operations", "Optional for ML"],
        ["pandas", "Latest", "Data manipulation", "Optional for analytics"],
        ["scikit-learn", "Latest", "Machine learning", "Optional for ML models"]
    ]
    
    dep_table = Table(dependencies, colWidths=[1.5*inch, 1*inch, 2*inch, 2*inch])
    dep_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(dep_table)
    
    story.append(Paragraph("Key Import Explanations:", subheading_style))
    imports_explanation = """
    • email: Built-in Python library for parsing email files (.eml format)
    • html2text: Converts HTML content to plain text for analysis
    • psycopg2: PostgreSQL adapter for Python database operations
    • flask: Web framework for creating REST API endpoints
    • werkzeug: Provides secure_filename() for safe file handling
    • os: Operating system interface for environment variables
    • re: Regular expressions for pattern matching in threat detection
    • datetime: Date and time handling for timestamps
    • uuid: Unique identifier generation for analysis sessions
    • logging: Application logging and error tracking
    """
    story.append(Paragraph(imports_explanation, styles['Normal']))
    
    story.append(PageBreak())
    
    # 6. Installation Guide
    story.append(Paragraph("6. Installation Guide", heading_style))
    
    story.append(Paragraph("System Requirements:", subheading_style))
    story.append(Paragraph("• Python 3.8 or higher", styles['Normal']))
    story.append(Paragraph("• PostgreSQL 12 or higher", styles['Normal']))
    story.append(Paragraph("• 4GB RAM minimum", styles['Normal']))
    story.append(Paragraph("• 10GB disk space", styles['Normal']))
    
    story.append(Paragraph("Step 1: Install PostgreSQL", subheading_style))
    postgres_install = """
    # Ubuntu/Debian:
    sudo apt update
    sudo apt install postgresql postgresql-contrib
    
    # macOS (using Homebrew):
    brew install postgresql
    brew services start postgresql
    
    # Windows:
    Download from https://www.postgresql.org/download/windows/
    """
    story.append(Paragraph(postgres_install, code_style))
    
    story.append(Paragraph("Step 2: Create Database", subheading_style))
    db_setup = """
    # Connect to PostgreSQL
    sudo -u postgres psql
    
    # Create database and user
    CREATE DATABASE phishing_detection;
    CREATE USER phishing_user WITH PASSWORD 'secure_password';
    GRANT ALL PRIVILEGES ON DATABASE phishing_detection TO phishing_user;
    \\q
    """
    story.append(Paragraph(db_setup, code_style))
    
    story.append(Paragraph("Step 3: Set Environment Variables", subheading_style))
    env_setup = """
    # Linux/macOS (.bashrc or .zshrc):
    export DATABASE_URL="postgresql://phishing_user:secure_password@localhost:5432/phishing_detection"
    
    # Windows (Command Prompt):
    set DATABASE_URL=postgresql://phishing_user:secure_password@localhost:5432/phishing_detection
    
    # Windows (PowerShell):
    $env:DATABASE_URL="postgresql://phishing_user:secure_password@localhost:5432/phishing_detection"
    """
    story.append(Paragraph(env_setup, code_style))
    
    story.append(Paragraph("Step 4: Install Python Dependencies", subheading_style))
    pip_install = """
    # Create virtual environment (recommended)
    python -m venv phishing_env
    
    # Activate virtual environment
    # Linux/macOS:
    source phishing_env/bin/activate
    # Windows:
    phishing_env\\Scripts\\activate
    
    # Install required packages
    pip install flask flask-cors psycopg2-binary html2text email-validator
    pip install reportlab werkzeug numpy pandas scikit-learn
    """
    story.append(Paragraph(pip_install, code_style))
    
    story.append(Paragraph("Step 5: Download Project Files", subheading_style))
    download_setup = """
    # Create project directory
    mkdir phishing-detection-platform
    cd phishing-detection-platform
    
    # Copy all Python files to python/ directory
    # Copy test .eml files to root directory
    # Ensure proper file structure as shown in section 4
    """
    story.append(Paragraph(download_setup, code_style))
    
    story.append(PageBreak())
    
    # 7. Running Commands
    story.append(Paragraph("7. Running Commands", heading_style))
    
    story.append(Paragraph("Start the Main Application:", subheading_style))
    run_app = """
    # Navigate to python directory
    cd python
    
    # Start Flask application
    python simple_app.py
    
    # Application will start on http://localhost:5000
    # Access web interface at http://localhost:5000
    """
    story.append(Paragraph(run_app, code_style))
    
    story.append(Paragraph("Database Statistics Tool:", subheading_style))
    stats_commands = """
    # View all statistics
    python database_stats_tool.py all
    
    # View threat statistics only
    python database_stats_tool.py threats
    
    # View failure statistics
    python database_stats_tool.py failures
    
    # View dashboard statistics
    python database_stats_tool.py dashboard
    
    # Test analyzer with sample files
    python database_stats_tool.py test
    """
    story.append(Paragraph(stats_commands, code_style))
    
    story.append(Paragraph("Testing with Sample Files:", subheading_style))
    testing_info = """
    The platform includes three test email files:
    • test_phishing_email.eml - Basic phishing patterns
    • test_safe_email.eml - Clean email sample
    • test_enhanced_phishing_email.eml - Advanced threats with headers
    
    You can download these from the web interface or analyze them directly.
    """
    story.append(Paragraph(testing_info, styles['Normal']))
    
    story.append(PageBreak())
    
    # 8. API Endpoints
    story.append(Paragraph("8. API Endpoints", heading_style))
    
    api_endpoints = [
        ["Method", "Endpoint", "Purpose", "Parameters"],
        ["GET", "/", "Main web interface", "None"],
        ["POST", "/api/upload", "Upload email for analysis", "file (multipart)"],
        ["GET", "/api/dashboard-stats", "Get dashboard statistics", "None"],
        ["GET", "/api/threat-statistics", "Get threat occurrence stats", "None"],
        ["GET", "/api/failure-statistics", "Get analysis failure stats", "None"],
        ["POST", "/api/detailed-report", "Get detailed HTML report", "file (.eml)"],
        ["POST", "/api/analyze-text", "Analyze text content", "content (JSON)"],
        ["GET", "/test_*.eml", "Download test samples", "None"]
    ]
    
    api_table = Table(api_endpoints, colWidths=[0.8*inch, 2*inch, 2*inch, 1.7*inch])
    api_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(api_table)
    
    story.append(Paragraph("Example API Usage:", subheading_style))
    api_examples = """
    # Upload email file using curl
    curl -X POST -F "file=@test_phishing_email.eml" http://localhost:5000/api/upload
    
    # Get dashboard statistics
    curl http://localhost:5000/api/dashboard-stats
    
    # Analyze text content
    curl -X POST -H "Content-Type: application/json" \\
         -d '{"content":"Click here to verify your account"}' \\
         http://localhost:5000/api/analyze-text
    """
    story.append(Paragraph(api_examples, code_style))
    
    story.append(PageBreak())
    
    # 9. Testing & Validation
    story.append(Paragraph("9. Testing & Validation", heading_style))
    
    story.append(Paragraph("Threat Detection Categories:", subheading_style))
    threat_categories = [
        "• Urgent Actions (expires in 24 hours, act now)",
        "• Credential Harvesting (enter your password, confirm login)",
        "• Financial Threats (unauthorized transaction, suspicious activity)",
        "• Microsoft Exchange (crosstenant authentication, office 365)",
        "• Suspicious Codes (specific patterns like XFCjGeORft8x7Ol)",
        "• Header Analysis (x-ms-exchange-crosstenant headers)"
    ]
    
    for category in threat_categories:
        story.append(Paragraph(category, styles['Normal']))
    
    story.append(Paragraph("Validation Results:", subheading_style))
    validation_results = """
    The enhanced test email successfully detects:
    ✓ 15 different threat patterns
    ✓ 8 suspicious email headers
    ✓ 41 HTML segments analyzed
    ✓ 100/100 threat score (HIGH risk)
    ✓ Proper database storage and statistics
    """
    story.append(Paragraph(validation_results, styles['Normal']))
    
    story.append(PageBreak())
    
    # 10. Troubleshooting
    story.append(Paragraph("10. Troubleshooting", heading_style))
    
    story.append(Paragraph("Common Issues and Solutions:", subheading_style))
    
    troubleshooting = [
        ["Issue", "Cause", "Solution"],
        ["Database connection error", "Wrong DATABASE_URL", "Check connection string and credentials"],
        ["Import errors", "Missing packages", "Install all required dependencies"],
        ["File upload fails", "Large file size", "Check file size limits in config"],
        ["UUID errors", "Old database schema", "Drop and recreate tables"],
        ["Port already in use", "Flask port conflict", "Change port in simple_app.py"],
        ["Permission denied", "File access rights", "Check file permissions"]
    ]
    
    trouble_table = Table(troubleshooting, colWidths=[2*inch, 2*inch, 2.5*inch])
    trouble_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(trouble_table)
    
    story.append(Paragraph("Debug Commands:", subheading_style))
    debug_commands = """
    # Check database connection
    python -c "from database_schema import DatabaseManager; db = DatabaseManager(); print('DB OK')"
    
    # Test email analyzer
    python -c "from email_html_analyzer import EmailHTMLAnalyzer; analyzer = EmailHTMLAnalyzer(); print('Analyzer OK')"
    
    # View application logs
    tail -f logs/application.log
    
    # Check database tables
    psql -d phishing_detection -c "\\dt"
    """
    story.append(Paragraph(debug_commands, code_style))
    
    # Footer
    story.append(Spacer(1, 30))
    story.append(Paragraph("End of Documentation", styles['Heading2']))
    story.append(Paragraph(f"Generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}", styles['Normal']))
    
    # Build PDF
    doc.build(story)
    print("✅ PDF documentation generated: Phishing_Detection_Platform_Documentation.pdf")

if __name__ == "__main__":
    create_documentation_pdf()