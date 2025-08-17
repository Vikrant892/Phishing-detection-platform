# Overview

This is an Advanced Cybersecurity Phishing Detection Platform that provides comprehensive email analysis and threat detection capabilities. The platform consists of a Python-based backend API and a web frontend, designed to analyze email files for phishing attempts and malicious content using machine learning and pattern recognition techniques.

The system supports multiple email formats (.eml, .msg, .txt) and provides real-time threat scoring, batch processing capabilities, and detailed reporting. It features a dashboard for monitoring threat activities, managing detection rules, and viewing analysis results with risk categorization.

**Project Status**: ✅ COMPLETED (August 17, 2025)
- Full system implementation with PostgreSQL database integration
- Enhanced email analyzer with header analysis and segment classification
- Complete PDF documentation and installation guide
- Ready for private Git repository deployment

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Backend Architecture
- **Framework**: Flask-based REST API with blueprint organization for modular endpoints
- **Database**: MySQL for persistent storage of threat patterns, analysis results, and user data
- **Caching**: Redis for performance optimization and session management
- **Processing**: Multi-threaded file processing with concurrent analysis capabilities

## Data Storage Design
- **Primary Database**: MySQL with utf8mb4 charset for comprehensive character support
- **Schema Design**: Separate models for EmailAnalysis, ThreatPattern, and user management
- **File Storage**: Local filesystem for uploaded files with configurable upload directories
- **Export System**: Support for PDF and Excel report generation

## Email Processing Pipeline
- **Parser Layer**: Multi-format email parser supporting EML, MSG, and TXT formats
- **Analysis Engine**: Machine learning-based threat detector with configurable scoring weights
- **Pattern Recognition**: Rule-based threat pattern matching with customizable detection rules
- **Batch Processing**: Concurrent processing support for multiple files with job tracking

## API Structure
- **Modular Design**: Blueprint-based API organization with separate modules for email, threat, and file operations
- **RESTful Endpoints**: Standard HTTP methods with JSON responses
- **File Upload**: Secure file handling with type validation and size limits
- **Documentation**: Built-in API documentation endpoint

## Security Implementation
- **Input Validation**: Comprehensive sanitization of user inputs and file uploads
- **Authentication**: JWT-based authentication with configurable token expiration
- **File Security**: Type validation, size limits, and secure filename handling
- **Error Handling**: Comprehensive logging and error reporting without sensitive data exposure

## Frontend Architecture
- **Technology Stack**: HTML/CSS/JavaScript with responsive design
- **Chart Integration**: Chart.js for data visualization and threat analytics
- **Real-time Updates**: JavaScript-based periodic data refresh for dashboard
- **Theme Support**: Light/dark theme system with user preferences

# External Dependencies

## Database Systems
- **MySQL**: Primary database for persistent data storage
- **Redis**: Caching layer for performance optimization

## Python Libraries
- **Flask**: Web framework and API development
- **MySQL Connector**: Database connectivity
- **Pandas**: Data manipulation and analysis
- **Scikit-learn**: Machine learning models for threat detection
- **ReportLab**: PDF report generation
- **XlsxWriter**: Excel file export functionality

## Email Processing
- **Python Email Library**: Built-in email parsing capabilities
- **HTML2Text**: HTML content conversion for analysis
- **Base64/QuoPri**: Email encoding/decoding support

## Security and Validation
- **Werkzeug**: Secure filename handling and file utilities
- **Hashlib**: File integrity and security hashing
- **JWT**: Token-based authentication system

## Frontend Libraries
- **Chart.js**: Data visualization and analytics charts
- **Bootstrap/CSS Grid**: Responsive design framework
- **Font Awesome**: Icon system for UI elements

## Development Tools
- **Logging**: Python logging framework with file rotation
- **Threading**: Concurrent processing capabilities
- **UUID**: Unique identifier generation for analysis sessions