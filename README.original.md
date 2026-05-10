# Advanced Cybersecurity Phishing Detection Platform

A comprehensive email analysis system designed to detect phishing attempts and malicious content using machine learning and pattern recognition techniques.

## 🚀 Features

- **Multi-format Email Support**: Analyzes .eml, .msg, and .txt email files
- **Advanced HTML Analysis**: Segment-by-segment analysis with line number tracking
- **Header Analysis**: Comprehensive email header inspection including x-ms-exchange-crosstenant headers
- **Database Storage**: PostgreSQL backend for storing analysis results and statistics
- **Real-time Dashboard**: Interactive web interface with threat analytics
- **Command-line Tools**: CLI utilities for database statistics and batch processing
- **Segment Classification**: Distinguishes single/multiple line and HTML segment types
- **Threat Pattern Recognition**: Detects 15+ threat categories with configurable patterns

## 📊 Dashboard Preview

The platform provides a responsive web dashboard showing:
- Real-time threat statistics
- Risk distribution analytics
- Recent analysis results
- Hourly threat patterns
- Database-driven insights

## 🛠 Technology Stack

- **Backend**: Flask (Python)
- **Database**: PostgreSQL
- **Frontend**: HTML/CSS/JavaScript with Chart.js
- **Email Processing**: Python email library + HTML2Text
- **Pattern Detection**: Regular expressions + configurable threat patterns
- **Documentation**: ReportLab for PDF generation

## 📁 Project Structure

```
phishing-detection-platform/
├── python/
│   ├── simple_app.py              # Main Flask application
│   ├── email_html_analyzer.py     # Email analysis engine
│   ├── database_schema.py         # Database operations
│   ├── database_stats_tool.py     # Command-line statistics
│   ├── generate_documentation.py  # PDF documentation generator
│   └── static/
│       └── index.html             # Web interface
├── test_phishing_email.eml        # Basic test sample
├── test_safe_email.eml            # Safe email sample
├── test_enhanced_phishing_email.eml # Advanced test sample
├── README.md                      # This file
└── Documentation.pdf              # Complete technical documentation
```

## 🔧 Installation

### Prerequisites
- Python 3.8 or higher
- PostgreSQL 12 or higher
- 4GB RAM minimum

### Quick Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/Vikrant892/phishing-detection-platform.git
   cd phishing-detection-platform
   ```

2. **Install PostgreSQL**
   ```bash
   # Ubuntu/Debian
   sudo apt update && sudo apt install postgresql postgresql-contrib
   
   # macOS
   brew install postgresql && brew services start postgresql
   ```

3. **Create database**
   ```bash
   sudo -u postgres psql
   CREATE DATABASE phishing_detection;
   CREATE USER phishing_user WITH PASSWORD '<your-password>';
   GRANT ALL PRIVILEGES ON DATABASE phishing_detection TO phishing_user;
   \q
   ```

4. **Set environment variable**
   ```bash
   export DATABASE_URL="postgresql://phishing_user:<your-password>@localhost:5432/phishing_detection"
   ```

5. **Install Python dependencies**
   ```bash
   pip install flask flask-cors psycopg2-binary html2text email-validator reportlab werkzeug
   ```

6. **Start the application**
   ```bash
   cd python
   python simple_app.py
   ```

7. **Access the web interface**
   Open http://localhost:5000 in your browser

## 🚦 Usage

### Web Interface
- Upload .eml files for analysis
- View real-time dashboard statistics
- Download test samples and documentation
- Monitor threat patterns and trends

### Command Line Tools
```bash
# View all statistics
python database_stats_tool.py all

# View threat patterns
python database_stats_tool.py threats

# Test analyzer with samples
python database_stats_tool.py test

# View dashboard stats
python database_stats_tool.py dashboard
```

### API Endpoints
- `POST /api/upload` - Upload email for analysis
- `GET /api/dashboard-stats` - Get dashboard statistics
- `GET /api/threat-statistics` - Get threat occurrence data
- `POST /api/detailed-report` - Generate detailed HTML report
- `GET /documentation.pdf` - Download complete documentation

## 🧪 Testing

The platform includes three test email samples:

1. **test_phishing_email.eml** - Basic phishing patterns
2. **test_safe_email.eml** - Clean email sample  
3. **test_enhanced_phishing_email.eml** - Advanced threats with headers

### Test Results
- Enhanced test email detects **15 different threat patterns**
- Analyzes **8 suspicious email headers**
- Processes **41 HTML segments**
- Achieves **100/100 threat score** for high-risk classification

## 🔍 Threat Detection Categories

- **Urgent Actions**: "expires in 24 hours", "act now", "verify immediately"
- **Credential Harvesting**: "enter your password", "confirm login"
- **Financial Threats**: "unauthorized transaction", "suspicious activity"
- **Microsoft Exchange**: "crosstenant authentication", "office 365"
- **Suspicious Codes**: Custom patterns like "XFCjGeORft8x7Ol"
- **Header Analysis**: x-ms-exchange-crosstenant headers

## 📋 Database Schema

The system uses PostgreSQL with six main tables:
- **email_analyses**: Main analysis results
- **email_headers**: Header analysis details
- **html_segments**: Segment classification data
- **threat_detections**: Individual threat findings
- **analysis_failures**: Failed analysis tracking
- **threat_statistics**: Aggregated statistics

## 📖 Documentation

Complete technical documentation is available:
- **PDF Documentation**: Comprehensive installation and usage guide
- **API Documentation**: Complete endpoint specifications
- **Database Schema**: Table structure and relationships
- **Troubleshooting Guide**: Common issues and solutions

Download the complete PDF documentation from the web interface or access `/documentation.pdf`.

## 🔒 Security Features

- Input validation and sanitization
- Secure file handling with type validation
- SQL injection prevention with parameterized queries
- Error handling without sensitive data exposure
- Comprehensive logging and audit trails

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is private and proprietary. All rights reserved.

## 🆘 Support

For issues and questions:
1. Check the troubleshooting section in the PDF documentation
2. Review the database logs for error details
3. Verify environment variable configuration
4. Ensure all dependencies are properly installed

## 🎯 Project Goals

This platform was built to provide:
- **Comprehensive email threat analysis** with detailed reporting
- **Database-driven insights** for security analytics
- **Scalable architecture** for production deployment
- **User-friendly interface** for security professionals
- **Complete documentation** for easy deployment and maintenance

---

**Built with security in mind for cybersecurity professionals and researchers.**