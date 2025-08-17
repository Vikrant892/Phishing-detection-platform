"""
Utility Helper Functions for Phishing Detection Platform
"""

import re
import hashlib
import os
import logging
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union, Tuple
import urllib.parse
from functools import wraps

logger = logging.getLogger(__name__)

def create_response(success: bool, message: str, data: Any = None, error: str = None, 
                   status_code: int = None) -> Dict[str, Any]:
    """
    Create standardized API response
    
    Args:
        success: Whether the operation was successful
        message: Response message
        data: Response data (optional)
        error: Error message (optional)
        status_code: HTTP status code (optional)
        
    Returns:
        Standardized response dictionary
    """
    response = {
        'success': success,
        'message': message,
        'timestamp': datetime.now().isoformat()
    }
    
    if data is not None:
        response['data'] = data
    
    if error is not None:
        response['error'] = error
    
    if status_code is not None:
        response['status_code'] = status_code
    
    return response

def validate_request_data(data: Dict[str, Any], required_fields: List[str]) -> Dict[str, Any]:
    """
    Validate request data for required fields
    
    Args:
        data: Request data dictionary
        required_fields: List of required field names
        
    Returns:
        Validation result with response if invalid
    """
    missing_fields = []
    
    for field in required_fields:
        if field not in data or data[field] is None or data[field] == '':
            missing_fields.append(field)
    
    if missing_fields:
        return {
            'valid': False,
            'response': create_response(
                success=False,
                message="Missing required fields",
                error=f"Required fields missing: {', '.join(missing_fields)}"
            )
        }
    
    return {'valid': True, 'response': None}

def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for safe storage
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    # Remove path components
    filename = os.path.basename(filename)
    
    # Replace dangerous characters
    filename = re.sub(r'[^\w\-_\.]', '_', filename)
    
    # Remove multiple underscores
    filename = re.sub(r'_+', '_', filename)
    
    # Ensure filename is not empty
    if not filename or filename == '_':
        filename = f"file_{uuid.uuid4().hex[:8]}"
    
    # Limit filename length
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:250 - len(ext)] + ext
    
    return filename

def get_file_hash(file_path: str, algorithm: str = 'sha256') -> str:
    """
    Calculate file hash
    
    Args:
        file_path: Path to file
        algorithm: Hash algorithm (md5, sha1, sha256)
        
    Returns:
        File hash as hex string
    """
    try:
        hash_obj = hashlib.new(algorithm)
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        
        return hash_obj.hexdigest()
    except Exception as e:
        logger.error(f"Failed to calculate file hash: {str(e)}")
        return ""

def calculate_risk_score(threat_analysis: Dict[str, Any]) -> float:
    """
    Calculate overall risk score from threat analysis
    
    Args:
        threat_analysis: Threat analysis results
        
    Returns:
        Risk score (0-100)
    """
    score = 0.0
    weights = {
        'header_threats': 0.25,
        'content_threats': 0.35,
        'attachment_threats': 0.20,
        'pattern_matches': 0.15,
        'reputation_analysis': 0.05
    }
    
    # Header threats
    header_threats = threat_analysis.get('header_threats', {})
    header_score = 0
    for category, threats in header_threats.items():
        if isinstance(threats, list):
            header_score += sum(threat.get('risk_score', 0) for threat in threats)
    score += min(header_score, 100) * weights['header_threats']
    
    # Content threats
    content_threats = threat_analysis.get('content_threats', {})
    content_score = 0
    for category, threats in content_threats.items():
        if isinstance(threats, list):
            content_score += sum(threat.get('risk_score', 0) for threat in threats)
    score += min(content_score, 100) * weights['content_threats']
    
    # Attachment threats
    attachment_threats = threat_analysis.get('attachment_threats', {})
    attachment_score = 0
    for category, threats in attachment_threats.items():
        if isinstance(threats, list):
            attachment_score += sum(threat.get('risk_score', 0) for threat in threats)
    score += min(attachment_score, 100) * weights['attachment_threats']
    
    # Pattern matches
    pattern_matches = threat_analysis.get('pattern_matches', [])
    pattern_score = sum(match.get('risk_score', 0) for match in pattern_matches)
    score += min(pattern_score, 100) * weights['pattern_matches']
    
    # Reputation analysis
    reputation = threat_analysis.get('reputation_analysis', {})
    rep_score = 100 - reputation.get('reputation_score', 50)
    score += rep_score * weights['reputation_analysis']
    
    return min(score, 100.0)

def extract_urls(content: str) -> List[str]:
    """
    Extract URLs from content
    
    Args:
        content: Text content
        
    Returns:
        List of extracted URLs
    """
    url_patterns = [
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
        r'www\.(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
        r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?'
    ]
    
    urls = []
    for pattern in url_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        urls.extend(matches)
    
    # Deduplicate and filter
    unique_urls = list(set(urls))
    filtered_urls = []
    
    for url in unique_urls:
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            if url.startswith('www.'):
                url = 'http://' + url
            else:
                # Skip if it doesn't look like a proper URL
                if '.' not in url:
                    continue
                url = 'http://' + url
        
        # Basic URL validation
        try:
            parsed = urllib.parse.urlparse(url)
            if parsed.netloc:
                filtered_urls.append(url)
        except:
            continue
    
    return filtered_urls

def extract_ip_addresses(content: str) -> List[str]:
    """
    Extract IP addresses from content
    
    Args:
        content: Text content
        
    Returns:
        List of extracted IP addresses
    """
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    matches = re.findall(ip_pattern, content)
    
    # Validate IP addresses
    valid_ips = []
    for ip in matches:
        parts = ip.split('.')
        if all(0 <= int(part) <= 255 for part in parts):
            valid_ips.append(ip)
    
    return list(set(valid_ips))

def extract_email_addresses(content: str) -> List[str]:
    """
    Extract email addresses from content
    
    Args:
        content: Text content
        
    Returns:
        List of extracted email addresses
    """
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    matches = re.findall(email_pattern, content)
    return list(set(matches))

def is_suspicious_url(url: str) -> bool:
    """
    Check if URL is suspicious
    
    Args:
        url: URL to check
        
    Returns:
        True if URL is suspicious
    """
    suspicious_patterns = [
        r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',  # IP addresses
        r'bit\.ly', r'tinyurl', r't\.co',  # URL shorteners
        r'[a-z0-9]+\.(tk|ml|ga|cf)\b',  # Suspicious TLDs
        r'secure.*update.*account',  # Security-themed phishing
        r'[a-z]\.{3,}[a-z]',  # Excessive dots
        r'-{3,}',  # Excessive dashes
        r'[0-9]{5,}',  # Long numbers in domain
    ]
    
    return any(re.search(pattern, url, re.IGNORECASE) for pattern in suspicious_patterns)

def normalize_domain(domain: str) -> str:
    """
    Normalize domain name
    
    Args:
        domain: Domain name
        
    Returns:
        Normalized domain
    """
    domain = domain.lower().strip()
    
    # Remove protocol
    domain = re.sub(r'^https?://', '', domain)
    
    # Remove www prefix
    domain = re.sub(r'^www\.', '', domain)
    
    # Remove path
    domain = domain.split('/')[0]
    
    # Remove port
    domain = domain.split(':')[0]
    
    return domain

def setup_logging():
    """Setup logging configuration"""
    log_dir = os.path.join(os.getcwd(), 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    log_file = os.path.join(log_dir, 'phishing_detector.log')
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )

def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human readable format
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        Formatted size string
    """
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.1f} {size_names[i]}"

def parse_duration(duration_str: str) -> timedelta:
    """
    Parse duration string to timedelta
    
    Args:
        duration_str: Duration string (e.g., "1h", "30m", "1d")
        
    Returns:
        timedelta object
    """
    pattern = r'(\d+)([smhd])'
    match = re.match(pattern, duration_str.lower())
    
    if not match:
        raise ValueError(f"Invalid duration format: {duration_str}")
    
    value, unit = match.groups()
    value = int(value)
    
    unit_map = {
        's': 'seconds',
        'm': 'minutes', 
        'h': 'hours',
        'd': 'days'
    }
    
    kwargs = {unit_map[unit]: value}
    return timedelta(**kwargs)

def generate_session_id() -> str:
    """Generate unique session ID"""
    return uuid.uuid4().hex

def mask_sensitive_data(data: str, mask_char: str = '*', visible_chars: int = 4) -> str:
    """
    Mask sensitive data for logging
    
    Args:
        data: Data to mask
        mask_char: Character to use for masking
        visible_chars: Number of characters to keep visible
        
    Returns:
        Masked data string
    """
    if not data or len(data) <= visible_chars:
        return mask_char * len(data)
    
    visible_part = data[:visible_chars]
    masked_part = mask_char * (len(data) - visible_chars)
    
    return visible_part + masked_part

def validate_email_address(email: str) -> bool:
    """
    Validate email address format
    
    Args:
        email: Email address to validate
        
    Returns:
        True if email is valid
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def truncate_text(text: str, max_length: int = 100, suffix: str = '...') -> str:
    """
    Truncate text to specified length
    
    Args:
        text: Text to truncate
        max_length: Maximum length
        suffix: Suffix to add if truncated
        
    Returns:
        Truncated text
    """
    if len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix

def safe_json_loads(json_str: str, default: Any = None) -> Any:
    """
    Safely load JSON string
    
    Args:
        json_str: JSON string
        default: Default value if parsing fails
        
    Returns:
        Parsed JSON or default value
    """
    try:
        return json.loads(json_str)
    except (json.JSONDecodeError, TypeError):
        return default

def require_auth(f):
    """Decorator for endpoints requiring authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Simple auth check - in production, implement proper JWT validation
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return create_response(
                success=False,
                message="Authentication required",
                error="Missing or invalid authorization header"
            ), 401
        
        return f(*args, **kwargs)
    return decorated_function

def rate_limit_key(identifier: str, window: str = '1h') -> str:
    """Generate rate limit key"""
    timestamp = datetime.now().replace(minute=0, second=0, microsecond=0)
    return f"rate_limit:{identifier}:{window}:{timestamp.isoformat()}"

def clean_html(html_content: str) -> str:
    """
    Clean HTML content and extract text
    
    Args:
        html_content: HTML content
        
    Returns:
        Clean text content
    """
    # Remove HTML tags
    clean_text = re.sub(r'<[^>]+>', '', html_content)
    
    # Decode HTML entities
    html_entities = {
        '&amp;': '&',
        '&lt;': '<',
        '&gt;': '>',
        '&quot;': '"',
        '&#39;': "'",
        '&nbsp;': ' '
    }
    
    for entity, char in html_entities.items():
        clean_text = clean_text.replace(entity, char)
    
    # Remove extra whitespace
    clean_text = re.sub(r'\s+', ' ', clean_text).strip()
    
    return clean_text

def detect_encoding(data: bytes) -> str:
    """
    Detect text encoding
    
    Args:
        data: Byte data
        
    Returns:
        Detected encoding
    """
    encodings = ['utf-8', 'latin1', 'cp1252', 'iso-8859-1']
    
    for encoding in encodings:
        try:
            data.decode(encoding)
            return encoding
        except UnicodeDecodeError:
            continue
    
    return 'utf-8'  # Default fallback

def create_secure_filename(original_filename: str) -> str:
    """
    Create secure filename with timestamp
    
    Args:
        original_filename: Original filename
        
    Returns:
        Secure filename with timestamp
    """
    # Sanitize the filename
    safe_name = sanitize_filename(original_filename)
    
    # Add timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    name, ext = os.path.splitext(safe_name)
    
    return f"{timestamp}_{name}{ext}"

def validate_file_type(filename: str, allowed_extensions: List[str]) -> bool:
    """
    Validate file type by extension
    
    Args:
        filename: Filename to validate
        allowed_extensions: List of allowed extensions
        
    Returns:
        True if file type is allowed
    """
    if not filename:
        return False
    
    ext = os.path.splitext(filename)[1].lower()
    return ext in [e.lower() for e in allowed_extensions]

def get_client_ip(request) -> str:
    """
    Get client IP address from request
    
    Args:
        request: Flask request object
        
    Returns:
        Client IP address
    """
    # Check for forwarded IP first
    forwarded_ip = request.headers.get('X-Forwarded-For')
    if forwarded_ip:
        return forwarded_ip.split(',')[0].strip()
    
    # Check for real IP
    real_ip = request.headers.get('X-Real-IP')
    if real_ip:
        return real_ip
    
    # Fallback to remote address
    return request.remote_addr or 'unknown'

def format_timestamp(timestamp: datetime, format_str: str = '%Y-%m-%d %H:%M:%S') -> str:
    """
    Format timestamp to string
    
    Args:
        timestamp: Datetime object
        format_str: Format string
        
    Returns:
        Formatted timestamp string
    """
    try:
        return timestamp.strftime(format_str)
    except:
        return str(timestamp)

def chunks(lst: List[Any], n: int) -> List[List[Any]]:
    """
    Yield successive n-sized chunks from list
    
    Args:
        lst: List to chunk
        n: Chunk size
        
    Returns:
        Generator yielding chunks
    """
    for i in range(0, len(lst), n):
        yield lst[i:i + n]
