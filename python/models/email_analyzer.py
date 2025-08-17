"""
Email Analyzer - Core email analysis and threat detection
"""

import email
import re
import hashlib
import mimetypes
import base64
from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional
import logging

from models.threat_detector import ThreatDetector
from utils.helpers import calculate_risk_score, extract_urls, extract_ip_addresses

logger = logging.getLogger(__name__)

class EmailAnalyzer:
    """Advanced email analyzer with comprehensive threat detection"""
    
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.threat_detector = ThreatDetector(db_manager)
        
        # Suspicious patterns for quick detection
        self.suspicious_patterns = {
            'urgent_words': [
                r'\burgent\b', r'\bemergency\b', r'\bimmediate\b', r'\basap\b',
                r'\bexpir[ey]\b', r'\bsuspend\b', r'\bverify\b', r'\bupdate\b'
            ],
            'financial_words': [
                r'\bmoney\b', r'\bbank\b', r'\bcredit\b', r'\bpayment\b',
                r'\btransfer\b', r'\baccount\b', r'\bwire\b', r'\brefund\b'
            ],
            'suspicious_domains': [
                r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',  # IP addresses
                r'[a-z0-9-]+\.tk\b', r'[a-z0-9-]+\.ml\b', r'[a-z0-9-]+\.ga\b'
            ],
            'encoding_tricks': [
                r'&#[0-9]+;', r'%[0-9a-f]{2}', r'[a-z]\.{3,}[a-z]'
            ]
        }
    
    def analyze_email(self, email_content: str, source_file: str = None) -> Dict[str, Any]:
        """
        Comprehensive email analysis
        
        Args:
            email_content: Raw email content
            source_file: Optional source file path
            
        Returns:
            Complete analysis results
        """
        try:
            # Parse email
            msg = email.message_from_string(email_content)
            
            # Extract email components
            headers = self._extract_headers(msg)
            body_parts = self._extract_body_parts(msg)
            attachments = self._extract_attachments(msg)
            metadata = self._extract_metadata(msg)
            
            # Generate email fingerprint
            email_hash = self._generate_email_hash(email_content)
            
            # Perform threat analysis
            threat_analysis = self.threat_detector.analyze_threats({
                'headers': headers,
                'body_parts': body_parts,
                'attachments': attachments,
                'metadata': metadata,
                'raw_content': email_content
            })
            
            # Calculate overall risk score
            risk_score = calculate_risk_score(threat_analysis)
            
            # Determine threat level
            threat_level = self._determine_threat_level(risk_score)
            
            # Generate analysis result
            analysis_result = {
                'email_hash': email_hash,
                'source_file': source_file,
                'timestamp': datetime.now().isoformat(),
                'headers': headers,
                'body_parts': body_parts,
                'attachments': attachments,
                'metadata': metadata,
                'threat_analysis': threat_analysis,
                'risk_score': risk_score,
                'threat_level': threat_level,
                'recommendations': self._generate_recommendations(threat_analysis, risk_score),
                'technical_details': self._extract_technical_details(msg)
            }
            
            # Store in database
            self._store_analysis_result(analysis_result)
            
            logger.info(f"Email analysis completed - Risk Score: {risk_score}, Threat Level: {threat_level}")
            return analysis_result
            
        except Exception as e:
            logger.error(f"Email analysis failed: {str(e)}")
            raise Exception(f"Email analysis failed: {str(e)}")
    
    def _extract_headers(self, msg: email.message.Message) -> Dict[str, Any]:
        """Extract and analyze email headers"""
        headers = {}
        
        # Standard headers
        standard_headers = [
            'From', 'To', 'Cc', 'Bcc', 'Subject', 'Date', 'Message-ID',
            'Return-Path', 'Reply-To', 'Sender', 'Organization'
        ]
        
        for header in standard_headers:
            value = msg.get(header, '')
            headers[header.lower().replace('-', '_')] = value
        
        # Security headers
        security_headers = [
            'X-Originating-IP', 'X-Sender-IP', 'X-MS-Exchange-CrossTenant-Id',
            'X-MS-Exchange-CrossTenant-UserPrincipalName', 'Authentication-Results',
            'DKIM-Signature', 'DomainKey-Signature', 'Received-SPF'
        ]
        
        for header in security_headers:
            value = msg.get(header, '')
            headers[header.lower().replace('-', '_')] = value
        
        # Received headers (trace route)
        received_headers = msg.get_all('Received', [])
        headers['received_trace'] = received_headers
        
        # Custom threat indicators
        headers['threat_indicators'] = self._analyze_header_threats(headers)
        
        return headers
    
    def _extract_body_parts(self, msg: email.message.Message) -> List[Dict[str, Any]]:
        """Extract and analyze email body parts"""
        body_parts = []
        
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type().startswith('text/'):
                    body_part = self._process_body_part(part)
                    if body_part:
                        body_parts.append(body_part)
        else:
            body_part = self._process_body_part(msg)
            if body_part:
                body_parts.append(body_part)
        
        return body_parts
    
    def _process_body_part(self, part: email.message.Message) -> Optional[Dict[str, Any]]:
        """Process individual body part"""
        try:
            content_type = part.get_content_type()
            charset = part.get_content_charset() or 'utf-8'
            
            # Get content
            content = part.get_payload(decode=True)
            if isinstance(content, bytes):
                content = content.decode(charset, errors='ignore')
            
            if not content:
                return None
            
            # Analyze content
            urls = extract_urls(content)
            ip_addresses = extract_ip_addresses(content)
            suspicious_patterns = self._find_suspicious_patterns(content)
            
            return {
                'content_type': content_type,
                'charset': charset,
                'content': content,
                'length': len(content),
                'urls': urls,
                'ip_addresses': ip_addresses,
                'suspicious_patterns': suspicious_patterns,
                'threat_score': self._calculate_content_threat_score(content, urls, suspicious_patterns)
            }
            
        except Exception as e:
            logger.warning(f"Failed to process body part: {str(e)}")
            return None
    
    def _extract_attachments(self, msg: email.message.Message) -> List[Dict[str, Any]]:
        """Extract and analyze email attachments"""
        attachments = []
        
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_disposition() == 'attachment':
                    attachment_info = self._analyze_attachment(part)
                    if attachment_info:
                        attachments.append(attachment_info)
        
        return attachments
    
    def _analyze_attachment(self, part: email.message.Message) -> Optional[Dict[str, Any]]:
        """Analyze individual attachment"""
        try:
            filename = part.get_filename()
            if not filename:
                return None
            
            content = part.get_payload(decode=True)
            if not content:
                return None
            
            # Calculate file hash
            file_hash = hashlib.sha256(content).hexdigest()
            
            # Determine file type
            content_type = part.get_content_type()
            mime_type, _ = mimetypes.guess_type(filename)
            
            # Analyze threat level
            threat_level = self._analyze_attachment_threat(filename, content_type, content)
            
            return {
                'filename': filename,
                'content_type': content_type,
                'mime_type': mime_type,
                'size': len(content),
                'hash': file_hash,
                'threat_level': threat_level,
                'is_executable': self._is_executable_file(filename),
                'is_archive': self._is_archive_file(filename)
            }
            
        except Exception as e:
            logger.warning(f"Failed to analyze attachment: {str(e)}")
            return None
    
    def _extract_metadata(self, msg: email.message.Message) -> Dict[str, Any]:
        """Extract email metadata"""
        return {
            'message_size': len(str(msg)),
            'header_count': len(msg.keys()),
            'is_multipart': msg.is_multipart(),
            'encoding': msg.get_content_charset() or 'unknown',
            'content_type': msg.get_content_type(),
            'boundary': msg.get_boundary(),
            'creation_time': datetime.now().isoformat()
        }
    
    def _generate_email_hash(self, email_content: str) -> str:
        """Generate unique hash for email"""
        return hashlib.sha256(email_content.encode('utf-8')).hexdigest()
    
    def _analyze_header_threats(self, headers: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze headers for threat indicators"""
        threats = []
        
        # Check for spoofed sender
        if headers.get('from') and headers.get('return_path'):
            if self._is_sender_spoofed(headers['from'], headers['return_path']):
                threats.append({
                    'type': 'sender_spoofing',
                    'severity': 'high',
                    'description': 'Potential sender spoofing detected'
                })
        
        # Check for suspicious originating IP
        originating_ip = headers.get('x_originating_ip', '')
        if originating_ip and self._is_suspicious_ip(originating_ip):
            threats.append({
                'type': 'suspicious_ip',
                'severity': 'medium',
                'description': f'Suspicious originating IP: {originating_ip}'
            })
        
        return threats
    
    def _find_suspicious_patterns(self, content: str) -> List[Dict[str, Any]]:
        """Find suspicious patterns in content"""
        patterns_found = []
        
        for category, patterns in self.suspicious_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    patterns_found.append({
                        'category': category,
                        'pattern': pattern,
                        'match': match.group(),
                        'position': match.span(),
                        'context': content[max(0, match.start()-50):match.end()+50]
                    })
        
        return patterns_found
    
    def _calculate_content_threat_score(self, content: str, urls: List[str], patterns: List[Dict]) -> float:
        """Calculate threat score for content"""
        score = 0.0
        
        # Base score from suspicious patterns
        score += len(patterns) * 10
        
        # URL analysis
        for url in urls:
            if self._is_suspicious_url(url):
                score += 20
        
        # Content analysis
        if len(content) < 50:  # Very short emails are suspicious
            score += 15
        
        if self._has_urgency_indicators(content):
            score += 25
        
        return min(score, 100.0)  # Cap at 100
    
    def _determine_threat_level(self, risk_score: float) -> str:
        """Determine threat level based on risk score"""
        if risk_score >= 80:
            return 'critical'
        elif risk_score >= 60:
            return 'high'
        elif risk_score >= 40:
            return 'medium'
        elif risk_score >= 20:
            return 'low'
        else:
            return 'minimal'
    
    def _generate_recommendations(self, threat_analysis: Dict, risk_score: float) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if risk_score >= 80:
            recommendations.append("IMMEDIATE ACTION REQUIRED: Quarantine this email immediately")
            recommendations.append("Do not click any links or open attachments")
            recommendations.append("Report to security team")
        elif risk_score >= 60:
            recommendations.append("HIGH RISK: Exercise extreme caution")
            recommendations.append("Verify sender through alternative communication")
            recommendations.append("Do not provide sensitive information")
        elif risk_score >= 40:
            recommendations.append("MEDIUM RISK: Be cautious with this email")
            recommendations.append("Verify suspicious links before clicking")
        elif risk_score >= 20:
            recommendations.append("LOW RISK: Minor concerns detected")
            recommendations.append("Standard caution advised")
        else:
            recommendations.append("MINIMAL RISK: Email appears legitimate")
        
        return recommendations
    
    def _extract_technical_details(self, msg: email.message.Message) -> Dict[str, Any]:
        """Extract technical details for analysis"""
        return {
            'message_id': msg.get('Message-ID', ''),
            'mime_version': msg.get('MIME-Version', ''),
            'user_agent': msg.get('User-Agent', ''),
            'x_mailer': msg.get('X-Mailer', ''),
            'content_encoding': msg.get('Content-Transfer-Encoding', ''),
            'precedence': msg.get('Precedence', ''),
            'list_unsubscribe': msg.get('List-Unsubscribe', '')
        }
    
    def _store_analysis_result(self, result: Dict[str, Any]) -> None:
        """Store analysis result in database"""
        try:
            self.db_manager.store_email_analysis(result)
        except Exception as e:
            logger.error(f"Failed to store analysis result: {str(e)}")
    
    # Helper methods
    def _is_sender_spoofed(self, from_header: str, return_path: str) -> bool:
        """Check if sender might be spoofed"""
        # Simplified spoofing detection
        return from_header.lower() != return_path.lower()
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP is suspicious"""
        # Placeholder for IP reputation checking
        return False
    
    def _is_suspicious_url(self, url: str) -> bool:
        """Check if URL is suspicious"""
        suspicious_indicators = [
            r'bit\.ly', r'tinyurl', r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',
            r'[a-z0-9]+\.tk', r'[a-z0-9]+\.ml'
        ]
        return any(re.search(pattern, url, re.IGNORECASE) for pattern in suspicious_indicators)
    
    def _has_urgency_indicators(self, content: str) -> bool:
        """Check for urgency indicators"""
        urgency_words = ['urgent', 'immediate', 'expire', 'suspend', 'verify', 'update', 'act now']
        return any(word in content.lower() for word in urgency_words)
    
    def _analyze_attachment_threat(self, filename: str, content_type: str, content: bytes) -> str:
        """Analyze attachment threat level"""
        if self._is_executable_file(filename):
            return 'high'
        elif self._is_archive_file(filename):
            return 'medium'
        elif content_type.startswith('image/') and len(content) > 10*1024*1024:  # Large images
            return 'low'
        else:
            return 'minimal'
    
    def _is_executable_file(self, filename: str) -> bool:
        """Check if file is executable"""
        executable_extensions = ['.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js']
        return any(filename.lower().endswith(ext) for ext in executable_extensions)
    
    def _is_archive_file(self, filename: str) -> bool:
        """Check if file is an archive"""
        archive_extensions = ['.zip', '.rar', '.7z', '.tar', '.gz']
        return any(filename.lower().endswith(ext) for ext in archive_extensions)
