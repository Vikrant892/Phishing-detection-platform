"""
Email parsing module for the Phishing Detection Platform
Supports multiple email formats: EML, MSG, TXT
"""

import email
import email.parser
import email.policy
import re
import json
import logging
import os
from typing import Dict, List, Optional, Any
from datetime import datetime
import base64
import quopri
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import html2text

logger = logging.getLogger(__name__)

class EmailParser:
    """Advanced email parser supporting multiple formats"""
    
    def __init__(self):
        self.html_converter = html2text.HTML2Text()
        self.html_converter.ignore_links = True
        self.html_converter.ignore_images = True
        self.html_converter.body_width = 0
    
    def parse_file(self, filepath: str) -> Optional[Dict[str, Any]]:
        """Parse email from file"""
        try:
            if not os.path.exists(filepath):
                logger.error(f"File not found: {filepath}")
                return None
            
            file_extension = os.path.splitext(filepath)[1].lower()
            
            if file_extension == '.eml':
                return self._parse_eml_file(filepath)
            elif file_extension == '.msg':
                return self._parse_msg_file(filepath)
            elif file_extension == '.txt':
                return self._parse_txt_file(filepath)
            else:
                logger.error(f"Unsupported file format: {file_extension}")
                return None
                
        except Exception as e:
            logger.error(f"Error parsing file {filepath}: {e}")
            return None
    
    def parse_content(self, content: str) -> Optional[Dict[str, Any]]:
        """Parse email from raw content string"""
        try:
            # Try to parse as EML format first
            msg = email.message_from_string(content, policy=email.policy.default)
            return self._extract_email_data(msg, content)
            
        except Exception as e:
            logger.error(f"Error parsing email content: {e}")
            return None
    
    def _parse_eml_file(self, filepath: str) -> Optional[Dict[str, Any]]:
        """Parse EML file format"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                raw_content = file.read()
                msg = email.message_from_string(raw_content, policy=email.policy.default)
                return self._extract_email_data(msg, raw_content)
                
        except Exception as e:
            logger.error(f"Error parsing EML file: {e}")
            return None
    
    def _parse_msg_file(self, filepath: str) -> Optional[Dict[str, Any]]:
        """Parse MSG file format (simplified approach)"""
        try:
            # For MSG files, we'll try to read as text and extract what we can
            with open(filepath, 'rb') as file:
                content = file.read()
                
            # Try to decode and extract readable text
            try:
                text_content = content.decode('utf-8', errors='ignore')
            except:
                text_content = str(content, errors='ignore')
            
            # Extract basic information using regex
            email_data = {
                'raw_content': text_content,
                'subject': self._extract_field(text_content, 'Subject'),
                'from': self._extract_field(text_content, 'From'),
                'to': self._extract_field(text_content, 'To'),
                'date': self._extract_field(text_content, 'Date'),
                'body': self._extract_body_from_raw(text_content),
                'headers': self._extract_headers_from_raw(text_content),
                'attachments': [],
                'format': 'MSG'
            }
            
            return email_data
            
        except Exception as e:
            logger.error(f"Error parsing MSG file: {e}")
            return None
    
    def _parse_txt_file(self, filepath: str) -> Optional[Dict[str, Any]]:
        """Parse plain text file"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                content = file.read()
            
            # Try to parse as email first
            try:
                msg = email.message_from_string(content, policy=email.policy.default)
                if msg.get('Subject') or msg.get('From'):
                    return self._extract_email_data(msg, content)
            except:
                pass
            
            # If not an email format, treat as plain text
            email_data = {
                'raw_content': content,
                'subject': 'Plain Text File',
                'from': 'unknown',
                'to': 'unknown',
                'date': datetime.now().isoformat(),
                'body': content,
                'headers': {},
                'attachments': [],
                'format': 'TXT'
            }
            
            return email_data
            
        except Exception as e:
            logger.error(f"Error parsing TXT file: {e}")
            return None
    
    def _extract_email_data(self, msg: email.message.EmailMessage, raw_content: str) -> Dict[str, Any]:
        """Extract comprehensive data from email message"""
        try:
            # Basic headers
            email_data = {
                'raw_content': raw_content,
                'subject': self._decode_header(msg.get('Subject', '')),
                'from': self._decode_header(msg.get('From', '')),
                'to': self._decode_header(msg.get('To', '')),
                'cc': self._decode_header(msg.get('Cc', '')),
                'bcc': self._decode_header(msg.get('Bcc', '')),
                'date': self._decode_header(msg.get('Date', '')),
                'message_id': self._decode_header(msg.get('Message-ID', '')),
                'reply_to': self._decode_header(msg.get('Reply-To', '')),
                'format': 'EML'
            }
            
            # Extract all headers
            headers = {}
            for key, value in msg.items():
                headers[key.lower()] = self._decode_header(value)
            email_data['headers'] = headers
            
            # Extract body content
            body_text, body_html = self._extract_body_content(msg)
            email_data['body'] = body_text
            email_data['body_html'] = body_html
            
            # Extract links
            email_data['links'] = self._extract_links(body_html or body_text)
            
            # Extract attachments
            email_data['attachments'] = self._extract_attachments(msg)
            
            # Extract security headers
            email_data['security_headers'] = self._extract_security_headers(headers)
            
            # Extract suspicious patterns
            email_data['suspicious_patterns'] = self._find_suspicious_patterns(email_data)
            
            return email_data
            
        except Exception as e:
            logger.error(f"Error extracting email data: {e}")
            return None
    
    def _decode_header(self, header_value: str) -> str:
        """Decode email header value"""
        if not header_value:
            return ''
        
        try:
            decoded_parts = email.header.decode_header(header_value)
            decoded_string = ''
            
            for part, encoding in decoded_parts:
                if isinstance(part, bytes):
                    if encoding:
                        decoded_string += part.decode(encoding, errors='ignore')
                    else:
                        decoded_string += part.decode('utf-8', errors='ignore')
                else:
                    decoded_string += str(part)
            
            return decoded_string.strip()
            
        except Exception as e:
            logger.warning(f"Header decode error: {e}")
            return str(header_value)
    
    def _extract_body_content(self, msg: email.message.EmailMessage) -> tuple:
        """Extract text and HTML body content"""
        body_text = ""
        body_html = ""
        
        try:
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_text += payload.decode('utf-8', errors='ignore')
                    elif part.get_content_type() == "text/html":
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_html += payload.decode('utf-8', errors='ignore')
            else:
                # Single part message
                payload = msg.get_payload(decode=True)
                if payload:
                    content = payload.decode('utf-8', errors='ignore')
                    if msg.get_content_type() == "text/html":
                        body_html = content
                        body_text = self.html_converter.handle(content)
                    else:
                        body_text = content
            
            # If no text body but HTML exists, convert HTML to text
            if not body_text and body_html:
                body_text = self.html_converter.handle(body_html)
            
            return body_text.strip(), body_html.strip()
            
        except Exception as e:
            logger.error(f"Body extraction error: {e}")
            return "", ""
    
    def _extract_links(self, content: str) -> List[Dict[str, str]]:
        """Extract links from email content"""
        links = []
        
        if not content:
            return links
        
        try:
            # Extract HTTP/HTTPS URLs
            url_pattern = r'https?://[^\s<>"]{1,}\w'
            urls = re.findall(url_pattern, content, re.IGNORECASE)
            
            for url in urls:
                links.append({
                    'url': url,
                    'type': 'http',
                    'suspicious': self._is_suspicious_url(url)
                })
            
            # Extract email addresses
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            emails = re.findall(email_pattern, content)
            
            for email_addr in emails:
                links.append({
                    'url': email_addr,
                    'type': 'email',
                    'suspicious': self._is_suspicious_email(email_addr)
                })
            
            return links
            
        except Exception as e:
            logger.error(f"Link extraction error: {e}")
            return []
    
    def _extract_attachments(self, msg: email.message.EmailMessage) -> List[Dict[str, Any]]:
        """Extract attachment information"""
        attachments = []
        
        try:
            for part in msg.walk():
                if part.get_content_disposition() == 'attachment':
                    filename = part.get_filename()
                    if filename:
                        attachments.append({
                            'filename': self._decode_header(filename),
                            'content_type': part.get_content_type(),
                            'size': len(part.get_payload(decode=True) or b''),
                            'suspicious': self._is_suspicious_attachment(filename)
                        })
            
            return attachments
            
        except Exception as e:
            logger.error(f"Attachment extraction error: {e}")
            return []
    
    def _extract_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Extract security-related headers"""
        security_headers = {}
        
        security_fields = [
            'x-spam-score', 'x-spam-status', 'x-virus-scanned',
            'authentication-results', 'dkim-signature', 'arc-authentication-results',
            'x-ms-exchange-crosstenant-id', 'x-ms-exchange-crosstenant-userprincipalname',
            'x-originating-ip', 'x-forefront-antispam-report'
        ]
        
        for field in security_fields:
            if field in headers:
                security_headers[field] = headers[field]
        
        return security_headers
    
    def _find_suspicious_patterns(self, email_data: Dict[str, Any]) -> List[Dict[str, str]]:
        """Find basic suspicious patterns in email"""
        patterns = []
        content = f"{email_data.get('subject', '')} {email_data.get('body', '')}"
        
        # Common phishing keywords
        suspicious_keywords = [
            'urgent', 'verify account', 'suspended', 'click here',
            'limited time', 'act now', 'confirm identity', 'update payment',
            'security alert', 'unauthorized access', 'immediate action'
        ]
        
        for keyword in suspicious_keywords:
            if keyword.lower() in content.lower():
                patterns.append({
                    'pattern': keyword,
                    'type': 'keyword',
                    'severity': 'medium'
                })
        
        return patterns
    
    def _is_suspicious_url(self, url: str) -> bool:
        """Check if URL is suspicious"""
        suspicious_indicators = [
            'bit.ly', 'tinyurl', 'shortened',
            'phishing', 'malware', 'suspicious'
        ]
        
        return any(indicator in url.lower() for indicator in suspicious_indicators)
    
    def _is_suspicious_email(self, email_addr: str) -> bool:
        """Check if email address is suspicious"""
        suspicious_domains = [
            'tempmail', 'guerrillamail', '10minutemail',
            'mailinator', 'disposable'
        ]
        
        return any(domain in email_addr.lower() for domain in suspicious_domains)
    
    def _is_suspicious_attachment(self, filename: str) -> bool:
        """Check if attachment is suspicious"""
        suspicious_extensions = [
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif',
            '.vbs', '.js', '.jar', '.zip', '.rar'
        ]
        
        return any(filename.lower().endswith(ext) for ext in suspicious_extensions)
    
    def _extract_field(self, content: str, field_name: str) -> str:
        """Extract field from raw content using regex"""
        pattern = f"{field_name}:\s*(.+?)(?:\n|$)"
        match = re.search(pattern, content, re.IGNORECASE | re.MULTILINE)
        return match.group(1).strip() if match else ''
    
    def _extract_headers_from_raw(self, content: str) -> Dict[str, str]:
        """Extract headers from raw content"""
        headers = {}
        lines = content.split('\n')
        
        for line in lines:
            if ':' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    key = parts[0].strip().lower()
                    value = parts[1].strip()
                    headers[key] = value
        
        return headers
    
    def _extract_body_from_raw(self, content: str) -> str:
        """Extract body from raw content"""
        # Look for double newline that typically separates headers from body
        body_start = content.find('\n\n')
        if body_start != -1:
            return content[body_start + 2:].strip()
        
        # If no clear separation, return the content
        return content
