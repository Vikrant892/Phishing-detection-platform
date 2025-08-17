"""
Email Parser Module - Advanced email parsing and content extraction
"""

import email
import email.utils
import mimetypes
import os
import re
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging
import base64
import quopri

class EmailParser:
    """Advanced email parser supporting multiple formats and content extraction"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.supported_formats = ['.eml', '.msg', '.txt']
        
    def parse_email_file(self, filepath: str) -> Dict[str, Any]:
        """Parse email file and extract comprehensive information"""
        try:
            file_extension = os.path.splitext(filepath)[1].lower()
            
            if file_extension not in self.supported_formats:
                raise ValueError(f"Unsupported file format: {file_extension}")
            
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            if file_extension == '.eml':
                return self._parse_eml(content)
            elif file_extension == '.msg':
                return self._parse_msg(content)
            else:  # .txt
                return self._parse_text(content)
                
        except Exception as e:
            self.logger.error(f"Email parsing error: {str(e)}")
            raise
    
    def _parse_eml(self, content: str) -> Dict[str, Any]:
        """Parse EML format email"""
        try:
            msg = email.message_from_string(content)
            
            # Extract basic headers
            headers = self._extract_headers(msg)
            
            # Extract body content
            body_parts = self._extract_body_parts(msg)
            
            # Extract attachments
            attachments = self._extract_attachments(msg)
            
            # Extract metadata
            metadata = self._extract_metadata(msg)
            
            return {
                'format': 'eml',
                'headers': headers,
                'body': body_parts,
                'attachments': attachments,
                'metadata': metadata,
                'raw_content': content,
                'parsed_date': datetime.utcnow().isoformat(),
                'segments': self._identify_segments(content)
            }
            
        except Exception as e:
            self.logger.error(f"EML parsing error: {str(e)}")
            raise
    
    def _parse_msg(self, content: str) -> Dict[str, Any]:
        """Parse MSG format email (simplified text-based parsing)"""
        try:
            # Basic MSG parsing - in real implementation would use python-msg library
            lines = content.split('\n')
            
            headers = {}
            body_content = []
            in_body = False
            
            for line in lines:
                if not in_body:
                    if ':' in line and not line.startswith(' '):
                        key, value = line.split(':', 1)
                        headers[key.strip().lower()] = value.strip()
                    elif line.strip() == '':
                        in_body = True
                else:
                    body_content.append(line)
            
            return {
                'format': 'msg',
                'headers': headers,
                'body': {
                    'plain': '\n'.join(body_content),
                    'html': '',
                    'parts': []
                },
                'attachments': [],
                'metadata': {
                    'size': len(content),
                    'line_count': len(lines)
                },
                'raw_content': content,
                'parsed_date': datetime.utcnow().isoformat(),
                'segments': self._identify_segments(content)
            }
            
        except Exception as e:
            self.logger.error(f"MSG parsing error: {str(e)}")
            raise
    
    def _parse_text(self, content: str) -> Dict[str, Any]:
        """Parse plain text email"""
        try:
            lines = content.split('\n')
            
            # Try to identify headers in text format
            headers = {}
            body_start = 0
            
            for i, line in enumerate(lines):
                if ':' in line and not line.startswith(' '):
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
                elif line.strip() == '' and headers:
                    body_start = i + 1
                    break
            
            body_content = '\n'.join(lines[body_start:])
            
            return {
                'format': 'txt',
                'headers': headers,
                'body': {
                    'plain': body_content,
                    'html': '',
                    'parts': []
                },
                'attachments': [],
                'metadata': {
                    'size': len(content),
                    'line_count': len(lines)
                },
                'raw_content': content,
                'parsed_date': datetime.utcnow().isoformat(),
                'segments': self._identify_segments(content)
            }
            
        except Exception as e:
            self.logger.error(f"Text parsing error: {str(e)}")
            raise
    
    def _extract_headers(self, msg: email.message.Message) -> Dict[str, str]:
        """Extract email headers"""
        headers = {}
        
        # Standard headers
        standard_headers = [
            'from', 'to', 'cc', 'bcc', 'subject', 'date',
            'message-id', 'reply-to', 'return-path', 'received'
        ]
        
        for header in standard_headers:
            value = msg.get(header)
            if value:
                headers[header] = str(value)
        
        # Security headers
        security_headers = [
            'x-mailer', 'x-originating-ip', 'x-sender-ip',
            'x-ms-exchange-crosstenant-id', 'x-ms-exchange-crosstenant-userprincipalname',
            'authentication-results', 'dkim-signature', 'spf'
        ]
        
        for header in security_headers:
            value = msg.get(header)
            if value:
                headers[header] = str(value)
        
        # Custom headers (X-* headers)
        for key, value in msg.items():
            if key.lower().startswith('x-') and key.lower() not in headers:
                headers[key.lower()] = str(value)
        
        return headers
    
    def _extract_body_parts(self, msg: email.message.Message) -> Dict[str, Any]:
        """Extract email body parts"""
        body_parts = {
            'plain': '',
            'html': '',
            'parts': []
        }
        
        try:
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get('Content-Disposition', ''))
                    
                    if 'attachment' not in content_disposition:
                        if content_type == 'text/plain':
                            body_parts['plain'] += self._decode_content(part)
                        elif content_type == 'text/html':
                            body_parts['html'] += self._decode_content(part)
                        
                        body_parts['parts'].append({
                            'content_type': content_type,
                            'content': self._decode_content(part)
                        })
            else:
                content_type = msg.get_content_type()
                content = self._decode_content(msg)
                
                if content_type == 'text/plain':
                    body_parts['plain'] = content
                elif content_type == 'text/html':
                    body_parts['html'] = content
                
                body_parts['parts'].append({
                    'content_type': content_type,
                    'content': content
                })
        
        except Exception as e:
            self.logger.error(f"Body extraction error: {str(e)}")
        
        return body_parts
    
    def _extract_attachments(self, msg: email.message.Message) -> List[Dict[str, Any]]:
        """Extract email attachments metadata"""
        attachments = []
        
        try:
            if msg.is_multipart():
                for part in msg.walk():
                    content_disposition = str(part.get('Content-Disposition', ''))
                    
                    if 'attachment' in content_disposition:
                        filename = part.get_filename()
                        if filename:
                            attachments.append({
                                'filename': filename,
                                'content_type': part.get_content_type(),
                                'size': len(part.get_payload(decode=True) or b''),
                                'content_disposition': content_disposition
                            })
        
        except Exception as e:
            self.logger.error(f"Attachment extraction error: {str(e)}")
        
        return attachments
    
    def _extract_metadata(self, msg: email.message.Message) -> Dict[str, Any]:
        """Extract email metadata"""
        return {
            'is_multipart': msg.is_multipart(),
            'content_type': msg.get_content_type(),
            'charset': msg.get_content_charset(),
            'size': len(str(msg)),
            'part_count': len(list(msg.walk())) if msg.is_multipart() else 1
        }
    
    def _decode_content(self, part: email.message.Message) -> str:
        """Decode email content based on encoding"""
        try:
            payload = part.get_payload(decode=True)
            if payload is None:
                return str(part.get_payload())
            
            charset = part.get_content_charset() or 'utf-8'
            return payload.decode(charset, errors='ignore')
        
        except Exception as e:
            self.logger.error(f"Content decoding error: {str(e)}")
            return str(part.get_payload())
    
    def _identify_segments(self, content: str) -> Dict[str, List[Dict[str, Any]]]:
        """Identify different segments in email content"""
        segments = {
            'headers': [],
            'body': [],
            'html_tags': [],
            'links': [],
            'custom_segments': []
        }
        
        lines = content.split('\n')
        
        # Identify header segments
        in_headers = True
        header_start = 0
        
        for i, line in enumerate(lines):
            if in_headers:
                if line.strip() == '':
                    segments['headers'].append({
                        'start_line': header_start + 1,
                        'end_line': i,
                        'content': '\n'.join(lines[header_start:i])
                    })
                    in_headers = False
                    body_start = i + 1
            
            # Identify HTML segments
            html_pattern = r'<[^>]+>'
            if re.search(html_pattern, line):
                segments['html_tags'].append({
                    'line_number': i + 1,
                    'content': line,
                    'tags': re.findall(html_pattern, line)
                })
            
            # Identify links
            url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            urls = re.findall(url_pattern, line)
            if urls:
                segments['links'].append({
                    'line_number': i + 1,
                    'content': line,
                    'urls': urls
                })
        
        # Add body segment
        if not in_headers and 'body_start' in locals():
            segments['body'].append({
                'start_line': body_start + 1,
                'end_line': len(lines),
                'content': '\n'.join(lines[body_start:])
            })
        
        return segments
    
    def extract_segment_content(self, content: str, start_tag: str, end_tag: str) -> List[Dict[str, Any]]:
        """Extract content between specific tags or markers"""
        segments = []
        lines = content.split('\n')
        
        in_segment = False
        segment_start = 0
        segment_content = []
        
        for i, line in enumerate(lines):
            if start_tag.lower() in line.lower():
                in_segment = True
                segment_start = i
                segment_content = [line]
            elif in_segment:
                segment_content.append(line)
                if end_tag and end_tag.lower() in line.lower():
                    segments.append({
                        'start_line': segment_start + 1,
                        'end_line': i + 1,
                        'content': '\n'.join(segment_content),
                        'start_tag': start_tag,
                        'end_tag': end_tag
                    })
                    in_segment = False
                    segment_content = []
        
        # Handle segments without end tag
        if in_segment and segment_content:
            segments.append({
                'start_line': segment_start + 1,
                'end_line': len(lines),
                'content': '\n'.join(segment_content),
                'start_tag': start_tag,
                'end_tag': end_tag or 'EOF'
            })
        
        return segments
