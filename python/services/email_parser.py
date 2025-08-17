"""
Email Parser Service - Advanced email parsing with support for multiple formats
"""

import email
import email.policy
import os
import mimetypes
import quopri
import base64
import re
from typing import Dict, List, Any, Optional, Tuple, Union
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class EmailParser:
    """Advanced email parser supporting multiple formats and encodings"""
    
    def __init__(self):
        self.supported_extensions = ['.eml', '.msg', '.txt', '.mbox']
        self.encoding_handlers = {
            'quoted-printable': quopri.decodestring,
            'base64': base64.b64decode,
            '7bit': lambda x: x.encode('utf-8') if isinstance(x, str) else x,
            '8bit': lambda x: x.encode('utf-8') if isinstance(x, str) else x
        }
    
    def parse_email_file(self, file_path: str) -> Dict[str, Any]:
        """
        Parse email from file with automatic format detection
        
        Args:
            file_path: Path to email file
            
        Returns:
            Parsed email data structure
        """
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"Email file not found: {file_path}")
            
            # Determine file type
            file_extension = os.path.splitext(file_path)[1].lower()
            
            if file_extension == '.eml':
                return self._parse_eml_file(file_path)
            elif file_extension == '.msg':
                return self._parse_msg_file(file_path)
            elif file_extension == '.txt':
                return self._parse_text_file(file_path)
            elif file_extension == '.mbox':
                return self._parse_mbox_file(file_path)
            else:
                # Try to parse as generic email
                return self._parse_generic_email_file(file_path)
                
        except Exception as e:
            logger.error(f"Failed to parse email file {file_path}: {str(e)}")
            raise Exception(f"Email parsing failed: {str(e)}")
    
    def parse_email_content(self, content: str, content_type: str = 'eml') -> Dict[str, Any]:
        """
        Parse email from string content
        
        Args:
            content: Raw email content
            content_type: Type of email content (eml, msg, txt)
            
        Returns:
            Parsed email data structure
        """
        try:
            if content_type == 'eml' or content_type == 'txt':
                return self._parse_email_string(content)
            else:
                raise ValueError(f"Unsupported content type: {content_type}")
                
        except Exception as e:
            logger.error(f"Failed to parse email content: {str(e)}")
            raise Exception(f"Email parsing failed: {str(e)}")
    
    def _parse_eml_file(self, file_path: str) -> Dict[str, Any]:
        """Parse .eml email file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            return self._parse_email_string(content)
        except UnicodeDecodeError:
            # Try binary mode if UTF-8 fails
            with open(file_path, 'rb') as f:
                content = f.read()
            # Detect encoding
            detected_content = self._detect_and_decode(content)
            return self._parse_email_string(detected_content)
    
    def _parse_msg_file(self, file_path: str) -> Dict[str, Any]:
        """Parse .msg email file (Outlook format)"""
        try:
            # For .msg files, we'll use a simplified approach
            # In production, you might want to use libraries like msg-extractor
            logger.warning("MSG file parsing is simplified - consider using msg-extractor library for full support")
            
            # Try to read as binary and extract what we can
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Basic MSG parsing - extract text parts
            text_content = self._extract_text_from_msg(content)
            
            # Create a basic email structure
            return {
                'raw_content': text_content,
                'headers': self._extract_basic_headers(text_content),
                'body_parts': [{'content': text_content, 'content_type': 'text/plain'}],
                'attachments': [],
                'metadata': {
                    'source_format': 'msg',
                    'file_path': file_path,
                    'file_size': len(content)
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to parse MSG file: {str(e)}")
            raise
    
    def _parse_text_file(self, file_path: str) -> Dict[str, Any]:
        """Parse plain text file containing email"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Check if it's actually an email format
            if 'From:' in content or 'To:' in content or 'Subject:' in content:
                return self._parse_email_string(content)
            else:
                # Treat as plain text message
                return {
                    'raw_content': content,
                    'headers': {'subject': 'Plain text message', 'from': 'unknown'},
                    'body_parts': [{'content': content, 'content_type': 'text/plain'}],
                    'attachments': [],
                    'metadata': {
                        'source_format': 'txt',
                        'file_path': file_path,
                        'is_plain_text': True
                    }
                }
        except Exception as e:
            logger.error(f"Failed to parse text file: {str(e)}")
            raise
    
    def _parse_mbox_file(self, file_path: str) -> Dict[str, Any]:
        """Parse mbox format file"""
        try:
            import mailbox
            
            mbox = mailbox.mbox(file_path)
            emails = []
            
            for message in mbox:
                parsed_email = self._parse_email_message(message)
                emails.append(parsed_email)
            
            # Return the first email if multiple, or combined data
            if emails:
                result = emails[0]
                result['metadata']['mbox_total_emails'] = len(emails)
                return result
            else:
                raise Exception("No emails found in mbox file")
                
        except Exception as e:
            logger.error(f"Failed to parse mbox file: {str(e)}")
            raise
    
    def _parse_generic_email_file(self, file_path: str) -> Dict[str, Any]:
        """Parse unknown email file format"""
        try:
            # Try as text first
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Check if it looks like an email
            if any(header in content for header in ['From:', 'To:', 'Subject:', 'Date:', 'Message-ID:']):
                return self._parse_email_string(content)
            else:
                # Try binary parsing
                with open(file_path, 'rb') as f:
                    binary_content = f.read()
                
                decoded_content = self._detect_and_decode(binary_content)
                return self._parse_email_string(decoded_content)
                
        except Exception as e:
            logger.error(f"Failed to parse generic email file: {str(e)}")
            raise
    
    def _parse_email_string(self, content: str) -> Dict[str, Any]:
        """Parse email from string content"""
        try:
            # Use email library with modern policy
            msg = email.message_from_string(content, policy=email.policy.default)
            return self._parse_email_message(msg)
            
        except Exception as e:
            logger.error(f"Failed to parse email string: {str(e)}")
            # Fallback to basic parsing
            return self._parse_email_fallback(content)
    
    def _parse_email_message(self, msg: email.message.Message) -> Dict[str, Any]:
        """Parse email.message.Message object into structured data"""
        try:
            # Extract headers
            headers = self._extract_headers(msg)
            
            # Extract body parts
            body_parts = self._extract_body_parts(msg)
            
            # Extract attachments
            attachments = self._extract_attachments(msg)
            
            # Extract metadata
            metadata = self._extract_metadata(msg)
            
            return {
                'raw_content': str(msg),
                'headers': headers,
                'body_parts': body_parts,
                'attachments': attachments,
                'metadata': metadata
            }
            
        except Exception as e:
            logger.error(f"Failed to parse email message: {str(e)}")
            raise
    
    def _extract_headers(self, msg: email.message.Message) -> Dict[str, Any]:
        """Extract email headers"""
        headers = {}
        
        # Standard headers
        standard_headers = [
            'From', 'To', 'Cc', 'Bcc', 'Subject', 'Date', 'Message-ID',
            'Reply-To', 'Return-Path', 'Sender', 'Organization', 'User-Agent',
            'X-Mailer', 'Precedence', 'Priority', 'Importance'
        ]
        
        for header in standard_headers:
            value = msg.get(header)
            if value:
                headers[header.lower().replace('-', '_')] = self._decode_header(value)
        
        # Security and routing headers
        security_headers = [
            'Received', 'X-Originating-IP', 'X-Sender-IP', 'X-Forwarded-For',
            'Authentication-Results', 'Received-SPF', 'DKIM-Signature',
            'DomainKey-Signature', 'X-Spam-Score', 'X-Spam-Status',
            'X-MS-Exchange-CrossTenant-Id', 'X-MS-Exchange-CrossTenant-UserPrincipalName'
        ]
        
        for header in security_headers:
            values = msg.get_all(header)
            if values:
                key = header.lower().replace('-', '_')
                if len(values) == 1:
                    headers[key] = self._decode_header(values[0])
                else:
                    headers[key] = [self._decode_header(v) for v in values]
        
        # MIME headers
        headers['mime_version'] = msg.get('MIME-Version', '')
        headers['content_type'] = msg.get_content_type()
        headers['content_encoding'] = msg.get('Content-Transfer-Encoding', '')
        
        return headers
    
    def _extract_body_parts(self, msg: email.message.Message) -> List[Dict[str, Any]]:
        """Extract email body parts"""
        body_parts = []
        
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type().startswith(('text/', 'message/')):
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
            
            # Skip attachments
            if part.get_content_disposition() == 'attachment':
                return None
            
            # Get content
            try:
                content = part.get_content()
            except:
                # Fallback to get_payload
                content = part.get_payload(decode=True)
                if isinstance(content, bytes):
                    content = content.decode(charset, errors='ignore')
            
            if not content:
                return None
            
            # Clean and process content
            content = str(content).strip()
            
            # Extract URLs from content
            urls = self._extract_urls(content)
            
            # Extract email addresses
            emails = self._extract_email_addresses(content)
            
            # Extract phone numbers
            phones = self._extract_phone_numbers(content)
            
            # Calculate content metrics
            metrics = self._calculate_content_metrics(content)
            
            return {
                'content_type': content_type,
                'charset': charset,
                'content': content,
                'length': len(content),
                'urls': urls,
                'emails': emails,
                'phone_numbers': phones,
                'metrics': metrics,
                'encoding': part.get('Content-Transfer-Encoding', ''),
                'content_id': part.get('Content-ID', ''),
                'content_location': part.get('Content-Location', '')
            }
            
        except Exception as e:
            logger.warning(f"Failed to process body part: {str(e)}")
            return None
    
    def _extract_attachments(self, msg: email.message.Message) -> List[Dict[str, Any]]:
        """Extract email attachments"""
        attachments = []
        
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_disposition() == 'attachment':
                    attachment_info = self._process_attachment(part)
                    if attachment_info:
                        attachments.append(attachment_info)
        
        return attachments
    
    def _process_attachment(self, part: email.message.Message) -> Optional[Dict[str, Any]]:
        """Process individual attachment"""
        try:
            filename = part.get_filename()
            if not filename:
                # Try to get filename from Content-Type
                content_type = part.get_content_type()
                filename = f"attachment.{mimetypes.guess_extension(content_type) or 'bin'}"
            
            # Decode filename if encoded
            filename = self._decode_header(filename)
            
            # Get content
            content = part.get_payload(decode=True)
            if not content:
                return None
            
            # Calculate hash
            import hashlib
            content_hash = hashlib.sha256(content).hexdigest()
            
            # Determine file info
            content_type = part.get_content_type()
            mime_type, encoding = mimetypes.guess_type(filename)
            
            # Analyze file type
            file_analysis = self._analyze_file_type(filename, content_type, content)
            
            return {
                'filename': filename,
                'content_type': content_type,
                'mime_type': mime_type,
                'encoding': encoding,
                'size': len(content),
                'hash': content_hash,
                'content_id': part.get('Content-ID', ''),
                'content_disposition': part.get('Content-Disposition', ''),
                'analysis': file_analysis
            }
            
        except Exception as e:
            logger.warning(f"Failed to process attachment: {str(e)}")
            return None
    
    def _extract_metadata(self, msg: email.message.Message) -> Dict[str, Any]:
        """Extract email metadata"""
        return {
            'message_size': len(str(msg)),
            'header_count': len(msg.keys()),
            'is_multipart': msg.is_multipart(),
            'boundary': msg.get_boundary(),
            'content_type': msg.get_content_type(),
            'content_subtype': msg.get_content_subtype(),
            'content_charset': msg.get_content_charset(),
            'defects': [str(defect) for defect in msg.defects],
            'parse_timestamp': datetime.now().isoformat()
        }
    
    def _decode_header(self, header_value: str) -> str:
        """Decode email header value"""
        try:
            if header_value:
                decoded_parts = email.header.decode_header(header_value)
                decoded_string = ''
                for part, charset in decoded_parts:
                    if isinstance(part, bytes):
                        if charset:
                            decoded_string += part.decode(charset, errors='ignore')
                        else:
                            decoded_string += part.decode('utf-8', errors='ignore')
                    else:
                        decoded_string += str(part)
                return decoded_string.strip()
        except Exception as e:
            logger.warning(f"Failed to decode header: {str(e)}")
        
        return str(header_value) if header_value else ''
    
    def _extract_urls(self, content: str) -> List[str]:
        """Extract URLs from content"""
        url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
        urls = url_pattern.findall(content)
        
        # Also look for www. domains
        www_pattern = re.compile(r'www\.(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
        www_urls = ['http://' + url for url in www_pattern.findall(content)]
        
        return list(set(urls + www_urls))
    
    def _extract_email_addresses(self, content: str) -> List[str]:
        """Extract email addresses from content"""
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        return list(set(email_pattern.findall(content)))
    
    def _extract_phone_numbers(self, content: str) -> List[str]:
        """Extract phone numbers from content"""
        phone_patterns = [
            r'\+?1?[-.\s]?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})',  # US format
            r'\+?([0-9]{1,3})[-.\s]?([0-9]{3,4})[-.\s]?([0-9]{3,4})[-.\s]?([0-9]{3,4})',  # International
        ]
        
        phones = []
        for pattern in phone_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if isinstance(match, tuple):
                    phone = ''.join(match)
                else:
                    phone = match
                if len(phone) >= 10:  # Minimum phone number length
                    phones.append(phone)
        
        return list(set(phones))
    
    def _calculate_content_metrics(self, content: str) -> Dict[str, Any]:
        """Calculate content metrics"""
        words = content.split()
        sentences = content.split('.')
        
        return {
            'word_count': len(words),
            'sentence_count': len([s for s in sentences if s.strip()]),
            'character_count': len(content),
            'line_count': len(content.split('\n')),
            'avg_word_length': sum(len(word) for word in words) / len(words) if words else 0,
            'uppercase_ratio': sum(1 for c in content if c.isupper()) / len(content) if content else 0,
            'punctuation_count': sum(1 for c in content if c in '.,!?;:'),
            'digit_count': sum(1 for c in content if c.isdigit())
        }
    
    def _analyze_file_type(self, filename: str, content_type: str, content: bytes) -> Dict[str, Any]:
        """Analyze file type and potential threats"""
        analysis = {
            'is_executable': False,
            'is_archive': False,
            'is_document': False,
            'is_image': False,
            'is_suspicious': False,
            'threat_level': 'low'
        }
        
        filename_lower = filename.lower()
        
        # Check file extensions
        executable_exts = ['.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js', '.jar']
        archive_exts = ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2']
        document_exts = ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf']
        image_exts = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico']
        
        if any(filename_lower.endswith(ext) for ext in executable_exts):
            analysis['is_executable'] = True
            analysis['threat_level'] = 'high'
            analysis['is_suspicious'] = True
        elif any(filename_lower.endswith(ext) for ext in archive_exts):
            analysis['is_archive'] = True
            analysis['threat_level'] = 'medium'
        elif any(filename_lower.endswith(ext) for ext in document_exts):
            analysis['is_document'] = True
            analysis['threat_level'] = 'medium'
        elif any(filename_lower.endswith(ext) for ext in image_exts):
            analysis['is_image'] = True
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'invoice.*\.exe',
            r'document.*\.zip',
            r'photo.*\.scr',
            r'payment.*\.bat'
        ]
        
        if any(re.search(pattern, filename_lower) for pattern in suspicious_patterns):
            analysis['is_suspicious'] = True
            analysis['threat_level'] = 'high'
        
        # Check file size
        if len(content) > 50 * 1024 * 1024:  # > 50MB
            analysis['is_suspicious'] = True
        
        return analysis
    
    def _detect_and_decode(self, content: bytes) -> str:
        """Detect encoding and decode content"""
        encodings = ['utf-8', 'latin1', 'cp1252', 'iso-8859-1']
        
        for encoding in encodings:
            try:
                return content.decode(encoding)
            except UnicodeDecodeError:
                continue
        
        # Fallback with error handling
        return content.decode('utf-8', errors='ignore')
    
    def _extract_text_from_msg(self, content: bytes) -> str:
        """Extract text from MSG file (simplified)"""
        try:
            # This is a very basic MSG parser
            # For production use, consider using python-msg library
            text = content.decode('utf-8', errors='ignore')
            
            # Remove null characters and control characters
            text = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', text)
            
            # Extract readable text
            readable_text = re.findall(r'[a-zA-Z0-9\s@.\-:;,!?()\[\]{}\'\"]+', text)
            return ' '.join(readable_text)
        except:
            return "MSG file content extraction failed"
    
    def _extract_basic_headers(self, content: str) -> Dict[str, str]:
        """Extract basic headers from text content"""
        headers = {}
        header_patterns = {
            'from': r'From:\s*(.+?)(?:\n|$)',
            'to': r'To:\s*(.+?)(?:\n|$)',
            'subject': r'Subject:\s*(.+?)(?:\n|$)',
            'date': r'Date:\s*(.+?)(?:\n|$)',
        }
        
        for header, pattern in header_patterns.items():
            match = re.search(pattern, content, re.IGNORECASE | re.MULTILINE)
            if match:
                headers[header] = match.group(1).strip()
        
        return headers
    
    def _parse_email_fallback(self, content: str) -> Dict[str, Any]:
        """Fallback email parsing when standard parsing fails"""
        try:
            headers = self._extract_basic_headers(content)
            
            # Extract body (everything after headers)
            header_end = content.find('\n\n')
            if header_end == -1:
                header_end = content.find('\r\n\r\n')
            
            if header_end != -1:
                body_content = content[header_end:].strip()
            else:
                body_content = content
            
            body_parts = [{
                'content': body_content,
                'content_type': 'text/plain',
                'charset': 'utf-8',
                'length': len(body_content),
                'urls': self._extract_urls(body_content),
                'emails': self._extract_email_addresses(body_content),
                'phone_numbers': self._extract_phone_numbers(body_content),
                'metrics': self._calculate_content_metrics(body_content)
            }]
            
            return {
                'raw_content': content,
                'headers': headers,
                'body_parts': body_parts,
                'attachments': [],
                'metadata': {
                    'source_format': 'fallback',
                    'parse_method': 'basic',
                    'message_size': len(content)
                }
            }
            
        except Exception as e:
            logger.error(f"Fallback parsing failed: {str(e)}")
            raise Exception(f"All parsing methods failed: {str(e)}")
    
    def validate_email_structure(self, parsed_email: Dict[str, Any]) -> Dict[str, Any]:
        """Validate parsed email structure and add warnings"""
        validation = {
            'is_valid': True,
            'warnings': [],
            'errors': []
        }
        
        # Check required fields
        if not parsed_email.get('headers'):
            validation['errors'].append('No headers found')
            validation['is_valid'] = False
        
        if not parsed_email.get('body_parts'):
            validation['warnings'].append('No body content found')
        
        # Check header integrity
        headers = parsed_email.get('headers', {})
        if not headers.get('from'):
            validation['warnings'].append('Missing sender information')
        
        if not headers.get('subject'):
            validation['warnings'].append('Missing subject')
        
        if not headers.get('date'):
            validation['warnings'].append('Missing date')
        
        # Check content quality
        body_parts = parsed_email.get('body_parts', [])
        if body_parts:
            total_content = sum(len(part.get('content', '')) for part in body_parts)
            if total_content == 0:
                validation['warnings'].append('Empty email body')
        
        return validation
