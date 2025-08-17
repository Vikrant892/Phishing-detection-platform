#!/usr/bin/env python3
"""
Enhanced Email HTML Analyzer for Phishing Detection
Specifically designed to parse .eml files and analyze HTML segments
"""

import email
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from bs4 import BeautifulSoup
import logging

logger = logging.getLogger(__name__)

class EmailHTMLAnalyzer:
    """Enhanced email analyzer focusing on HTML content analysis"""
    
    def __init__(self):
        # Suspicious phrases and patterns for phishing detection
        self.suspicious_patterns = {
            'urgent_actions': [
                'verify your account immediately',
                'account will be suspended',
                'urgent action required',
                'click here immediately',
                'act now or lose access',
                'expires in 24 hours',
                'immediate verification needed',
                'account locked temporarily'
            ],
            'financial_threats': [
                'unauthorized transaction',
                'suspicious activity detected',
                'billing issue detected',
                'payment method expired',
                'refund pending approval',
                'wire transfer requested',
                'update payment information',
                'credit card charged'
            ],
            'suspicious_links': [
                r'bit\.ly\/\w+',
                r'tinyurl\.com\/\w+',
                r'shortened\.link\/\w+',
                r'click\.here\/\w+',
                r'secure-verify\..*\.com',
                r'account-verification\..*\.net'
            ],
            'impersonation': [
                'from your bank security team',
                'microsoft security team',
                'paypal security center',
                'amazon account services',
                'google security alert',
                'apple id security',
                'facebook security team'
            ],
            'credential_harvesting': [
                'enter your password',
                'confirm your login',
                'verify your identity',
                'update your credentials',
                'reset your password',
                'confirm account details',
                'validate your information'
            ],
            'suspicious_headers': [
                'x-ms-exchange-crosstenant-id',
                'x-ms-exchange-crosstenant-userprincipalname',
                'x-ms-exchange-crosstenant-network',
                'x-ms-exchange-transport-endtoendlatency',
                'x-originating-ip',
                'x-remote-ip',
                'x-sender-ip'
            ],
            'suspicious_codes': [
                r'XFCjGeORft8x7Ol',
                r'[A-Za-z0-9]{12,}',
                r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                r'eyJ[A-Za-z0-9+/=]+',  # JWT tokens
                r'Bearer [A-Za-z0-9\-\._~\+\/]+=*',  # Bearer tokens
                r'ssh-rsa [A-Za-z0-9+/=]+',  # SSH keys
                r'-----BEGIN [A-Z ]+-----'  # PEM certificates/keys
            ],
            'microsoft_exchange': [
                'crosstenant authentication',
                'exchange online protection',
                'office 365 security',
                'azure ad authentication',
                'tenant isolation bypass',
                'cross-tenant access'
            ]
        }
    
    def parse_eml_file(self, file_path):
        """Parse .eml file and extract email components"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                email_content = file.read()
            
            # Parse email message
            msg = email.message_from_string(email_content)
            
            email_data = {
                'subject': msg.get('Subject', 'No Subject'),
                'sender': msg.get('From', 'Unknown Sender'),
                'recipient': msg.get('To', 'Unknown Recipient'),
                'date': msg.get('Date', 'Unknown Date'),
                'html_content': '',
                'text_content': '',
                'raw_content': email_content,
                'headers': {}
            }
            
            # Extract and analyze all email headers
            for header_name, header_value in msg.items():
                email_data['headers'][header_name.lower()] = {
                    'value': header_value,
                    'is_suspicious': self._is_suspicious_header(header_name, header_value),
                    'threat_patterns': self._analyze_header_threats(header_name, header_value)
                }
            
            # Extract HTML and text content
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    
                    if content_type == "text/html":
                        html_payload = part.get_payload(decode=True)
                        if html_payload:
                            email_data['html_content'] = html_payload.decode('utf-8', errors='ignore')
                    
                    elif content_type == "text/plain":
                        text_payload = part.get_payload(decode=True)
                        if text_payload:
                            email_data['text_content'] = text_payload.decode('utf-8', errors='ignore')
            else:
                # Single part message
                content_type = msg.get_content_type()
                payload = msg.get_payload(decode=True)
                
                if payload:
                    decoded_payload = payload.decode('utf-8', errors='ignore')
                    if content_type == "text/html":
                        email_data['html_content'] = decoded_payload
                    else:
                        email_data['text_content'] = decoded_payload
            
            return email_data
            
        except Exception as e:
            logger.error(f"Error parsing .eml file: {e}")
            return None
    
    def _is_suspicious_header(self, header_name, header_value):
        """Check if a header is suspicious"""
        header_lower = header_name.lower()
        value_lower = header_value.lower() if header_value else ""
        
        # Check against suspicious header patterns
        for pattern in self.suspicious_patterns['suspicious_headers']:
            if pattern in header_lower:
                return True
        
        # Check for suspicious values in headers
        for category, patterns in self.suspicious_patterns.items():
            for pattern in patterns:
                if isinstance(pattern, str):
                    if pattern.lower() in value_lower:
                        return True
                else:
                    # Regex pattern
                    if re.search(pattern, header_value, re.IGNORECASE):
                        return True
        
        return False
    
    def _analyze_header_threats(self, header_name, header_value):
        """Analyze header for specific threat patterns"""
        threats = []
        header_lower = header_name.lower()
        value_lower = header_value.lower() if header_value else ""
        
        # Check suspicious header names
        for pattern in self.suspicious_patterns['suspicious_headers']:
            if pattern in header_lower:
                threats.append(f"Suspicious header: {pattern}")
        
        # Check for suspicious codes/patterns in header values
        for pattern in self.suspicious_patterns['suspicious_codes']:
            if re.search(pattern, header_value, re.IGNORECASE):
                threats.append(f"Suspicious code pattern: {pattern}")
        
        # Check Microsoft Exchange specific threats
        for pattern in self.suspicious_patterns['microsoft_exchange']:
            if pattern.lower() in value_lower:
                threats.append(f"Microsoft Exchange threat: {pattern}")
        
        return threats
    
    def extract_html_segments(self, html_content):
        """Extract and analyze HTML segments with line numbers"""
        if not html_content:
            return []
        
        segments = []
        lines = html_content.split('\n')
        
        # Track HTML tags and content
        in_tag = False
        current_segment = []
        segment_start_line = 0
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Skip empty lines
            if not line_stripped:
                continue
            
            # Check for HTML tags
            if '<' in line and '>' in line:
                # If we were building a segment, save it
                if current_segment:
                    segment_content = '\n'.join(current_segment)
                    segments.append({
                        'content': segment_content,
                        'start_line': segment_start_line,
                        'end_line': line_num - 1,
                        'type': 'html_content',
                        'is_single_line': segment_start_line == (line_num - 1),
                        'is_html_segment': '<' in segment_content and '>' in segment_content,
                        'is_multiline': segment_start_line != (line_num - 1),
                        'line_count': (line_num - 1) - segment_start_line + 1
                    })
                    current_segment = []
                
                # Start new segment
                segment_start_line = line_num
                current_segment = [line]
                
                # Check if tag closes on same line
                if line.count('<') == line.count('>'):
                    segments.append({
                        'content': line,
                        'start_line': line_num,
                        'end_line': line_num,
                        'type': 'html_tag',
                        'is_single_line': True,
                        'is_html_segment': True,
                        'is_multiline': False,
                        'line_count': 1
                    })
                    current_segment = []
                    segment_start_line = 0
            else:
                # Regular content line
                if not current_segment:
                    segment_start_line = line_num
                current_segment.append(line)
        
        # Add final segment if exists
        if current_segment:
            segment_content = '\n'.join(current_segment)
            segments.append({
                'content': segment_content,
                'start_line': segment_start_line,
                'end_line': len(lines),
                'type': 'content',
                'is_single_line': segment_start_line == len(lines),
                'is_html_segment': '<' in segment_content and '>' in segment_content,
                'is_multiline': segment_start_line != len(lines),
                'line_count': len(lines) - segment_start_line + 1
            })
        
        return segments
    
    def analyze_html_segment_for_threats(self, segment_content):
        """Analyze HTML segment for suspicious phrases"""
        threats_found = []
        content_lower = segment_content.lower()
        
        # Remove HTML tags for text analysis
        soup = BeautifulSoup(segment_content, 'html.parser')
        text_content = soup.get_text()
        text_lower = text_content.lower()
        
        # Check each category of suspicious patterns
        for category, patterns in self.suspicious_patterns.items():
            for pattern in patterns:
                if isinstance(pattern, str):
                    # Simple string match
                    if pattern.lower() in text_lower:
                        threats_found.append({
                            'category': category,
                            'pattern': pattern,
                            'type': 'phrase_match',
                            'context': self._extract_context(text_content, pattern, 50)
                        })
                else:
                    # Regex pattern match
                    matches = re.findall(pattern, content_lower, re.IGNORECASE)
                    for match in matches:
                        threats_found.append({
                            'category': category,
                            'pattern': pattern,
                            'match': match,
                            'type': 'regex_match',
                            'context': self._extract_context(content_lower, match, 50)
                        })
        
        return threats_found
    
    def _extract_context(self, text, pattern, context_length=50):
        """Extract context around a suspicious pattern"""
        pattern_lower = pattern.lower()
        text_lower = text.lower()
        
        index = text_lower.find(pattern_lower)
        if index == -1:
            return ""
        
        start = max(0, index - context_length)
        end = min(len(text), index + len(pattern) + context_length)
        
        context = text[start:end]
        
        # Highlight the suspicious pattern
        context = context.replace(pattern, f"**{pattern}**")
        
        return context.strip()
    
    def analyze_email_file(self, file_path):
        """Complete analysis of an .eml email file"""
        # Parse the email file
        email_data = self.parse_eml_file(file_path)
        if not email_data:
            return {
                'success': False,
                'error': 'Failed to parse email file'
            }
        
        # Extract HTML segments
        html_segments = self.extract_html_segments(email_data['html_content'])
        
        # Analyze each segment for threats
        analysis_results = {
            'email_info': {
                'subject': email_data['subject'],
                'sender': email_data['sender'],
                'recipient': email_data['recipient'],
                'date': email_data['date']
            },
            'headers': email_data.get('headers', {}),
            'html_segments': [],
            'threats_found': [],
            'overall_status': 'PASS',
            'threat_score': 0
        }
        
        total_threats = 0
        
        for segment in html_segments:
            threats = self.analyze_html_segment_for_threats(segment['content'])
            
            segment_analysis = {
                'segment': segment,
                'threats': threats,
                'threat_count': len(threats)
            }
            
            analysis_results['html_segments'].append(segment_analysis)
            analysis_results['threats_found'].extend(threats)
            total_threats += len(threats)
        
        # Calculate threat score and status
        if total_threats > 0:
            analysis_results['overall_status'] = 'FAIL'
            analysis_results['threat_score'] = min(total_threats * 15, 100)
        
        # If no HTML content, analyze text content
        if not html_segments and email_data['text_content']:
            text_threats = self.analyze_html_segment_for_threats(email_data['text_content'])
            if text_threats:
                analysis_results['threats_found'].extend(text_threats)
                analysis_results['overall_status'] = 'FAIL'
                analysis_results['threat_score'] = min(len(text_threats) * 15, 100)
        
        analysis_results['success'] = True
        return analysis_results
    
    def format_analysis_report(self, analysis_results):
        """Format analysis results into a readable report"""
        if not analysis_results['success']:
            return f"ERROR: {analysis_results['error']}"
        
        report = []
        report.append("="*60)
        report.append("EMAIL PHISHING ANALYSIS REPORT")
        report.append("="*60)
        
        # Email information
        email_info = analysis_results['email_info']
        report.append(f"Subject: {email_info['subject']}")
        report.append(f"From: {email_info['sender']}")
        report.append(f"To: {email_info['recipient']}")
        report.append(f"Date: {email_info['date']}")
        report.append("")
        
        # Overall status
        status = analysis_results['overall_status']
        score = analysis_results['threat_score']
        
        if status == 'PASS':
            report.append("✅ ANALYSIS RESULT: PASS - No suspicious content detected")
        else:
            report.append(f"❌ ANALYSIS RESULT: FAIL - Threats detected (Score: {score}/100)")
        
        report.append("")
        
        # HTML segments analysis
        if analysis_results['html_segments']:
            report.append("HTML SEGMENTS ANALYSIS:")
            report.append("-" * 40)
            
            for i, segment_analysis in enumerate(analysis_results['html_segments'], 1):
                segment = segment_analysis['segment']
                threats = segment_analysis['threats']
                
                report.append(f"\nSegment {i} (Lines {segment['start_line']}-{segment['end_line']}):")
                report.append(f"Type: {segment['type']}")
                
                # Show segment content with line numbers
                content_lines = segment['content'].split('\n')
                for j, line in enumerate(content_lines):
                    line_num = segment['start_line'] + j
                    report.append(f"{line_num:4d}: {line}")
                
                # Show threats found in this segment
                if threats:
                    report.append(f"\n⚠️  THREATS FOUND IN THIS SEGMENT:")
                    for threat in threats:
                        report.append(f"   - Category: {threat['category']}")
                        report.append(f"   - Pattern: {threat['pattern']}")
                        if threat.get('context'):
                            report.append(f"   - Context: {threat['context']}")
                        report.append("")
                else:
                    report.append("✅ No threats found in this segment")
                
                report.append("-" * 40)
        
        # Summary of all threats
        if analysis_results['threats_found']:
            report.append("\nTHREAT SUMMARY:")
            report.append("-" * 20)
            
            threat_categories = {}
            for threat in analysis_results['threats_found']:
                category = threat['category']
                if category not in threat_categories:
                    threat_categories[category] = []
                threat_categories[category].append(threat['pattern'])
            
            for category, patterns in threat_categories.items():
                report.append(f"{category.replace('_', ' ').title()}: {len(patterns)} threat(s)")
                for pattern in set(patterns):  # Remove duplicates
                    report.append(f"  - {pattern}")
        
        return '\n'.join(report)