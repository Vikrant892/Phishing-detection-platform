"""
Threat Detection Module - Advanced phishing and malicious content detection
"""

import re
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Tuple
import hashlib
import urllib.parse
import ipaddress
import socket

class ThreatDetector:
    """Advanced threat detection engine with multiple analysis methods"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.threat_patterns = {}
        self.risk_weights = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 1
        }
        self.load_default_patterns()
        
    def load_default_patterns(self):
        """Load default threat detection patterns"""
        self.threat_patterns = {
            'urgent_language': {
                'patterns': [
                    r'urgent[ly]?\s*(?:action|response|attention)',
                    r'immediate[ly]?\s*(?:action|response|required)',
                    r'expires?\s*(?:today|soon|in\s*\d+\s*hours?)',
                    r'act\s*now\s*(?:or|before)',
                    r'limited\s*time\s*offer'
                ],
                'severity': 'medium',
                'category': 'social_engineering'
            },
            'financial_keywords': {
                'patterns': [
                    r'(?:verify|update|confirm)\s*(?:your\s*)?(?:account|payment|billing)',
                    r'suspended\s*(?:account|service)',
                    r'unusual\s*(?:activity|login|transaction)',
                    r'security\s*(?:alert|warning|breach)',
                    r'click\s*(?:here|now|below)\s*to\s*(?:verify|update|confirm)'
                ],
                'severity': 'high',
                'category': 'financial_fraud'
            },
            'malicious_links': {
                'patterns': [
                    r'bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly',
                    r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',
                    r'[a-zA-Z0-9\-]+\.(?:tk|ml|ga|cf|top|xyz|click)',
                ],
                'severity': 'high',
                'category': 'malicious_infrastructure'
            },
            'credential_harvesting': {
                'patterns': [
                    r'(?:login|sign\s*in|log\s*on)\s*(?:to|at|here)',
                    r'username\s*(?:and|or|\&)\s*password',
                    r'enter\s*(?:your\s*)?(?:credentials|login|password)',
                    r'verify\s*(?:your\s*)?identity'
                ],
                'severity': 'critical',
                'category': 'credential_theft'
            },
            'attachment_risks': {
                'patterns': [
                    r'\.(?:exe|scr|bat|com|pif|vbs|js|jar|zip|rar)$',
                    r'invoice\.(?:pdf|doc|docx|xls|xlsx)',
                    r'receipt\.(?:pdf|doc|docx)',
                    r'document\.(?:zip|rar|7z)'
                ],
                'severity': 'high',
                'category': 'malicious_attachments'
            }
        }
    
    def analyze_email(self, email_data: Dict[str, Any], setup_rules: List[Dict] = None) -> Dict[str, Any]:
        """Comprehensive email threat analysis"""
        try:
            analysis_result = {
                'email_id': self._generate_email_id(email_data),
                'analysis_date': datetime.utcnow().isoformat(),
                'threat_score': 0,
                'risk_level': 'low',
                'threats_detected': [],
                'segments_analyzed': [],
                'recommendations': [],
                'metadata': {
                    'analyzer_version': '1.0.0',
                    'analysis_duration': 0
                }
            }
            
            start_time = datetime.utcnow()
            
            # Analyze headers
            if 'headers' in email_data:
                header_threats = self._analyze_headers(email_data['headers'])
                analysis_result['threats_detected'].extend(header_threats)
            
            # Analyze body content
            if 'body' in email_data:
                body_threats = self._analyze_body(email_data['body'])
                analysis_result['threats_detected'].extend(body_threats)
            
            # Analyze attachments
            if 'attachments' in email_data:
                attachment_threats = self._analyze_attachments(email_data['attachments'])
                analysis_result['threats_detected'].extend(attachment_threats)
            
            # Apply custom setup rules if provided
            if setup_rules:
                custom_threats = self._apply_setup_rules(email_data, setup_rules)
                analysis_result['threats_detected'].extend(custom_threats)
            
            # Calculate threat score and risk level
            analysis_result['threat_score'] = self._calculate_threat_score(analysis_result['threats_detected'])
            analysis_result['risk_level'] = self._determine_risk_level(analysis_result['threat_score'])
            
            # Generate recommendations
            analysis_result['recommendations'] = self._generate_recommendations(analysis_result)
            
            # Calculate analysis duration
            end_time = datetime.utcnow()
            analysis_result['metadata']['analysis_duration'] = (end_time - start_time).total_seconds()
            
            return analysis_result
            
        except Exception as e:
            self.logger.error(f"Email analysis error: {str(e)}")
            raise
    
    def _analyze_headers(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Analyze email headers for threats"""
        threats = []
        
        try:
            # Check sender reputation
            sender_threats = self._check_sender_reputation(headers)
            threats.extend(sender_threats)
            
            # Check for spoofing indicators
            spoofing_threats = self._check_spoofing_indicators(headers)
            threats.extend(spoofing_threats)
            
            # Check authentication headers
            auth_threats = self._check_authentication_headers(headers)
            threats.extend(auth_threats)
            
            # Check suspicious routing
            routing_threats = self._check_routing_patterns(headers)
            threats.extend(routing_threats)
            
        except Exception as e:
            self.logger.error(f"Header analysis error: {str(e)}")
        
        return threats
    
    def _analyze_body(self, body_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze email body content for threats"""
        threats = []
        
        try:
            # Analyze plain text content
            if body_data.get('plain'):
                plain_threats = self._analyze_text_content(body_data['plain'], 'plain_text')
                threats.extend(plain_threats)
            
            # Analyze HTML content
            if body_data.get('html'):
                html_threats = self._analyze_html_content(body_data['html'])
                threats.extend(html_threats)
            
            # Analyze individual parts
            for part in body_data.get('parts', []):
                part_threats = self._analyze_content_part(part)
                threats.extend(part_threats)
                
        except Exception as e:
            self.logger.error(f"Body analysis error: {str(e)}")
        
        return threats
    
    def _analyze_attachments(self, attachments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze email attachments for threats"""
        threats = []
        
        try:
            for attachment in attachments:
                # Check file extension
                filename = attachment.get('filename', '')
                if self._is_suspicious_extension(filename):
                    threats.append({
                        'type': 'suspicious_attachment',
                        'severity': 'high',
                        'category': 'malicious_attachments',
                        'description': f'Suspicious file extension: {filename}',
                        'evidence': filename,
                        'location': 'attachment'
                    })
                
                # Check file size anomalies
                size = attachment.get('size', 0)
                if size > 10 * 1024 * 1024:  # 10MB
                    threats.append({
                        'type': 'large_attachment',
                        'severity': 'medium',
                        'category': 'suspicious_content',
                        'description': f'Unusually large attachment: {size} bytes',
                        'evidence': f'{filename} ({size} bytes)',
                        'location': 'attachment'
                    })
                
                # Check for double extensions
                if filename.count('.') > 1:
                    threats.append({
                        'type': 'double_extension',
                        'severity': 'high',
                        'category': 'malicious_attachments',
                        'description': f'File with multiple extensions: {filename}',
                        'evidence': filename,
                        'location': 'attachment'
                    })
        
        except Exception as e:
            self.logger.error(f"Attachment analysis error: {str(e)}")
        
        return threats
    
    def _analyze_text_content(self, content: str, content_type: str) -> List[Dict[str, Any]]:
        """Analyze text content for threat patterns"""
        threats = []
        
        try:
            lines = content.split('\n')
            
            for category, pattern_data in self.threat_patterns.items():
                for pattern in pattern_data['patterns']:
                    matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                    
                    for match in matches:
                        # Find line number
                        line_num = content[:match.start()].count('\n') + 1
                        
                        threats.append({
                            'type': 'pattern_match',
                            'severity': pattern_data['severity'],
                            'category': pattern_data['category'],
                            'description': f'{category} pattern detected',
                            'evidence': match.group(),
                            'location': f'{content_type}:line_{line_num}',
                            'line_number': line_num,
                            'pattern': pattern
                        })
            
            # Check for URLs
            url_threats = self._analyze_urls_in_content(content, content_type)
            threats.extend(url_threats)
            
            # Check for email addresses
            email_threats = self._analyze_emails_in_content(content, content_type)
            threats.extend(email_threats)
            
        except Exception as e:
            self.logger.error(f"Text analysis error: {str(e)}")
        
        return threats
    
    def _analyze_html_content(self, html_content: str) -> List[Dict[str, Any]]:
        """Analyze HTML content for specific threats"""
        threats = []
        
        try:
            # Check for hidden content
            hidden_patterns = [
                r'style\s*=\s*["\'][^"\']*display\s*:\s*none',
                r'style\s*=\s*["\'][^"\']*visibility\s*:\s*hidden',
                r'style\s*=\s*["\'][^"\']*font-size\s*:\s*0'
            ]
            
            for pattern in hidden_patterns:
                if re.search(pattern, html_content, re.IGNORECASE):
                    threats.append({
                        'type': 'hidden_content',
                        'severity': 'medium',
                        'category': 'deceptive_content',
                        'description': 'Hidden HTML content detected',
                        'evidence': pattern,
                        'location': 'html_body'
                    })
            
            # Check for suspicious scripts
            script_pattern = r'<script[^>]*>(.*?)</script>'
            scripts = re.findall(script_pattern, html_content, re.IGNORECASE | re.DOTALL)
            
            for script in scripts:
                if any(keyword in script.lower() for keyword in ['eval', 'unescape', 'fromcharcode']):
                    threats.append({
                        'type': 'suspicious_script',
                        'severity': 'high',
                        'category': 'malicious_code',
                        'description': 'Potentially malicious JavaScript detected',
                        'evidence': script[:100] + '...' if len(script) > 100 else script,
                        'location': 'html_script'
                    })
            
            # Analyze HTML content as text
            text_threats = self._analyze_text_content(html_content, 'html')
            threats.extend(text_threats)
            
        except Exception as e:
            self.logger.error(f"HTML analysis error: {str(e)}")
        
        return threats
    
    def _analyze_urls_in_content(self, content: str, content_type: str) -> List[Dict[str, Any]]:
        """Analyze URLs found in content"""
        threats = []
        
        try:
            url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+|[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}[^\s<>"\']*'
            urls = re.findall(url_pattern, content)
            
            for url in urls:
                url_threats = self._analyze_single_url(url, content_type)
                threats.extend(url_threats)
        
        except Exception as e:
            self.logger.error(f"URL analysis error: {str(e)}")
        
        return threats
    
    def _analyze_single_url(self, url: str, location: str) -> List[Dict[str, Any]]:
        """Analyze a single URL for threats"""
        threats = []
        
        try:
            # Parse URL
            if not url.startswith(('http://', 'https://')):
                if url.startswith('www.'):
                    url = 'http://' + url
                else:
                    url = 'http://' + url
            
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()
            
            # Check for IP addresses instead of domains
            try:
                ipaddress.ip_address(domain.split(':')[0])
                threats.append({
                    'type': 'ip_based_url',
                    'severity': 'high',
                    'category': 'malicious_infrastructure',
                    'description': 'URL uses IP address instead of domain',
                    'evidence': url,
                    'location': location
                })
            except ValueError:
                pass
            
            # Check for suspicious domains
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.xyz', '.click', '.download', '.work']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                threats.append({
                    'type': 'suspicious_tld',
                    'severity': 'medium',
                    'category': 'malicious_infrastructure',
                    'description': f'Suspicious top-level domain: {domain}',
                    'evidence': url,
                    'location': location
                })
            
            # Check for URL shorteners
            shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link']
            if any(shortener in domain for shortener in shorteners):
                threats.append({
                    'type': 'url_shortener',
                    'severity': 'medium',
                    'category': 'suspicious_content',
                    'description': 'URL shortener detected',
                    'evidence': url,
                    'location': location
                })
            
            # Check for homograph attacks
            if self._detect_homograph_attack(domain):
                threats.append({
                    'type': 'homograph_attack',
                    'severity': 'high',
                    'category': 'domain_spoofing',
                    'description': 'Potential homograph attack in domain',
                    'evidence': url,
                    'location': location
                })
        
        except Exception as e:
            self.logger.error(f"Single URL analysis error: {str(e)}")
        
        return threats
    
    def _apply_setup_rules(self, email_data: Dict[str, Any], setup_rules: List[Dict]) -> List[Dict[str, Any]]:
        """Apply custom setup rules for threat detection"""
        threats = []
        
        try:
            for rule in setup_rules:
                start_tag = rule.get('start_segment', '<body')
                end_tag = rule.get('end_segment', '</body>')
                search_phrase = rule.get('phrase', '')
                rule_type = rule.get('type', 'single_line')
                
                if not search_phrase:
                    continue
                
                # Extract content based on segments
                content_to_search = self._extract_segment_content(
                    email_data.get('raw_content', ''),
                    start_tag,
                    end_tag
                )
                
                # Search for phrase
                if self._search_phrase_in_content(content_to_search, search_phrase, rule_type):
                    threats.append({
                        'type': 'custom_rule_match',
                        'severity': rule.get('severity', 'medium'),
                        'category': 'custom_detection',
                        'description': f'Custom rule matched: {search_phrase}',
                        'evidence': search_phrase,
                        'location': f'{start_tag}...{end_tag}',
                        'rule': rule
                    })
        
        except Exception as e:
            self.logger.error(f"Setup rules application error: {str(e)}")
        
        return threats
    
    def _calculate_threat_score(self, threats: List[Dict[str, Any]]) -> int:
        """Calculate overall threat score"""
        total_score = 0
        
        for threat in threats:
            severity = threat.get('severity', 'low')
            score = self.risk_weights.get(severity, 1)
            total_score += score
        
        return min(total_score, 100)  # Cap at 100
    
    def _determine_risk_level(self, threat_score: int) -> str:
        """Determine risk level based on threat score"""
        if threat_score >= 20:
            return 'critical'
        elif threat_score >= 15:
            return 'high'
        elif threat_score >= 8:
            return 'medium'
        else:
            return 'low'
    
    def _generate_recommendations(self, analysis_result: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        threat_categories = set(threat.get('category', '') for threat in analysis_result['threats_detected'])
        
        if 'credential_theft' in threat_categories:
            recommendations.append("Do not enter credentials or personal information")
            recommendations.append("Verify sender through alternative communication channel")
        
        if 'malicious_attachments' in threat_categories:
            recommendations.append("Do not open attachments from unknown senders")
            recommendations.append("Scan attachments with antivirus before opening")
        
        if 'malicious_infrastructure' in threat_categories:
            recommendations.append("Do not click on suspicious links")
            recommendations.append("Verify URLs manually before visiting")
        
        if 'social_engineering' in threat_categories:
            recommendations.append("Be skeptical of urgent or pressure tactics")
            recommendations.append("Verify claims through official channels")
        
        if analysis_result['risk_level'] in ['high', 'critical']:
            recommendations.append("Consider quarantining this email")
            recommendations.append("Report to security team")
        
        return recommendations
    
    def _generate_email_id(self, email_data: Dict[str, Any]) -> str:
        """Generate unique identifier for email"""
        content = email_data.get('raw_content', str(email_data))
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _is_suspicious_extension(self, filename: str) -> bool:
        """Check if file extension is suspicious"""
        suspicious_extensions = [
            '.exe', '.scr', '.bat', '.com', '.pif', '.vbs', '.js', '.jar',
            '.app', '.deb', '.pkg', '.dmg', '.run', '.msi', '.cmd'
        ]
        return any(filename.lower().endswith(ext) for ext in suspicious_extensions)
    
    def _detect_homograph_attack(self, domain: str) -> bool:
        """Detect potential homograph attacks in domain names"""
        # Check for mixed scripts or suspicious Unicode characters
        suspicious_chars = ['а', 'о', 'р', 'е', 'у', 'х', 'с', 'м', 'к', 'т']  # Cyrillic lookalikes
        return any(char in domain for char in suspicious_chars)
    
    def _check_sender_reputation(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Check sender reputation and authenticity"""
        threats = []
        
        sender = headers.get('from', '')
        if sender:
            # Check for display name spoofing
            if '<' in sender and '>' in sender:
                display_name = sender.split('<')[0].strip().strip('"\'')
                email_address = sender.split('<')[1].split('>')[0].strip()
                
                if display_name and email_address:
                    # Check if display name looks like a brand but email doesn't match
                    brand_keywords = ['amazon', 'paypal', 'microsoft', 'apple', 'google', 'facebook']
                    if any(keyword in display_name.lower() for keyword in brand_keywords):
                        if not any(keyword in email_address.lower() for keyword in brand_keywords):
                            threats.append({
                                'type': 'display_name_spoofing',
                                'severity': 'high',
                                'category': 'sender_spoofing',
                                'description': 'Display name spoofing detected',
                                'evidence': sender,
                                'location': 'headers'
                            })
        
        return threats
    
    def _check_spoofing_indicators(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Check for email spoofing indicators"""
        threats = []
        
        # Check Return-Path vs From mismatch
        return_path = headers.get('return-path', '')
        from_addr = headers.get('from', '')
        
        if return_path and from_addr:
            from_domain = from_addr.split('@')[-1].strip('>')
            return_domain = return_path.split('@')[-1].strip('>')
            
            if from_domain != return_domain:
                threats.append({
                    'type': 'return_path_mismatch',
                    'severity': 'medium',
                    'category': 'sender_spoofing',
                    'description': 'Return-Path domain differs from From domain',
                    'evidence': f'From: {from_domain}, Return-Path: {return_domain}',
                    'location': 'headers'
                })
        
        return threats
    
    def _check_authentication_headers(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Check email authentication headers"""
        threats = []
        
        # Check SPF, DKIM, DMARC results
        auth_results = headers.get('authentication-results', '')
        if auth_results:
            if 'spf=fail' in auth_results.lower():
                threats.append({
                    'type': 'spf_failure',
                    'severity': 'high',
                    'category': 'authentication_failure',
                    'description': 'SPF authentication failed',
                    'evidence': auth_results,
                    'location': 'headers'
                })
            
            if 'dkim=fail' in auth_results.lower():
                threats.append({
                    'type': 'dkim_failure',
                    'severity': 'medium',
                    'category': 'authentication_failure',
                    'description': 'DKIM authentication failed',
                    'evidence': auth_results,
                    'location': 'headers'
                })
        
        return threats
    
    def _check_routing_patterns(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Check for suspicious routing patterns"""
        threats = []
        
        received_headers = headers.get('received', '')
        if received_headers:
            # Check for unusual number of hops
            hop_count = received_headers.count('Received:')
            if hop_count > 10:
                threats.append({
                    'type': 'excessive_hops',
                    'severity': 'medium',
                    'category': 'routing_anomaly',
                    'description': f'Unusual number of routing hops: {hop_count}',
                    'evidence': f'{hop_count} hops detected',
                    'location': 'headers'
                })
        
        return threats
    
    def _analyze_content_part(self, part: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze individual content part"""
        threats = []
        
        content_type = part.get('content_type', '')
        content = part.get('content', '')
        
        if content_type.startswith('text/'):
            text_threats = self._analyze_text_content(content, content_type)
            threats.extend(text_threats)
        
        return threats
    
    def _analyze_emails_in_content(self, content: str, content_type: str) -> List[Dict[str, Any]]:
        """Analyze email addresses found in content"""
        threats = []
        
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = re.findall(email_pattern, content)
        
        for email_addr in emails:
            domain = email_addr.split('@')[1].lower()
            
            # Check for suspicious domains
            if any(domain.endswith(tld) for tld in ['.tk', '.ml', '.ga', '.cf']):
                threats.append({
                    'type': 'suspicious_email_domain',
                    'severity': 'medium',
                    'category': 'suspicious_contact',
                    'description': f'Suspicious email domain: {domain}',
                    'evidence': email_addr,
                    'location': content_type
                })
        
        return threats
    
    def _extract_segment_content(self, content: str, start_tag: str, end_tag: str) -> str:
        """Extract content between start and end tags"""
        try:
            start_idx = content.lower().find(start_tag.lower())
            if start_idx == -1:
                return content
            
            if end_tag:
                end_idx = content.lower().find(end_tag.lower(), start_idx)
                if end_idx != -1:
                    return content[start_idx:end_idx + len(end_tag)]
            
            return content[start_idx:]
        
        except Exception:
            return content
    
    def _search_phrase_in_content(self, content: str, phrase: str, search_type: str) -> bool:
        """Search for phrase in content based on search type"""
        try:
            if search_type == 'single_line':
                return phrase.lower() in content.lower()
            elif search_type == 'multi_line':
                return phrase.lower() in content.lower()
            elif search_type == 'regex':
                return bool(re.search(phrase, content, re.IGNORECASE))
            else:
                return phrase.lower() in content.lower()
        
        except Exception:
            return False
