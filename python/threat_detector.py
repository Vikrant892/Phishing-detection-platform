"""
Advanced threat detection module for the Phishing Detection Platform
Implements machine learning-based threat scoring and pattern recognition
"""

import re
import json
import logging
import pandas as pd
import numpy as np
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime
import os
from urllib.parse import urlparse
import hashlib
from models import Database, ThreatPattern
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import warnings
warnings.filterwarnings('ignore')

logger = logging.getLogger(__name__)

class ThreatDetector:
    """Advanced threat detection engine with ML capabilities"""
    
    def __init__(self):
        self.db = Database()
        self.threat_patterns = []
        self.ml_model = None
        self.vectorizer = None
        self.load_threat_patterns()
        self.initialize_ml_model()
        
        # Threat scoring weights
        self.scoring_weights = {
            'suspicious_keywords': 15,
            'phishing_patterns': 25,
            'suspicious_links': 20,
            'suspicious_attachments': 15,
            'header_analysis': 10,
            'domain_reputation': 10,
            'ml_prediction': 5
        }
    
    def load_threat_patterns(self):
        """Load threat patterns from database"""
        try:
            self.threat_patterns = self.db.get_threat_patterns()
            logger.info(f"Loaded {len(self.threat_patterns)} threat patterns")
        except Exception as e:
            logger.error(f"Failed to load threat patterns: {e}")
            self.threat_patterns = []
    
    def load_patterns_from_file(self, filepath: str) -> int:
        """Load threat patterns from file (CSV, Excel, JSON)"""
        try:
            file_extension = os.path.splitext(filepath)[1].lower()
            patterns_added = 0
            
            if file_extension == '.csv':
                df = pd.read_csv(filepath)
            elif file_extension in ['.xlsx', '.xls']:
                df = pd.read_excel(filepath)
            elif file_extension == '.json':
                with open(filepath, 'r') as f:
                    data = json.load(f)
                df = pd.DataFrame(data)
            else:
                raise ValueError(f"Unsupported file format: {file_extension}")
            
            # Process each row as a threat pattern
            for _, row in df.iterrows():
                try:
                    pattern = ThreatPattern(
                        segment_start=str(row.get('segment_start', '<body')),
                        segment_end=str(row.get('segment_end', '</body>')),
                        pattern=str(row.get('pattern', '')),
                        description=str(row.get('description', '')),
                        severity=str(row.get('severity', 'MEDIUM')).upper(),
                        is_active=bool(row.get('is_active', True))
                    )
                    
                    if pattern.pattern:  # Only add if pattern is not empty
                        pattern_id = self.db.add_threat_pattern(pattern)
                        if pattern_id:
                            patterns_added += 1
                            
                except Exception as e:
                    logger.warning(f"Skipped invalid pattern: {e}")
                    continue
            
            # Reload patterns from database
            self.load_threat_patterns()
            
            logger.info(f"Added {patterns_added} threat patterns from file")
            return patterns_added
            
        except Exception as e:
            logger.error(f"Failed to load patterns from file: {e}")
            return 0
    
    def initialize_ml_model(self):
        """Initialize machine learning model for threat detection"""
        try:
            # Try to load existing model
            model_path = '../models/threat_model.pkl'
            vectorizer_path = '../models/vectorizer.pkl'
            
            if os.path.exists(model_path) and os.path.exists(vectorizer_path):
                with open(model_path, 'rb') as f:
                    self.ml_model = pickle.load(f)
                with open(vectorizer_path, 'rb') as f:
                    self.vectorizer = pickle.load(f)
                logger.info("Loaded existing ML model")
            else:
                # Train new model with sample data
                self.train_ml_model()
                
        except Exception as e:
            logger.warning(f"ML model initialization failed: {e}")
            self.ml_model = None
            self.vectorizer = None
    
    def train_ml_model(self):
        """Train machine learning model with sample data"""
        try:
            # Create models directory
            os.makedirs('../models', exist_ok=True)
            
            # Sample training data (in production, this would be a larger dataset)
            training_data = [
                ("Urgent: Verify your account immediately", 1),
                ("Your account has been suspended", 1),
                ("Click here to update your payment information", 1),
                ("Limited time offer - act now!", 1),
                ("Security alert: Unauthorized access detected", 1),
                ("Please confirm your identity", 1),
                ("Your bank account requires immediate attention", 1),
                ("Winner! You've won $1,000,000", 1),
                ("Meeting scheduled for tomorrow at 2 PM", 0),
                ("Thank you for your order", 0),
                ("Weekly newsletter", 0),
                ("Project update from team", 0),
                ("Invoice for services rendered", 0),
                ("Birthday party invitation", 0),
                ("Conference registration confirmation", 0),
                ("Monthly report attached", 0)
            ]
            
            texts = [item[0] for item in training_data]
            labels = [item[1] for item in training_data]
            
            # Create TF-IDF vectorizer
            self.vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
            X = self.vectorizer.fit_transform(texts)
            
            # Train Random Forest classifier
            self.ml_model = RandomForestClassifier(n_estimators=100, random_state=42)
            self.ml_model.fit(X, labels)
            
            # Save model and vectorizer
            with open('../models/threat_model.pkl', 'wb') as f:
                pickle.dump(self.ml_model, f)
            with open('../models/vectorizer.pkl', 'wb') as f:
                pickle.dump(self.vectorizer, f)
            
            logger.info("Trained and saved new ML model")
            
        except Exception as e:
            logger.error(f"ML model training failed: {e}")
            self.ml_model = None
            self.vectorizer = None
    
    def analyze_email(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive email threat analysis"""
        analysis_result = {
            'threats': [],
            'score_breakdown': {},
            'recommendations': [],
            'analysis_timestamp': datetime.now().isoformat()
        }
        
        try:
            # 1. Analyze suspicious keywords
            keyword_threats = self._analyze_keywords(email_data)
            analysis_result['threats'].extend(keyword_threats)
            analysis_result['score_breakdown']['suspicious_keywords'] = len(keyword_threats) * 10
            
            # 2. Analyze phishing patterns
            pattern_threats = self._analyze_patterns(email_data)
            analysis_result['threats'].extend(pattern_threats)
            analysis_result['score_breakdown']['phishing_patterns'] = len(pattern_threats) * 15
            
            # 3. Analyze links
            link_threats = self._analyze_links(email_data)
            analysis_result['threats'].extend(link_threats)
            analysis_result['score_breakdown']['suspicious_links'] = len(link_threats) * 12
            
            # 4. Analyze attachments
            attachment_threats = self._analyze_attachments(email_data)
            analysis_result['threats'].extend(attachment_threats)
            analysis_result['score_breakdown']['suspicious_attachments'] = len(attachment_threats) * 18
            
            # 5. Analyze headers
            header_threats = self._analyze_headers(email_data)
            analysis_result['threats'].extend(header_threats)
            analysis_result['score_breakdown']['header_analysis'] = len(header_threats) * 8
            
            # 6. Domain reputation analysis
            domain_threats = self._analyze_domain_reputation(email_data)
            analysis_result['threats'].extend(domain_threats)
            analysis_result['score_breakdown']['domain_reputation'] = len(domain_threats) * 20
            
            # 7. ML-based prediction
            ml_score = self._ml_prediction(email_data)
            analysis_result['score_breakdown']['ml_prediction'] = ml_score
            
            # Generate recommendations
            analysis_result['recommendations'] = self._generate_recommendations(analysis_result)
            
            logger.info(f"Email analysis completed: {len(analysis_result['threats'])} threats found")
            
        except Exception as e:
            logger.error(f"Email analysis error: {e}")
            analysis_result['error'] = str(e)
        
        return analysis_result
    
    def _analyze_keywords(self, email_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze email for suspicious keywords"""
        threats = []
        content = f"{email_data.get('subject', '')} {email_data.get('body', '')}"
        
        suspicious_keywords = {
            'urgent': {'severity': 'medium', 'weight': 10},
            'verify account': {'severity': 'high', 'weight': 20},
            'suspended': {'severity': 'high', 'weight': 18},
            'click here': {'severity': 'medium', 'weight': 12},
            'limited time': {'severity': 'medium', 'weight': 8},
            'act now': {'severity': 'medium', 'weight': 10},
            'confirm identity': {'severity': 'high', 'weight': 15},
            'update payment': {'severity': 'high', 'weight': 18},
            'security alert': {'severity': 'high', 'weight': 16},
            'unauthorized access': {'severity': 'high', 'weight': 20},
            'immediate action': {'severity': 'medium', 'weight': 12},
            'winner': {'severity': 'high', 'weight': 25},
            'congratulations': {'severity': 'medium', 'weight': 10},
            'free money': {'severity': 'high', 'weight': 22},
            'bank account': {'severity': 'high', 'weight': 18}
        }
        
        for keyword, props in suspicious_keywords.items():
            if keyword.lower() in content.lower():
                threats.append({
                    'type': 'suspicious_keyword',
                    'severity': props['severity'],
                    'description': f"Suspicious keyword detected: '{keyword}'",
                    'location': 'content',
                    'weight': props['weight'],
                    'pattern': keyword
                })
        
        return threats
    
    def _analyze_patterns(self, email_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze email against loaded threat patterns"""
        threats = []
        
        for pattern in self.threat_patterns:
            if not pattern.get('is_active', True):
                continue
            
            segment_start = pattern.get('segment_start', '<body')
            segment_end = pattern.get('segment_end', '</body>')
            pattern_text = pattern.get('pattern', '')
            
            # Extract content segment
            content_segment = self._extract_segment(
                email_data.get('raw_content', ''),
                segment_start,
                segment_end
            )
            
            if pattern_text.lower() in content_segment.lower():
                severity_map = {'LOW': 5, 'MEDIUM': 10, 'HIGH': 15, 'CRITICAL': 20}
                weight = severity_map.get(pattern.get('severity', 'MEDIUM'), 10)
                
                threats.append({
                    'type': 'threat_pattern',
                    'severity': pattern.get('severity', 'MEDIUM').lower(),
                    'description': pattern.get('description', f"Threat pattern detected: {pattern_text}"),
                    'location': f"{segment_start} to {segment_end}",
                    'weight': weight,
                    'pattern': pattern_text,
                    'pattern_id': pattern.get('id')
                })
        
        return threats
    
    def _analyze_links(self, email_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze email links for threats"""
        threats = []
        links = email_data.get('links', [])
        
        for link in links:
            url = link.get('url', '')
            
            # Check for suspicious URL patterns
            if self._is_suspicious_url_advanced(url):
                threats.append({
                    'type': 'suspicious_link',
                    'severity': 'high',
                    'description': f"Suspicious URL detected: {url}",
                    'location': 'links',
                    'weight': 18,
                    'url': url
                })
            
            # Check for URL shorteners
            if self._is_url_shortener(url):
                threats.append({
                    'type': 'url_shortener',
                    'severity': 'medium',
                    'description': f"URL shortener detected: {url}",
                    'location': 'links',
                    'weight': 12,
                    'url': url
                })
        
        return threats
    
    def _analyze_attachments(self, email_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze email attachments for threats"""
        threats = []
        attachments = email_data.get('attachments', [])
        
        dangerous_extensions = [
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif',
            '.vbs', '.js', '.jar', '.app', '.dmg', '.pkg'
        ]
        
        suspicious_extensions = [
            '.zip', '.rar', '.7z', '.doc', '.docx', '.xls',
            '.xlsx', '.pdf', '.rtf'
        ]
        
        for attachment in attachments:
            filename = attachment.get('filename', '').lower()
            
            # Check for dangerous extensions
            for ext in dangerous_extensions:
                if filename.endswith(ext):
                    threats.append({
                        'type': 'dangerous_attachment',
                        'severity': 'high',
                        'description': f"Dangerous file type: {filename}",
                        'location': 'attachments',
                        'weight': 25,
                        'filename': filename
                    })
                    break
            
            # Check for suspicious extensions
            for ext in suspicious_extensions:
                if filename.endswith(ext):
                    threats.append({
                        'type': 'suspicious_attachment',
                        'severity': 'medium',
                        'description': f"Potentially suspicious file: {filename}",
                        'location': 'attachments',
                        'weight': 10,
                        'filename': filename
                    })
                    break
        
        return threats
    
    def _analyze_headers(self, email_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze email headers for security threats"""
        threats = []
        headers = email_data.get('headers', {})
        security_headers = email_data.get('security_headers', {})
        
        # Check for missing security headers
        expected_security_headers = [
            'dkim-signature', 'authentication-results'
        ]
        
        missing_headers = []
        for header in expected_security_headers:
            if header not in security_headers:
                missing_headers.append(header)
        
        if missing_headers:
            threats.append({
                'type': 'missing_security_headers',
                'severity': 'medium',
                'description': f"Missing security headers: {', '.join(missing_headers)}",
                'location': 'headers',
                'weight': 8,
                'missing_headers': missing_headers
            })
        
        # Check for suspicious originating IP
        originating_ip = headers.get('x-originating-ip', '')
        if originating_ip and self._is_suspicious_ip(originating_ip):
            threats.append({
                'type': 'suspicious_ip',
                'severity': 'high',
                'description': f"Suspicious originating IP: {originating_ip}",
                'location': 'headers',
                'weight': 15,
                'ip_address': originating_ip
            })
        
        return threats
    
    def _analyze_domain_reputation(self, email_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze sender domain reputation"""
        threats = []
        sender = email_data.get('from', '')
        
        if '@' in sender:
            domain = sender.split('@')[1].lower()
            
            # Check against known bad domains
            suspicious_domains = [
                'tempmail.com', 'guerrillamail.com', '10minutemail.com',
                'mailinator.com', 'throwaway.email', 'temp-mail.org'
            ]
            
            if domain in suspicious_domains:
                threats.append({
                    'type': 'suspicious_domain',
                    'severity': 'high',
                    'description': f"Email from suspicious domain: {domain}",
                    'location': 'sender',
                    'weight': 20,
                    'domain': domain
                })
            
            # Check for domain typosquatting
            legitimate_domains = [
                'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
                'amazon.com', 'apple.com', 'microsoft.com', 'google.com'
            ]
            
            for legit_domain in legitimate_domains:
                if self._is_typosquatting(domain, legit_domain):
                    threats.append({
                        'type': 'domain_typosquatting',
                        'severity': 'high',
                        'description': f"Possible typosquatting: {domain} vs {legit_domain}",
                        'location': 'sender',
                        'weight': 22,
                        'domain': domain,
                        'target_domain': legit_domain
                    })
        
        return threats
    
    def _ml_prediction(self, email_data: Dict[str, Any]) -> int:
        """Use ML model to predict threat score"""
        if not self.ml_model or not self.vectorizer:
            return 0
        
        try:
            # Combine subject and body for prediction
            text = f"{email_data.get('subject', '')} {email_data.get('body', '')}"
            
            # Vectorize the text
            text_vector = self.vectorizer.transform([text])
            
            # Get prediction probability
            prediction_proba = self.ml_model.predict_proba(text_vector)[0]
            
            # Return threat probability as score (0-30)
            threat_score = int(prediction_proba[1] * 30) if len(prediction_proba) > 1 else 0
            
            return threat_score
            
        except Exception as e:
            logger.error(f"ML prediction error: {e}")
            return 0
    
    def calculate_threat_score(self, analysis_result: Dict[str, Any]) -> float:
        """Calculate overall threat score"""
        try:
            total_score = 0
            score_breakdown = analysis_result.get('score_breakdown', {})
            
            for category, score in score_breakdown.items():
                weight = self.scoring_weights.get(category, 1)
                weighted_score = min(score * weight / 100, weight)
                total_score += weighted_score
            
            # Cap at 100
            final_score = min(total_score, 100)
            
            return round(final_score, 2)
            
        except Exception as e:
            logger.error(f"Threat score calculation error: {e}")
            return 0.0
    
    def _generate_recommendations(self, analysis_result: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        threats = analysis_result.get('threats', [])
        
        threat_types = set(threat['type'] for threat in threats)
        
        if 'suspicious_keyword' in threat_types:
            recommendations.append("Be cautious of urgency-inducing language and verify sender authenticity")
        
        if 'suspicious_link' in threat_types:
            recommendations.append("Do not click on suspicious links. Verify URLs manually")
        
        if 'dangerous_attachment' in threat_types:
            recommendations.append("Do not open executable attachments from unknown senders")
        
        if 'missing_security_headers' in threat_types:
            recommendations.append("Email lacks proper authentication headers. Verify sender through alternative means")
        
        if 'suspicious_domain' in threat_types:
            recommendations.append("Sender uses a suspicious domain. Verify legitimacy before responding")
        
        if not recommendations:
            recommendations.append("Email appears safe, but always exercise caution with unsolicited messages")
        
        return recommendations
    
    # Helper methods
    def _extract_segment(self, content: str, start_tag: str, end_tag: str) -> str:
        """Extract content segment between tags"""
        try:
            start_idx = content.lower().find(start_tag.lower())
            if start_idx == -1:
                return content
            
            end_idx = content.lower().find(end_tag.lower(), start_idx)
            if end_idx == -1:
                return content[start_idx:]
            
            return content[start_idx:end_idx + len(end_tag)]
            
        except Exception:
            return content
    
    def _is_suspicious_url_advanced(self, url: str) -> bool:
        """Advanced suspicious URL detection"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Check for suspicious patterns
            suspicious_patterns = [
                'secure-', 'account-', 'verify-', 'update-',
                'login-', 'bank-', 'paypal-', 'amazon-'
            ]
            
            for pattern in suspicious_patterns:
                if pattern in domain:
                    return True
            
            # Check for IP addresses instead of domains
            ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
            if re.match(ip_pattern, domain):
                return True
            
            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.website', '.click']
            for tld in suspicious_tlds:
                if domain.endswith(tld):
                    return True
            
            return False
            
        except Exception:
            return False
    
    def _is_url_shortener(self, url: str) -> bool:
        """Check if URL is from a URL shortening service"""
        shortener_domains = [
            'bit.ly', 'tinyurl.com', 'short.link', 'ow.ly',
            't.co', 'goo.gl', 'tiny.cc', 'is.gd'
        ]
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            return any(shortener in domain for shortener in shortener_domains)
        except:
            return False
    
    def _is_suspicious_ip(self, ip_address: str) -> bool:
        """Check if IP address is suspicious"""
        # This is a simplified check - in production, you'd use threat intelligence feeds
        suspicious_ranges = [
            '10.', '192.168.', '172.16.'  # Private IP ranges (suspicious for external email)
        ]
        
        return any(ip_address.startswith(range_) for range_ in suspicious_ranges)
    
    def _is_typosquatting(self, domain: str, target_domain: str) -> bool:
        """Check if domain is likely typosquatting"""
        if domain == target_domain:
            return False
        
        # Simple Levenshtein-like check
        if len(domain) != len(target_domain):
            return False
        
        differences = sum(c1 != c2 for c1, c2 in zip(domain, target_domain))
        return differences == 1  # Only one character different
