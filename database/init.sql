-- Phishing Detection Platform Database Initialization
-- This script initializes the database with essential data and configurations

USE `phishing_detection`;

-- Ensure proper SQL mode and settings
SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET AUTOCOMMIT = 0;
START TRANSACTION;

-- Insert comprehensive threat patterns for immediate use
INSERT INTO `threat_patterns` (
    `pattern_name`, `segment_start`, `segment_end`, `pattern`, `pattern_type`, 
    `description`, `severity`, `category`, `is_case_sensitive`, `weight`
) VALUES
-- Phishing Patterns
('Account Verification Urgent', '<body', '</body>', 'verify your account immediately', 'KEYWORD', 'Urgent account verification request - common phishing tactic', 'HIGH', 'PHISHING', FALSE, 20),
('Login Credentials Request', '<body', '</body>', 'confirm.*login.*credential', 'REGEX', 'Requesting login credentials directly', 'CRITICAL', 'PHISHING', FALSE, 25),
('Password Reset Scam', '<body', '</body>', 'reset.*password.*expire', 'REGEX', 'Fake password reset with expiration pressure', 'HIGH', 'PHISHING', FALSE, 18),
('Account Locked Alert', '<body', '</body>', 'account.*locked.*security', 'REGEX', 'Fake account lockout notifications', 'HIGH', 'PHISHING', FALSE, 19),
('Bank Account Issues', '<body', '</body>', 'bank account.*problem.*immediate', 'REGEX', 'Fake banking issues requiring immediate action', 'CRITICAL', 'PHISHING', FALSE, 24),

-- Scam Patterns
('Prize Winner Notification', '<body', '</body>', '(won|winner|prize).*(\$|USD|EUR|£)', 'REGEX', 'Lottery or prize winning notifications', 'HIGH', 'SCAM', FALSE, 21),
('Inheritance Scam', '<body', '</body>', 'inherit.*million.*(dollar|USD)', 'REGEX', 'Inheritance scam offering large sums', 'HIGH', 'SCAM', FALSE, 22),
('Charity Donation Request', '<body', '</body>', 'donate.*urgent.*help', 'REGEX', 'Fake charity donation requests', 'MEDIUM', 'SCAM', FALSE, 15),
('Investment Opportunity', '<body', '</body>', 'investment.*guaranteed.*return', 'REGEX', 'Too good to be true investment offers', 'HIGH', 'SCAM', FALSE, 18),
('Tax Refund Scam', '<body', '</body>', 'tax refund.*claim.*expire', 'REGEX', 'Fake tax refund notifications', 'HIGH', 'SCAM', FALSE, 19),

-- Malware Patterns
('Executable Attachments', 'Content-Type', 'filename', '\.(exe|scr|bat|cmd|com|pif|vbs|js|jar)$', 'REGEX', 'Potentially dangerous executable file types', 'CRITICAL', 'MALWARE', FALSE, 30),
('Suspicious Archives', 'Content-Type', 'filename', '\.(zip|rar|7z).*\.(exe|scr|bat)$', 'REGEX', 'Archives containing executable files', 'HIGH', 'MALWARE', FALSE, 25),
('Macro-Enabled Documents', 'Content-Type', 'filename', '\.(docm|xlsm|pptm)$', 'REGEX', 'Office documents with macros enabled', 'HIGH', 'MALWARE', FALSE, 20),
('PDF with JavaScript', 'Content-Type', 'application/pdf', 'javascript', 'KEYWORD', 'PDF files containing JavaScript', 'HIGH', 'MALWARE', TRUE, 22),

-- Suspicious Links
('URL Shorteners', '<body', '</body>', '(bit\.ly|tinyurl|short\.link|t\.co|goo\.gl|ow\.ly)', 'REGEX', 'Shortened URLs that may hide malicious destinations', 'MEDIUM', 'SUSPICIOUS_LINKS', FALSE, 14),
('IP Address URLs', '<body', '</body>', 'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'REGEX', 'URLs using IP addresses instead of domain names', 'HIGH', 'SUSPICIOUS_LINKS', FALSE, 18),
('Suspicious Domains', '<body', '</body>', '\.(tk|ml|ga|cf)/', 'REGEX', 'Links to suspicious top-level domains', 'MEDIUM', 'SUSPICIOUS_LINKS', FALSE, 12),
('Typosquatting Domains', '<body', '</body>', '(payp4l|g00gle|micr0soft|amaz0n)', 'REGEX', 'Domains that mimic legitimate services', 'HIGH', 'SUSPICIOUS_LINKS', FALSE, 20),

-- Social Engineering
('Urgency Language', '<body', '</body>', '(urgent|immediate|expire|deadline|act now)', 'REGEX', 'Language designed to create urgency', 'MEDIUM', 'SOCIAL_ENGINEERING', FALSE, 10),
('Authority Impersonation', 'From', 'From', '(noreply@|support@|security@|admin@)', 'REGEX', 'Impersonating official support channels', 'MEDIUM', 'SOCIAL_ENGINEERING', FALSE, 12),
('Personal Information Request', '<body', '</body>', 'provide.*(ssn|social security|credit card|password)', 'REGEX', 'Requesting sensitive personal information', 'CRITICAL', 'SOCIAL_ENGINEERING', FALSE, 28),
('Fear-Based Language', '<body', '</body>', '(suspend|terminate|legal action|law enforcement)', 'REGEX', 'Using fear tactics to manipulate victims', 'HIGH', 'SOCIAL_ENGINEERING', FALSE, 16),

-- Header Analysis Patterns
('Missing SPF Record', 'Received-SPF', 'Authentication-Results', 'fail', 'KEYWORD', 'Email failed SPF authentication', 'MEDIUM', 'HEADER_ANALYSIS', FALSE, 15),
('Missing DKIM Signature', 'DKIM-Signature', 'DKIM-Signature', '', 'KEYWORD', 'No DKIM signature present', 'LOW', 'HEADER_ANALYSIS', FALSE, 8),
('Suspicious Originating IP', 'X-Originating-IP', 'X-Originating-IP', '^(10\.|192\.168\.|172\.16\.)', 'REGEX', 'Email originating from private IP ranges', 'MEDIUM', 'HEADER_ANALYSIS', FALSE, 12),
('Forged Return-Path', 'Return-Path', 'From', '!=', 'KEYWORD', 'Return-Path differs significantly from From field', 'HIGH', 'HEADER_ANALYSIS', FALSE, 18),

-- Content Analysis
('Hidden Text', '<body', '</body>', '<span style="display:none"', 'KEYWORD', 'Hidden text that may contain spam content', 'MEDIUM', 'CONTENT_ANALYSIS', FALSE, 12),
('Excessive Capitalization', '<body', '</body>', '[A-Z]{10,}', 'REGEX', 'Excessive use of capital letters', 'LOW', 'CONTENT_ANALYSIS', FALSE, 6),
('Multiple Exclamation Marks', '<body', '</body>', '!{3,}', 'REGEX', 'Excessive use of exclamation marks', 'LOW', 'CONTENT_ANALYSIS', FALSE, 5),
('Suspicious Keywords Combination', '<body', '</body>', '(free|money|cash).*[Nn]o.*obligation', 'REGEX', 'Combination of suspicious promotional keywords', 'MEDIUM', 'CONTENT_ANALYSIS', FALSE, 11),

-- Cryptocurrency Scams
('Cryptocurrency Investment', '<body', '</body>', '(bitcoin|ethereum|crypto).*invest.*guaranteed', 'REGEX', 'Cryptocurrency investment scams', 'HIGH', 'CRYPTO_SCAM', FALSE, 20),
('Wallet Verification Scam', '<body', '</body>', 'verify.*wallet.*private key', 'REGEX', 'Fake wallet verification requesting private keys', 'CRITICAL', 'CRYPTO_SCAM', FALSE, 26),
('Mining Opportunity', '<body', '</body>', 'mining.*profit.*guaranteed.*bitcoin', 'REGEX', 'Fake cryptocurrency mining opportunities', 'HIGH', 'CRYPTO_SCAM', FALSE, 19),

-- Romance Scams
('Romance Scam Language', '<body', '</body>', '(love|dear|honey).*money.*emergency', 'REGEX', 'Romance scam requesting money for emergencies', 'HIGH', 'ROMANCE_SCAM', FALSE, 21),
('Military Romance Scam', '<body', '</body>', 'military.*deployed.*money.*help', 'REGEX', 'Fake military personnel requesting financial help', 'HIGH', 'ROMANCE_SCAM', FALSE, 20),

-- Tech Support Scams
('Fake Tech Support', '<body', '</body>', '(microsoft|apple|google).*support.*computer.*virus', 'REGEX', 'Fake tech support claiming computer infections', 'HIGH', 'TECH_SUPPORT_SCAM', FALSE, 19),
('Windows License Expired', '<body', '</body>', 'windows.*license.*expired.*renew', 'REGEX', 'Fake Windows license expiration notices', 'MEDIUM', 'TECH_SUPPORT_SCAM', FALSE, 15);

-- Insert initial system configuration
INSERT INTO `system_logs` (`log_level`, `component`, `action`, `message`, `ip_address`) VALUES
('INFO', 'DATABASE', 'INITIALIZATION', 'Database schema initialized successfully', '127.0.0.1'),
('INFO', 'DATABASE', 'THREAT_PATTERNS', 'Initial threat patterns loaded successfully', '127.0.0.1');

-- Insert sample ML model performance data
INSERT INTO `ml_models` (
    `model_name`, `model_version`, `model_type`, `accuracy`, `precision_score`, 
    `recall_score`, `f1_score`, `is_active`, `training_date`, `model_config`
) VALUES
(
    'ThreatDetectionRF', 
    '1.0.0', 
    'RandomForestClassifier', 
    87.50, 
    89.20, 
    85.10, 
    87.10, 
    TRUE, 
    NOW(), 
    JSON_OBJECT(
        'n_estimators', 100,
        'max_depth', 10,
        'min_samples_split', 2,
        'min_samples_leaf', 1,
        'random_state', 42,
        'features', JSON_ARRAY('keyword_density', 'link_count', 'attachment_count', 'urgency_score', 'sender_reputation')
    )
);

-- Insert reputation data for common legitimate domains
INSERT INTO `sender_reputation` (`domain`, `reputation_type`, `reputation_score`, `reason`, `added_by`) VALUES
('gmail.com', 'WHITELIST', 95, 'Legitimate email provider', 'SYSTEM'),
('yahoo.com', 'WHITELIST', 90, 'Legitimate email provider', 'SYSTEM'),
('outlook.com', 'WHITELIST', 95, 'Microsoft email service', 'SYSTEM'),
('microsoft.com', 'WHITELIST', 98, 'Official Microsoft domain', 'SYSTEM'),
('google.com', 'WHITELIST', 98, 'Official Google domain', 'SYSTEM'),
('apple.com', 'WHITELIST', 98, 'Official Apple domain', 'SYSTEM'),
('amazon.com', 'WHITELIST', 95, 'Official Amazon domain', 'SYSTEM'),
('paypal.com', 'WHITELIST', 95, 'Official PayPal domain', 'SYSTEM'),
('banking.com', 'WHITELIST', 90, 'Legitimate banking domain pattern', 'SYSTEM'),
('gov', 'WHITELIST', 98, 'Government domains', 'SYSTEM');

-- Insert known suspicious domains
INSERT INTO `sender_reputation` (`domain`, `reputation_type`, `reputation_score`, `reason`, `added_by`) VALUES
('tempmail.com', 'BLACKLIST', 10, 'Temporary email service', 'SYSTEM'),
('10minutemail.com', 'BLACKLIST', 5, 'Temporary email service', 'SYSTEM'),
('guerrillamail.com', 'BLACKLIST', 8, 'Temporary email service', 'SYSTEM'),
('mailinator.com', 'BLACKLIST', 12, 'Temporary email service', 'SYSTEM'),
('throwaway.email', 'BLACKLIST', 5, 'Disposable email service', 'SYSTEM'),
('no-reply.com', 'GREYLIST', 50, 'Suspicious no-reply domain', 'SYSTEM'),
('noreply.tk', 'BLACKLIST', 15, 'Suspicious TLD with no-reply pattern', 'SYSTEM');

-- Create triggers for automated statistics updates
DELIMITER //

CREATE TRIGGER `tr_email_analysis_insert` 
AFTER INSERT ON `email_analyses` 
FOR EACH ROW
BEGIN
    -- Update threat pattern detection counts if applicable
    IF NEW.analysis_data IS NOT NULL THEN
        -- This would be expanded to update specific pattern statistics
        -- based on the analysis results stored in the JSON field
        INSERT INTO system_logs (log_level, component, action, message, details)
        VALUES ('DEBUG', 'TRIGGER', 'ANALYSIS_INSERT', 'New analysis record created', 
                JSON_OBJECT('analysis_id', NEW.analysis_id, 'threat_score', NEW.threat_score));
    END IF;
END //

CREATE TRIGGER `tr_threat_pattern_update`
AFTER UPDATE ON `threat_patterns`
FOR EACH ROW
BEGIN
    IF OLD.is_active != NEW.is_active THEN
        INSERT INTO system_logs (log_level, component, action, message, details)
        VALUES ('INFO', 'TRIGGER', 'PATTERN_STATUS_CHANGE', 'Threat pattern status changed', 
                JSON_OBJECT('pattern_id', NEW.id, 'old_status', OLD.is_active, 'new_status', NEW.is_active));
    END IF;
END //

DELIMITER ;

-- Create additional indexes for optimal performance
CREATE INDEX `idx_analyses_search` ON `email_analyses` (`email_sender`, `email_subject`(100), `risk_level`);
CREATE INDEX `idx_patterns_search` ON `threat_patterns` (`pattern`(50), `category`, `is_active`);
CREATE INDEX `idx_logs_search` ON `system_logs` (`component`, `action`, `log_level`, `created_at`);

-- Insert initial statistics record for today
INSERT INTO `detection_stats` (
    `stat_date`, `total_analyses`, `high_risk_count`, `medium_risk_count`, 
    `low_risk_count`, `quarantined_count`, `avg_threat_score`
) VALUES (
    CURDATE(), 0, 0, 0, 0, 0, 0.00
) ON DUPLICATE KEY UPDATE stat_date = stat_date;

-- Create user for application access (if not exists)
-- Note: In production, use more secure credentials
CREATE USER IF NOT EXISTS 'phishing_app'@'localhost' IDENTIFIED BY 'change_me_in_production';
CREATE USER IF NOT EXISTS 'phishing_app'@'%' IDENTIFIED BY 'change_me_in_production';

-- Grant appropriate permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON phishing_detection.* TO 'phishing_app'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON phishing_detection.* TO 'phishing_app'@'%';

-- Grant execute permissions for stored procedures
GRANT EXECUTE ON PROCEDURE phishing_detection.sp_update_threat_pattern_stats TO 'phishing_app'@'localhost';
GRANT EXECUTE ON PROCEDURE phishing_detection.sp_cleanup_old_data TO 'phishing_app'@'localhost';
GRANT EXECUTE ON PROCEDURE phishing_detection.sp_get_dashboard_stats TO 'phishing_app'@'localhost';
GRANT EXECUTE ON PROCEDURE phishing_detection.sp_update_threat_pattern_stats TO 'phishing_app'@'%';
GRANT EXECUTE ON PROCEDURE phishing_detection.sp_cleanup_old_data TO 'phishing_app'@'%';
GRANT EXECUTE ON PROCEDURE phishing_detection.sp_get_dashboard_stats TO 'phishing_app'@'%';

-- Flush privileges to ensure changes take effect
FLUSH PRIVILEGES;

-- Final system log entry
INSERT INTO `system_logs` (`log_level`, `component`, `action`, `message`, `details`) VALUES
('INFO', 'DATABASE', 'INITIALIZATION_COMPLETE', 'Database initialization completed successfully', 
 JSON_OBJECT(
     'patterns_loaded', (SELECT COUNT(*) FROM threat_patterns),
     'reputation_entries', (SELECT COUNT(*) FROM sender_reputation),
     'ml_models', (SELECT COUNT(*) FROM ml_models),
     'initialization_time', NOW()
 ));

COMMIT;

-- Display initialization summary
SELECT 
    'Database Initialization Complete' as status,
    (SELECT COUNT(*) FROM threat_patterns) as threat_patterns_loaded,
    (SELECT COUNT(*) FROM sender_reputation) as reputation_entries_loaded,
    (SELECT COUNT(*) FROM ml_models) as ml_models_registered,
    NOW() as completion_time;
