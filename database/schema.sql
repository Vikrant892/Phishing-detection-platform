-- Phishing Detection Platform Database Schema
-- MySQL 8+ compatible schema with advanced indexing and security features

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET AUTOCOMMIT = 0;
START TRANSACTION;
SET time_zone = "+00:00";

-- Database creation (if not exists)
CREATE DATABASE IF NOT EXISTS `phishing_detection` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `phishing_detection`;

-- Email analyses table - stores all email analysis results
CREATE TABLE `email_analyses` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `analysis_id` varchar(36) NOT NULL,
  `email_subject` text DEFAULT NULL,
  `email_sender` varchar(255) DEFAULT NULL,
  `email_recipient` varchar(255) DEFAULT NULL,
  `email_date` datetime DEFAULT NULL,
  `threat_score` decimal(5,2) DEFAULT 0.00,
  `risk_level` enum('LOW','MEDIUM','HIGH') DEFAULT 'LOW',
  `threats_found` int(11) DEFAULT 0,
  `analysis_data` json DEFAULT NULL,
  `email_content` longtext DEFAULT NULL,
  `email_headers` json DEFAULT NULL,
  `links_extracted` json DEFAULT NULL,
  `attachments_info` json DEFAULT NULL,
  `is_quarantined` boolean DEFAULT FALSE,
  `quarantine_reason` text DEFAULT NULL,
  `quarantine_date` datetime DEFAULT NULL,
  `processing_time_ms` int(11) DEFAULT NULL,
  `ml_confidence` decimal(5,2) DEFAULT NULL,
  `false_positive` boolean DEFAULT FALSE,
  `reviewed_by` varchar(100) DEFAULT NULL,
  `review_date` datetime DEFAULT NULL,
  `review_notes` text DEFAULT NULL,
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_analysis_id` (`analysis_id`),
  KEY `idx_created_at` (`created_at`),
  KEY `idx_risk_level` (`risk_level`),
  KEY `idx_threat_score` (`threat_score`),
  KEY `idx_sender` (`email_sender`),
  KEY `idx_quarantined` (`is_quarantined`),
  KEY `idx_email_date` (`email_date`),
  FULLTEXT KEY `idx_subject_content` (`email_subject`, `email_content`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Threat patterns table - stores detection patterns and rules
CREATE TABLE `threat_patterns` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `pattern_name` varchar(255) DEFAULT NULL,
  `segment_start` varchar(255) NOT NULL,
  `segment_end` varchar(255) NOT NULL,
  `pattern` text NOT NULL,
  `pattern_type` enum('KEYWORD','REGEX','ML_FEATURE','HEADER','URL','ATTACHMENT') DEFAULT 'KEYWORD',
  `description` text DEFAULT NULL,
  `severity` enum('LOW','MEDIUM','HIGH','CRITICAL') DEFAULT 'MEDIUM',
  `category` varchar(100) DEFAULT NULL,
  `is_active` boolean DEFAULT TRUE,
  `is_case_sensitive` boolean DEFAULT FALSE,
  `weight` int(11) DEFAULT 10,
  `false_positive_rate` decimal(5,2) DEFAULT 0.00,
  `detection_count` int(11) DEFAULT 0,
  `last_detected` datetime DEFAULT NULL,
  `created_by` varchar(100) DEFAULT NULL,
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_segment` (`segment_start`, `segment_end`),
  KEY `idx_severity` (`severity`),
  KEY `idx_active` (`is_active`),
  KEY `idx_category` (`category`),
  KEY `idx_pattern_type` (`pattern_type`),
  FULLTEXT KEY `idx_pattern_text` (`pattern`, `description`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Detection statistics table - aggregated daily statistics
CREATE TABLE `detection_stats` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `stat_date` date NOT NULL,
  `total_analyses` int(11) DEFAULT 0,
  `high_risk_count` int(11) DEFAULT 0,
  `medium_risk_count` int(11) DEFAULT 0,
  `low_risk_count` int(11) DEFAULT 0,
  `quarantined_count` int(11) DEFAULT 0,
  `false_positive_count` int(11) DEFAULT 0,
  `avg_threat_score` decimal(5,2) DEFAULT 0.00,
  `avg_processing_time` int(11) DEFAULT 0,
  `unique_senders` int(11) DEFAULT 0,
  `unique_domains` int(11) DEFAULT 0,
  `total_links` int(11) DEFAULT 0,
  `suspicious_links` int(11) DEFAULT 0,
  `total_attachments` int(11) DEFAULT 0,
  `suspicious_attachments` int(11) DEFAULT 0,
  `ml_accuracy` decimal(5,2) DEFAULT NULL,
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_stat_date` (`stat_date`),
  KEY `idx_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- System logs table - application and security logs
CREATE TABLE `system_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `log_level` enum('DEBUG','INFO','WARNING','ERROR','CRITICAL') DEFAULT 'INFO',
  `component` varchar(100) DEFAULT NULL,
  `action` varchar(255) DEFAULT NULL,
  `message` text NOT NULL,
  `details` json DEFAULT NULL,
  `user_id` varchar(100) DEFAULT NULL,
  `session_id` varchar(255) DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `request_id` varchar(36) DEFAULT NULL,
  `execution_time` int(11) DEFAULT NULL,
  `memory_usage` int(11) DEFAULT NULL,
  `stack_trace` text DEFAULT NULL,
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_log_level` (`log_level`),
  KEY `idx_created_at` (`created_at`),
  KEY `idx_component` (`component`),
  KEY `idx_action` (`action`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_ip_address` (`ip_address`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- User sessions table - for session management
CREATE TABLE `user_sessions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `session_id` varchar(255) NOT NULL,
  `user_id` varchar(100) DEFAULT 'anonymous',
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `last_activity` timestamp DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `session_data` json DEFAULT NULL,
  `is_active` boolean DEFAULT TRUE,
  `expires_at` datetime DEFAULT NULL,
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_session_id` (`session_id`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_last_activity` (`last_activity`),
  KEY `idx_expires_at` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Whitelist/Blacklist table - for trusted/blocked senders and domains
CREATE TABLE `sender_reputation` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `email_address` varchar(255) DEFAULT NULL,
  `domain` varchar(255) DEFAULT NULL,
  `reputation_type` enum('WHITELIST','BLACKLIST','GREYLIST') NOT NULL,
  `reputation_score` int(11) DEFAULT 0,
  `reason` text DEFAULT NULL,
  `added_by` varchar(100) DEFAULT NULL,
  `is_active` boolean DEFAULT TRUE,
  `expires_at` datetime DEFAULT NULL,
  `last_seen` datetime DEFAULT NULL,
  `detection_count` int(11) DEFAULT 0,
  `false_positive_count` int(11) DEFAULT 0,
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_email_address` (`email_address`),
  KEY `idx_domain` (`domain`),
  KEY `idx_reputation_type` (`reputation_type`),
  KEY `idx_active` (`is_active`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ML model metadata table - for tracking ML model versions and performance
CREATE TABLE `ml_models` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `model_name` varchar(255) NOT NULL,
  `model_version` varchar(50) NOT NULL,
  `model_type` varchar(100) DEFAULT NULL,
  `model_path` text DEFAULT NULL,
  `training_data_size` int(11) DEFAULT NULL,
  `accuracy` decimal(5,2) DEFAULT NULL,
  `precision_score` decimal(5,2) DEFAULT NULL,
  `recall_score` decimal(5,2) DEFAULT NULL,
  `f1_score` decimal(5,2) DEFAULT NULL,
  `is_active` boolean DEFAULT FALSE,
  `training_date` datetime DEFAULT NULL,
  `last_used` datetime DEFAULT NULL,
  `usage_count` int(11) DEFAULT 0,
  `model_config` json DEFAULT NULL,
  `performance_metrics` json DEFAULT NULL,
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_model_version` (`model_name`, `model_version`),
  KEY `idx_is_active` (`is_active`),
  KEY `idx_accuracy` (`accuracy`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Report exports table - tracks generated reports
CREATE TABLE `report_exports` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `report_id` varchar(36) NOT NULL,
  `report_type` enum('PDF','EXCEL','CSV','JSON') NOT NULL,
  `report_name` varchar(255) DEFAULT NULL,
  `date_from` date DEFAULT NULL,
  `date_to` date DEFAULT NULL,
  `filters` json DEFAULT NULL,
  `file_path` text DEFAULT NULL,
  `file_size` int(11) DEFAULT NULL,
  `record_count` int(11) DEFAULT NULL,
  `generated_by` varchar(100) DEFAULT NULL,
  `generation_time_ms` int(11) DEFAULT NULL,
  `download_count` int(11) DEFAULT 0,
  `expires_at` datetime DEFAULT NULL,
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_report_id` (`report_id`),
  KEY `idx_report_type` (`report_type`),
  KEY `idx_generated_by` (`generated_by`),
  KEY `idx_expires_at` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create indexes for better performance
CREATE INDEX `idx_analyses_composite` ON `email_analyses` (`risk_level`, `created_at`, `threat_score`);
CREATE INDEX `idx_stats_composite` ON `detection_stats` (`stat_date`, `total_analyses`);
CREATE INDEX `idx_logs_composite` ON `system_logs` (`log_level`, `created_at`, `component`);

-- Create views for common queries
CREATE VIEW `v_daily_threat_summary` AS
SELECT 
    DATE(created_at) as analysis_date,
    COUNT(*) as total_analyses,
    SUM(CASE WHEN risk_level = 'HIGH' THEN 1 ELSE 0 END) as high_risk,
    SUM(CASE WHEN risk_level = 'MEDIUM' THEN 1 ELSE 0 END) as medium_risk,
    SUM(CASE WHEN risk_level = 'LOW' THEN 1 ELSE 0 END) as low_risk,
    AVG(threat_score) as avg_threat_score,
    SUM(CASE WHEN is_quarantined = TRUE THEN 1 ELSE 0 END) as quarantined
FROM email_analyses 
WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
GROUP BY DATE(created_at)
ORDER BY analysis_date DESC;

CREATE VIEW `v_top_threat_patterns` AS
SELECT 
    tp.id,
    tp.pattern,
    tp.severity,
    tp.detection_count,
    tp.last_detected,
    tp.false_positive_rate
FROM threat_patterns tp
WHERE tp.is_active = TRUE
ORDER BY tp.detection_count DESC, tp.severity DESC
LIMIT 50;

CREATE VIEW `v_recent_high_risk_analyses` AS
SELECT 
    analysis_id,
    email_subject,
    email_sender,
    threat_score,
    threats_found,
    is_quarantined,
    created_at
FROM email_analyses 
WHERE risk_level = 'HIGH' 
    AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
ORDER BY created_at DESC;

-- Create stored procedures for common operations
DELIMITER //

CREATE PROCEDURE `sp_update_threat_pattern_stats`(
    IN pattern_id INT
)
BEGIN
    DECLARE detection_count INT DEFAULT 0;
    DECLARE last_detected_date DATETIME DEFAULT NULL;
    
    -- Count detections for this pattern
    SELECT COUNT(*), MAX(ea.created_at)
    INTO detection_count, last_detected_date
    FROM email_analyses ea
    WHERE JSON_SEARCH(ea.analysis_data, 'one', CAST(pattern_id AS CHAR), NULL, '$.threats[*].pattern_id') IS NOT NULL;
    
    -- Update pattern statistics
    UPDATE threat_patterns 
    SET detection_count = detection_count,
        last_detected = last_detected_date,
        updated_at = CURRENT_TIMESTAMP
    WHERE id = pattern_id;
END //

CREATE PROCEDURE `sp_cleanup_old_data`(
    IN retention_days INT DEFAULT 90
)
BEGIN
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        RESIGNAL;
    END;
    
    START TRANSACTION;
    
    -- Clean up old analyses (keep only last N days)
    DELETE FROM email_analyses 
    WHERE created_at < DATE_SUB(CURDATE(), INTERVAL retention_days DAY)
        AND is_quarantined = FALSE;
    
    -- Clean up old system logs
    DELETE FROM system_logs 
    WHERE created_at < DATE_SUB(CURDATE(), INTERVAL retention_days DAY)
        AND log_level NOT IN ('ERROR', 'CRITICAL');
    
    -- Clean up expired sessions
    DELETE FROM user_sessions 
    WHERE expires_at < NOW() OR last_activity < DATE_SUB(NOW(), INTERVAL 7 DAY);
    
    -- Clean up old reports
    DELETE FROM report_exports 
    WHERE expires_at < NOW() OR created_at < DATE_SUB(CURDATE(), INTERVAL 30 DAY);
    
    COMMIT;
END //

CREATE PROCEDURE `sp_get_dashboard_stats`()
BEGIN
    SELECT 
        (SELECT COUNT(*) FROM email_analyses) as total_analyses,
        (SELECT COUNT(*) FROM email_analyses WHERE risk_level = 'HIGH') as high_risk_count,
        (SELECT COUNT(*) FROM email_analyses WHERE risk_level = 'MEDIUM') as medium_risk_count,
        (SELECT COUNT(*) FROM email_analyses WHERE risk_level = 'LOW') as low_risk_count,
        (SELECT COUNT(*) FROM email_analyses WHERE is_quarantined = TRUE) as quarantined_count,
        (SELECT ROUND(AVG(threat_score), 2) FROM email_analyses) as avg_threat_score,
        (SELECT COUNT(*) FROM email_analyses WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)) as recent_24h,
        (SELECT COUNT(*) FROM threat_patterns WHERE is_active = TRUE) as active_patterns;
END //

DELIMITER ;

-- Insert default data
INSERT INTO `threat_patterns` (`pattern_name`, `segment_start`, `segment_end`, `pattern`, `pattern_type`, `description`, `severity`, `category`, `weight`) VALUES
('Urgent Account Verification', '<body', '</body>', 'urgent.*verify.*account', 'REGEX', 'Common phishing pattern requesting urgent account verification', 'HIGH', 'PHISHING', 20),
('Account Suspension Warning', '<body', '</body>', 'account.*suspend', 'REGEX', 'Threatening account suspension to create urgency', 'HIGH', 'PHISHING', 18),
('Click Here Links', '<body', '</body>', 'click here', 'KEYWORD', 'Suspicious call-to-action text', 'MEDIUM', 'SUSPICIOUS_LINKS', 12),
('Limited Time Offer', '<body', '</body>', 'limited time', 'KEYWORD', 'Creating artificial urgency', 'MEDIUM', 'SCAM', 10),
('Lottery Winner Notification', '<body', '</body>', 'congratulations.*winner', 'REGEX', 'Lottery scam notification', 'HIGH', 'SCAM', 22),
('Bank Security Alert', '<body', '</body>', 'security alert', 'KEYWORD', 'Fake security notifications', 'HIGH', 'PHISHING', 16),
('Update Payment Information', '<body', '</body>', 'update.*payment', 'REGEX', 'Requesting payment information updates', 'HIGH', 'PHISHING', 18),
('Free Money Claims', '<body', '</body>', 'free money', 'KEYWORD', 'Too good to be true offers', 'HIGH', 'SCAM', 20),
('Suspicious File Extensions', 'Content-Type', 'filename', '\.(exe|scr|bat|cmd|com|pif|vbs|js)$', 'REGEX', 'Dangerous executable file extensions', 'CRITICAL', 'MALWARE', 25),
('URL Shorteners', '<body', '</body>', '(bit\.ly|tinyurl|short\.link)', 'REGEX', 'Shortened URLs that may hide malicious destinations', 'MEDIUM', 'SUSPICIOUS_LINKS', 14);

-- Insert initial ML model record
INSERT INTO `ml_models` (`model_name`, `model_version`, `model_type`, `accuracy`, `is_active`, `training_date`) VALUES
('ThreatDetectionRF', '1.0.0', 'RandomForest', 85.50, TRUE, NOW());

-- Create event scheduler for automated maintenance
SET GLOBAL event_scheduler = ON;

CREATE EVENT `ev_daily_stats_update`
ON SCHEDULE EVERY 1 DAY
STARTS TIMESTAMP(CURDATE() + INTERVAL 1 DAY, '02:00:00')
DO
  INSERT INTO detection_stats (
    stat_date, total_analyses, high_risk_count, medium_risk_count, 
    low_risk_count, quarantined_count, avg_threat_score
  )
  SELECT 
    CURDATE() - INTERVAL 1 DAY,
    COUNT(*),
    SUM(CASE WHEN risk_level = 'HIGH' THEN 1 ELSE 0 END),
    SUM(CASE WHEN risk_level = 'MEDIUM' THEN 1 ELSE 0 END),
    SUM(CASE WHEN risk_level = 'LOW' THEN 1 ELSE 0 END),
    SUM(CASE WHEN is_quarantined = TRUE THEN 1 ELSE 0 END),
    AVG(threat_score)
  FROM email_analyses 
  WHERE DATE(created_at) = CURDATE() - INTERVAL 1 DAY
  ON DUPLICATE KEY UPDATE
    total_analyses = VALUES(total_analyses),
    high_risk_count = VALUES(high_risk_count),
    medium_risk_count = VALUES(medium_risk_count),
    low_risk_count = VALUES(low_risk_count),
    quarantined_count = VALUES(quarantined_count),
    avg_threat_score = VALUES(avg_threat_score);

COMMIT;
