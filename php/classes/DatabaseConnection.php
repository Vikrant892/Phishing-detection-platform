<?php
/**
 * Database Connection Class
 * Handles all database operations with MySQL/SQLite fallback
 */

class DatabaseConnection {
    private $connection;
    private $dbType;
    private $config;
    
    public function __construct() {
        $this->config = $this->getDbConfig();
        $this->connect();
    }
    
    /**
     * Get database configuration from environment or defaults
     */
    private function getDbConfig() {
        return [
            'host' => $_ENV['PGHOST'] ?? 'localhost',
            'port' => $_ENV['PGPORT'] ?? 3306,
            'database' => $_ENV['PGDATABASE'] ?? 'phishing_detector',
            'username' => $_ENV['PGUSER'] ?? 'root',
            'password' => $_ENV['PGPASSWORD'] ?? 'password',
            'charset' => 'utf8mb4'
        ];
    }
    
    /**
     * Establish database connection
     */
    private function connect() {
        try {
            // Try MySQL first
            $dsn = "mysql:host={$this->config['host']};port={$this->config['port']};dbname={$this->config['database']};charset={$this->config['charset']}";
            $this->connection = new PDO($dsn, $this->config['username'], $this->config['password'], [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false
            ]);
            $this->dbType = 'mysql';
            
        } catch (PDOException $e) {
            // Fallback to SQLite
            try {
                $dbPath = __DIR__ . '/../../database/phishing_detector.db';
                $dbDir = dirname($dbPath);
                if (!is_dir($dbDir)) {
                    mkdir($dbDir, 0755, true);
                }
                
                $this->connection = new PDO("sqlite:$dbPath", null, null, [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
                ]);
                $this->dbType = 'sqlite';
                
                // Create tables if they don't exist
                $this->createTables();
                
            } catch (PDOException $e2) {
                throw new Exception("Database connection failed: " . $e2->getMessage());
            }
        }
    }
    
    /**
     * Create database tables for SQLite
     */
    private function createTables() {
        $tables = [
            "CREATE TABLE IF NOT EXISTS email_analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_hash TEXT UNIQUE NOT NULL,
                source_file TEXT,
                sender TEXT,
                recipient TEXT,
                subject TEXT,
                analysis_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                risk_score REAL DEFAULT 0,
                threat_level TEXT DEFAULT 'minimal',
                threat_types TEXT,
                analysis_data TEXT,
                is_quarantined BOOLEAN DEFAULT FALSE,
                false_positive BOOLEAN DEFAULT FALSE
            )",
            
            "CREATE TABLE IF NOT EXISTS threat_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                pattern_type TEXT DEFAULT 'literal',
                segment_start TEXT,
                segment_end TEXT,
                pattern_text TEXT NOT NULL,
                risk_score INTEGER DEFAULT 10,
                is_active BOOLEAN DEFAULT TRUE,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            
            "CREATE TABLE IF NOT EXISTS sender_reputation (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_email TEXT UNIQUE NOT NULL,
                reputation_score INTEGER DEFAULT 50,
                total_emails INTEGER DEFAULT 0,
                threat_emails INTEGER DEFAULT 0,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_whitelisted BOOLEAN DEFAULT FALSE,
                is_blacklisted BOOLEAN DEFAULT FALSE,
                notes TEXT
            )",
            
            "CREATE TABLE IF NOT EXISTS threat_statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date_recorded DATE NOT NULL UNIQUE,
                total_emails INTEGER DEFAULT 0,
                threat_emails INTEGER DEFAULT 0,
                critical_threats INTEGER DEFAULT 0,
                high_threats INTEGER DEFAULT 0,
                medium_threats INTEGER DEFAULT 0,
                low_threats INTEGER DEFAULT 0,
                quarantined_emails INTEGER DEFAULT 0,
                false_positives INTEGER DEFAULT 0
            )",
            
            "CREATE TABLE IF NOT EXISTS quarantine_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_hash TEXT NOT NULL,
                quarantine_reason TEXT,
                quarantined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                reviewed_by TEXT,
                reviewed_at DATETIME,
                action_taken TEXT DEFAULT 'pending'
            )",
            
            "CREATE TABLE IF NOT EXISTS system_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                setting_key TEXT UNIQUE NOT NULL,
                setting_value TEXT,
                setting_type TEXT DEFAULT 'string',
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )"
        ];
        
        foreach ($tables as $table) {
            $this->connection->exec($table);
        }
        
        // Insert default settings
        $this->insertDefaultSettings();
    }
    
    /**
     * Insert default system settings
     */
    private function insertDefaultSettings() {
        $defaultSettings = [
            ['risk_threshold', '40.0', 'float'],
            ['auto_quarantine', '1', 'boolean'],
            ['notification_email', 'admin@example.com', 'string'],
            ['max_file_size', '100', 'integer'],
            ['retention_days', '90', 'integer']
        ];
        
        foreach ($defaultSettings as $setting) {
            $stmt = $this->connection->prepare("
                INSERT OR IGNORE INTO system_settings (setting_key, setting_value, setting_type) 
                VALUES (?, ?, ?)
            ");
            $stmt->execute($setting);
        }
    }
    
    /**
     * Get recent email analyses
     */
    public function getRecentAnalyses($limit = 50) {
        $stmt = $this->connection->prepare("
            SELECT * FROM email_analyses 
            ORDER BY analysis_timestamp DESC 
            LIMIT ?
        ");
        $stmt->execute([$limit]);
        $results = $stmt->fetchAll();
        
        // Parse JSON fields
        foreach ($results as &$result) {
            if ($result['threat_types']) {
                $result['threat_types'] = json_decode($result['threat_types'], true);
            }
            if ($result['analysis_data']) {
                $result['analysis_data'] = json_decode($result['analysis_data'], true);
            }
        }
        
        return $results;
    }
    
    /**
     * Get analysis by email hash
     */
    public function getAnalysisByHash($emailHash) {
        $stmt = $this->connection->prepare("
            SELECT * FROM email_analyses WHERE email_hash = ?
        ");
        $stmt->execute([$emailHash]);
        $result = $stmt->fetch();
        
        if ($result) {
            if ($result['threat_types']) {
                $result['threat_types'] = json_decode($result['threat_types'], true);
            }
            if ($result['analysis_data']) {
                $result['analysis_data'] = json_decode($result['analysis_data'], true);
            }
        }
        
        return $result;
    }
    
    /**
     * Store email analysis result
     */
    public function storeEmailAnalysis($analysisData) {
        try {
            $stmt = $this->connection->prepare("
                INSERT OR REPLACE INTO email_analyses 
                (email_hash, source_file, sender, recipient, subject, risk_score, 
                 threat_level, threat_types, analysis_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ");
            
            $threatTypes = json_encode($analysisData['threat_classification'] ?? []);
            $analysisJson = json_encode($analysisData);
            
            $result = $stmt->execute([
                $analysisData['email_hash'],
                $analysisData['source_file'] ?? null,
                $analysisData['headers']['from'] ?? '',
                $analysisData['headers']['to'] ?? '',
                $analysisData['headers']['subject'] ?? '',
                $analysisData['risk_score'],
                $analysisData['threat_level'],
                $threatTypes,
                $analysisJson
            ]);
            
            if ($result) {
                $this->updateDailyStatistics();
                return $this->connection->lastInsertId();
            }
            
            return false;
            
        } catch (PDOException $e) {
            error_log("Failed to store email analysis: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Get threat statistics
     */
    public function getThreatStatistics($days = 30) {
        $startDate = date('Y-m-d', strtotime("-$days days"));
        $endDate = date('Y-m-d');
        
        $stmt = $this->connection->prepare("
            SELECT 
                SUM(total_emails) as total_emails,
                SUM(threat_emails) as threat_emails,
                SUM(critical_threats) as critical_threats,
                SUM(high_threats) as high_threats,
                SUM(medium_threats) as medium_threats,
                SUM(low_threats) as low_threats,
                SUM(quarantined_emails) as quarantined_emails,
                SUM(false_positives) as false_positives
            FROM threat_statistics 
            WHERE date_recorded BETWEEN ? AND ?
        ");
        
        $stmt->execute([$startDate, $endDate]);
        $result = $stmt->fetch();
        
        // Calculate percentages
        $total = $result['total_emails'] ?? 0;
        if ($total > 0) {
            $result['threat_percentage'] = ($result['threat_emails'] / $total) * 100;
            $result['quarantine_percentage'] = ($result['quarantined_emails'] / $total) * 100;
        } else {
            $result['threat_percentage'] = 0;
            $result['quarantine_percentage'] = 0;
        }
        
        return $result;
    }
    
    /**
     * Get total emails count
     */
    public function getTotalEmailsCount() {
        $stmt = $this->connection->prepare("SELECT COUNT(*) as count FROM email_analyses");
        $stmt->execute();
        $result = $stmt->fetch();
        return $result['count'] ?? 0;
    }
    
    /**
     * Get threats count
     */
    public function getThreatsCount() {
        $stmt = $this->connection->prepare("
            SELECT COUNT(*) as count FROM email_analyses 
            WHERE risk_score >= 40
        ");
        $stmt->execute();
        $result = $stmt->fetch();
        return $result['count'] ?? 0;
    }
    
    /**
     * Get quarantined emails count
     */
    public function getQuarantinedCount() {
        $stmt = $this->connection->prepare("
            SELECT COUNT(*) as count FROM email_analyses 
            WHERE is_quarantined = 1
        ");
        $stmt->execute();
        $result = $stmt->fetch();
        return $result['count'] ?? 0;
    }
    
    /**
     * Get threat patterns
     */
    public function getThreatPatterns() {
        $stmt = $this->connection->prepare("
            SELECT * FROM threat_patterns WHERE is_active = 1 
            ORDER BY risk_score DESC
        ");
        $stmt->execute();
        return $stmt->fetchAll();
    }
    
    /**
     * Add threat pattern
     */
    public function addThreatPattern($patternData) {
        try {
            $stmt = $this->connection->prepare("
                INSERT INTO threat_patterns 
                (name, pattern_type, segment_start, segment_end, pattern_text, risk_score)
                VALUES (?, ?, ?, ?, ?, ?)
            ");
            
            return $stmt->execute([
                $patternData['name'],
                $patternData['pattern_type'] ?? 'literal',
                $patternData['segment_start'] ?? '',
                $patternData['segment_end'] ?? '',
                $patternData['pattern_text'],
                $patternData['risk_score'] ?? 10
            ]);
            
        } catch (PDOException $e) {
            error_log("Failed to add threat pattern: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Add email to quarantine
     */
    public function addToQuarantine($emailHash, $reason) {
        try {
            $this->connection->beginTransaction();
            
            // Add to quarantine queue
            $stmt = $this->connection->prepare("
                INSERT INTO quarantine_queue (email_hash, quarantine_reason)
                VALUES (?, ?)
            ");
            $stmt->execute([$emailHash, $reason]);
            
            // Update email analysis record
            $stmt = $this->connection->prepare("
                UPDATE email_analyses SET is_quarantined = 1 WHERE email_hash = ?
            ");
            $stmt->execute([$emailHash]);
            
            $this->connection->commit();
            return true;
            
        } catch (PDOException $e) {
            $this->connection->rollback();
            error_log("Failed to quarantine email: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Get system settings
     */
    public function getSystemSettings() {
        $stmt = $this->connection->prepare("SELECT * FROM system_settings");
        $stmt->execute();
        $results = $stmt->fetchAll();
        
        $settings = [];
        foreach ($results as $setting) {
            $value = $setting['setting_value'];
            
            // Convert based on type
            switch ($setting['setting_type']) {
                case 'boolean':
                    $value = (bool) $value;
                    break;
                case 'integer':
                    $value = (int) $value;
                    break;
                case 'float':
                    $value = (float) $value;
                    break;
            }
            
            $settings[$setting['setting_key']] = $value;
        }
        
        return $settings;
    }
    
    /**
     * Update system settings
     */
    public function updateSystemSettings($settings) {
        try {
            $this->connection->beginTransaction();
            
            foreach ($settings as $key => $value) {
                $stmt = $this->connection->prepare("
                    INSERT OR REPLACE INTO system_settings 
                    (setting_key, setting_value, setting_type, updated_at) 
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ");
                
                $type = 'string';
                if (is_bool($value)) {
                    $type = 'boolean';
                    $value = $value ? '1' : '0';
                } elseif (is_int($value)) {
                    $type = 'integer';
                } elseif (is_float($value)) {
                    $type = 'float';
                }
                
                $stmt->execute([$key, (string) $value, $type]);
            }
            
            $this->connection->commit();
            return true;
            
        } catch (PDOException $e) {
            $this->connection->rollback();
            error_log("Failed to update settings: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Update daily statistics
     */
    private function updateDailyStatistics() {
        try {
            $today = date('Y-m-d');
            
            // Get today's counts
            $stmt = $this->connection->prepare("
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN risk_score >= 80 THEN 1 ELSE 0 END) as critical,
                    SUM(CASE WHEN risk_score >= 60 AND risk_score < 80 THEN 1 ELSE 0 END) as high,
                    SUM(CASE WHEN risk_score >= 40 AND risk_score < 60 THEN 1 ELSE 0 END) as medium,
                    SUM(CASE WHEN risk_score >= 20 AND risk_score < 40 THEN 1 ELSE 0 END) as low,
                    SUM(CASE WHEN is_quarantined = 1 THEN 1 ELSE 0 END) as quarantined,
                    SUM(CASE WHEN false_positive = 1 THEN 1 ELSE 0 END) as false_pos
                FROM email_analyses 
                WHERE DATE(analysis_timestamp) = ?
            ");
            
            $stmt->execute([$today]);
            $counts = $stmt->fetch();
            
            // Update statistics
            $threatTotal = ($counts['critical'] ?? 0) + ($counts['high'] ?? 0) + 
                          ($counts['medium'] ?? 0) + ($counts['low'] ?? 0);
            
            $stmt = $this->connection->prepare("
                INSERT OR REPLACE INTO threat_statistics 
                (date_recorded, total_emails, threat_emails, critical_threats, high_threats, 
                 medium_threats, low_threats, quarantined_emails, false_positives)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ");
            
            $stmt->execute([
                $today,
                $counts['total'] ?? 0,
                $threatTotal,
                $counts['critical'] ?? 0,
                $counts['high'] ?? 0,
                $counts['medium'] ?? 0,
                $counts['low'] ?? 0,
                $counts['quarantined'] ?? 0,
                $counts['false_pos'] ?? 0
            ]);
            
        } catch (PDOException $e) {
            error_log("Failed to update daily statistics: " . $e->getMessage());
        }
    }
    
    /**
     * Test database connection
     */
    public function testConnection() {
        try {
            $stmt = $this->connection->prepare("SELECT 1");
            $stmt->execute();
            return true;
        } catch (PDOException $e) {
            return false;
        }
    }
    
    /**
     * Get database type
     */
    public function getDbType() {
        return $this->dbType;
    }
    
    /**
     * Close database connection
     */
    public function close() {
        $this->connection = null;
    }
    
    /**
     * Destructor
     */
    public function __destruct() {
        $this->close();
    }
}
?>
