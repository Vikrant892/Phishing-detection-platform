<?php
/**
 * Configuration File
 * Global configuration settings for the application
 */

// Start output buffering
ob_start();

// Set timezone
date_default_timezone_set('UTC');

// Application Configuration
define('APP_NAME', 'Phishing Detection Platform');
define('APP_VERSION', '1.0.0');
define('APP_DEBUG', false);

// Directory Configuration
define('ROOT_DIR', dirname(__DIR__));
define('UPLOADS_DIR', ROOT_DIR . '/uploads');
define('EXPORTS_DIR', ROOT_DIR . '/exports');
define('LOGS_DIR', ROOT_DIR . '/logs');
define('TEMP_DIR', ROOT_DIR . '/temp');

// Create directories if they don't exist
$directories = [UPLOADS_DIR, EXPORTS_DIR, LOGS_DIR, TEMP_DIR];
foreach ($directories as $dir) {
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
}

// Database Configuration
define('DB_HOST', $_ENV['PGHOST'] ?? 'localhost');
define('DB_PORT', $_ENV['PGPORT'] ?? 3306);
define('DB_NAME', $_ENV['PGDATABASE'] ?? 'phishing_detector');
define('DB_USER', $_ENV['PGUSER'] ?? 'root');
define('DB_PASS', $_ENV['PGPASSWORD'] ?? null);
define('DB_CHARSET', 'utf8mb4');

// API Configuration
define('PYTHON_API_URL', 'http://localhost:8000/api/v1');
define('API_TIMEOUT', 300); // 5 minutes

// File Upload Configuration
define('MAX_FILE_SIZE', 100 * 1024 * 1024); // 100MB
define('ALLOWED_FILE_TYPES', ['.eml', '.msg', '.txt', '.mbox', '.zip']);

// Security Configuration
define('SESSION_TIMEOUT', 3600); // 1 hour
define('CSRF_TOKEN_NAME', 'csrf_token');
define('ENCRYPTION_KEY', getenv('ENCRYPTION_KEY') ?: null);

// Threat Detection Configuration
define('DEFAULT_RISK_THRESHOLD', 40.0);
define('AUTO_QUARANTINE_THRESHOLD', 80.0);
define('AUTO_QUARANTINE_ENABLED', true);

// Email Processing Configuration
define('BATCH_PROCESSING_LIMIT', 50);
define('PROCESSING_TIMEOUT', 300); // 5 minutes

// Logging Configuration
define('LOG_LEVEL', 'INFO');
define('LOG_FILE', LOGS_DIR . '/application.log');
define('ERROR_LOG_FILE', LOGS_DIR . '/error.log');

// Cache Configuration
define('CACHE_ENABLED', true);
define('CACHE_LIFETIME', 300); // 5 minutes

// Report Configuration
define('REPORT_FORMATS', ['html', 'json', 'csv', 'txt']);
define('REPORT_RETENTION_DAYS', 30);

// Performance Configuration
define('PAGINATION_LIMIT', 50);
define('MAX_SEARCH_RESULTS', 1000);

// Feature Flags
$features = [
    'batch_processing' => true,
    'real_time_alerts' => true,
    'export_reports' => true,
    'quarantine_management' => true,
    'sender_reputation' => true,
    'threat_patterns' => true,
    'dashboard_analytics' => true,
    'mobile_responsive' => true
];

define('FEATURES', $features);

// Error Reporting
if (APP_DEBUG) {
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
    ini_set('log_errors', 1);
    ini_set('error_log', ERROR_LOG_FILE);
} else {
    error_reporting(E_ERROR | E_WARNING | E_PARSE);
    ini_set('display_errors', 0);
    ini_set('log_errors', 1);
    ini_set('error_log', ERROR_LOG_FILE);
}

// Session Configuration
ini_set('session.cookie_lifetime', SESSION_TIMEOUT);
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 0); // Set to 1 for HTTPS
ini_set('session.use_strict_mode', 1);

// Memory and execution limits
ini_set('memory_limit', '512M');
ini_set('max_execution_time', 300);
ini_set('max_input_time', 300);

// File upload limits
ini_set('upload_max_filesize', '100M');
ini_set('post_max_size', '120M');
ini_set('max_file_uploads', 20);

/**
 * Get application configuration value
 */
function getConfig($key, $default = null) {
    $config = [
        'app_name' => APP_NAME,
        'app_version' => APP_VERSION,
        'debug' => APP_DEBUG,
        'max_file_size' => MAX_FILE_SIZE,
        'allowed_file_types' => ALLOWED_FILE_TYPES,
        'risk_threshold' => DEFAULT_RISK_THRESHOLD,
        'quarantine_threshold' => AUTO_QUARANTINE_THRESHOLD,
        'features' => FEATURES
    ];
    
    return $config[$key] ?? $default;
}

/**
 * Get database configuration
 */
function getDbConfig() {
    return [
        'host' => DB_HOST,
        'port' => DB_PORT,
        'database' => DB_NAME,
        'username' => DB_USER,
        'password' => DB_PASS,
        'charset' => DB_CHARSET
    ];
}

/**
 * Log message to application log
 */
function logMessage($message, $level = 'INFO') {
    $timestamp = date('Y-m-d H:i:s');
    $logEntry = "[$timestamp] [$level] $message" . PHP_EOL;
    
    // Write to log file
    file_put_contents(LOG_FILE, $logEntry, FILE_APPEND | LOCK_EX);
    
    // Also log errors to error log
    if ($level === 'ERROR') {
        error_log($message);
    }
}

/**
 * Generate CSRF token
 */
function generateCSRFToken() {
    if (!isset($_SESSION[CSRF_TOKEN_NAME])) {
        $_SESSION[CSRF_TOKEN_NAME] = bin2hex(random_bytes(32));
    }
    return $_SESSION[CSRF_TOKEN_NAME];
}

/**
 * Verify CSRF token
 */
function verifyCSRFToken($token) {
    return isset($_SESSION[CSRF_TOKEN_NAME]) && 
           hash_equals($_SESSION[CSRF_TOKEN_NAME], $token);
}

/**
 * Sanitize input data
 */
function sanitizeInput($data) {
    if (is_array($data)) {
        return array_map('sanitizeInput', $data);
    }
    
    return htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8');
}

/**
 * Format file size
 */
function formatFileSize($bytes) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $i = 0;
    
    while ($bytes >= 1024 && $i < count($units) - 1) {
        $bytes /= 1024;
        $i++;
    }
    
    return round($bytes, 2) . ' ' . $units[$i];
}

/**
 * Check if feature is enabled
 */
function isFeatureEnabled($feature) {
    return FEATURES[$feature] ?? false;
}

/**
 * Get threat level color class
 */
function getThreatLevelClass($threatLevel) {
    $classes = [
        'critical' => 'danger',
        'high' => 'warning',
        'medium' => 'info',
        'low' => 'secondary',
        'minimal' => 'success'
    ];
    
    return $classes[$threatLevel] ?? 'secondary';
}

/**
 * Get risk score color class
 */
function getRiskScoreClass($riskScore) {
    if ($riskScore >= 80) return 'danger';
    if ($riskScore >= 60) return 'warning';
    if ($riskScore >= 40) return 'info';
    if ($riskScore >= 20) return 'secondary';
    return 'success';
}

/**
 * Format timestamp
 */
function formatTimestamp($timestamp, $format = 'Y-m-d H:i:s') {
    return date($format, strtotime($timestamp));
}

/**
 * Time ago helper
 */
function timeAgo($timestamp) {
    $time = time() - strtotime($timestamp);
    
    if ($time < 60) return 'Just now';
    if ($time < 3600) return floor($time/60) . ' minutes ago';
    if ($time < 86400) return floor($time/3600) . ' hours ago';
    if ($time < 2592000) return floor($time/86400) . ' days ago';
    
    return date('M j, Y', strtotime($timestamp));
}

/**
 * Truncate text
 */
function truncateText($text, $length = 100, $suffix = '...') {
    if (strlen($text) <= $length) {
        return $text;
    }
    
    return substr($text, 0, $length - strlen($suffix)) . $suffix;
}

/**
 * Generate unique ID
 */
function generateUniqueId($prefix = '') {
    return $prefix . uniqid() . '_' . mt_rand(1000, 9999);
}

/**
 * Validate email address
 */
function isValidEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

/**
 * Get client IP address
 */
function getClientIP() {
    $ipKeys = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];
    
    foreach ($ipKeys as $key) {
        if (!empty($_SERVER[$key])) {
            $ip = $_SERVER[$key];
            if (strpos($ip, ',') !== false) {
                $ip = trim(explode(',', $ip)[0]);
            }
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return $ip;
            }
        }
    }
    
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

/**
 * Check if request is AJAX
 */
function isAjaxRequest() {
    return !empty($_SERVER['HTTP_X_REQUESTED_WITH']) && 
           strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';
}

/**
 * Send JSON response
 */
function sendJSONResponse($data, $statusCode = 200) {
    http_response_code($statusCode);
    header('Content-Type: application/json');
    echo json_encode($data);
    exit;
}

// Initialize logging
logMessage("Application initialized - " . APP_NAME . " v" . APP_VERSION);

// Set default timezone for the application
if (function_exists('date_default_timezone_set')) {
    date_default_timezone_set('UTC');
}
?>
