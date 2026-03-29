<?php
/**
 * Configuration settings for the Phishing Detection Platform
 */

// Error reporting
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Session configuration
session_start();

// Database configuration
define('DB_HOST', $_ENV['PGHOST'] ?? 'localhost');
define('DB_NAME', $_ENV['PGDATABASE'] ?? 'phishing_detection');
define('DB_USER', $_ENV['PGUSER'] ?? 'root');
define('DB_PASS', $_ENV['PGPASSWORD'] ?? null);
define('DB_PORT', $_ENV['PGPORT'] ?? 3306);

// API configuration
define('API_BASE_URL', 'http://localhost:8000/api');
define('API_TIMEOUT', 30);

// Application configuration
define('APP_NAME', 'Phishing Detection Platform');
define('APP_VERSION', '1.0.0');
define('UPLOAD_DIR', '../uploads/');
define('LOGS_DIR', '../logs/');
define('REPORTS_DIR', '../reports/');

// Security configuration
define('CSRF_TOKEN_LENGTH', 32);
define('SESSION_TIMEOUT', 3600); // 1 hour

// File upload limits
define('MAX_FILE_SIZE', 16 * 1024 * 1024); // 16MB
define('ALLOWED_EXTENSIONS', ['eml', 'msg', 'txt', 'csv', 'xlsx', 'xls', 'json']);

// Pagination
define('ITEMS_PER_PAGE', 20);

// Theme settings
define('DEFAULT_THEME', 'light');

/**
 * Database connection class
 */
class Database {
    private static $instance = null;
    private $connection;
    
    private function __construct() {
        try {
            $dsn = "mysql:host=" . DB_HOST . ";port=" . DB_PORT . ";dbname=" . DB_NAME . ";charset=utf8mb4";
            $this->connection = new PDO($dsn, DB_USER, DB_PASS, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false
            ]);
        } catch (PDOException $e) {
            error_log("Database connection failed: " . $e->getMessage());
            throw new Exception("Database connection failed");
        }
    }
    
    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    public function getConnection() {
        return $this->connection;
    }
    
    public function query($sql, $params = []) {
        try {
            $stmt = $this->connection->prepare($sql);
            $stmt->execute($params);
            return $stmt;
        } catch (PDOException $e) {
            error_log("Database query failed: " . $e->getMessage());
            throw new Exception("Database query failed");
        }
    }
}

/**
 * API client class
 */
class ApiClient {
    private $baseUrl;
    private $timeout;
    
    public function __construct() {
        $this->baseUrl = API_BASE_URL;
        $this->timeout = API_TIMEOUT;
    }
    
    public function get($endpoint, $params = []) {
        $url = $this->baseUrl . $endpoint;
        if (!empty($params)) {
            $url .= '?' . http_build_query($params);
        }
        
        return $this->makeRequest('GET', $url);
    }
    
    public function post($endpoint, $data = []) {
        $url = $this->baseUrl . $endpoint;
        return $this->makeRequest('POST', $url, $data);
    }
    
    public function postFile($endpoint, $files = [], $data = []) {
        $url = $this->baseUrl . $endpoint;
        
        $curl = curl_init();
        
        // Prepare multipart data
        $postData = $data;
        foreach ($files as $key => $file) {
            if (file_exists($file)) {
                $postData[$key] = new CURLFile($file);
            }
        }
        
        curl_setopt_array($curl, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $postData,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_HTTPHEADER => [
                'Accept: application/json'
            ]
        ]);
        
        $response = curl_exec($curl);
        $httpCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        
        if (curl_errno($curl)) {
            $error = curl_error($curl);
            curl_close($curl);
            throw new Exception("API request failed: " . $error);
        }
        
        curl_close($curl);
        
        $decodedResponse = json_decode($response, true);
        
        return [
            'status_code' => $httpCode,
            'data' => $decodedResponse,
            'success' => $httpCode >= 200 && $httpCode < 300
        ];
    }
    
    private function makeRequest($method, $url, $data = null) {
        $curl = curl_init();
        
        $options = [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'Accept: application/json'
            ]
        ];
        
        if ($method === 'POST' && $data !== null) {
            $options[CURLOPT_POST] = true;
            $options[CURLOPT_POSTFIELDS] = json_encode($data);
        }
        
        curl_setopt_array($curl, $options);
        
        $response = curl_exec($curl);
        $httpCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        
        if (curl_errno($curl)) {
            $error = curl_error($curl);
            curl_close($curl);
            throw new Exception("API request failed: " . $error);
        }
        
        curl_close($curl);
        
        $decodedResponse = json_decode($response, true);
        
        return [
            'status_code' => $httpCode,
            'data' => $decodedResponse,
            'success' => $httpCode >= 200 && $httpCode < 300
        ];
    }
}

/**
 * Utility functions
 */
function generateCsrfToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(CSRF_TOKEN_LENGTH));
    }
    return $_SESSION['csrf_token'];
}

function verifyCsrfToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

function sanitizeInput($input) {
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

function formatFileSize($bytes) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    
    for ($i = 0; $bytes > 1024 && $i < count($units) - 1; $i++) {
        $bytes /= 1024;
    }
    
    return round($bytes, 2) . ' ' . $units[$i];
}

function formatThreatScore($score) {
    if ($score >= 70) {
        return [
            'score' => $score,
            'level' => 'HIGH',
            'class' => 'danger',
            'color' => '#dc3545'
        ];
    } elseif ($score >= 40) {
        return [
            'score' => $score,
            'level' => 'MEDIUM',
            'class' => 'warning',
            'color' => '#ffc107'
        ];
    } else {
        return [
            'score' => $score,
            'level' => 'LOW',
            'class' => 'success',
            'color' => '#28a745'
        ];
    }
}

function formatDateTime($datetime) {
    return date('M d, Y H:i', strtotime($datetime));
}

function validateFileUpload($file) {
    $errors = [];
    
    // Check if file was uploaded
    if (!isset($file['tmp_name']) || !is_uploaded_file($file['tmp_name'])) {
        $errors[] = 'No file uploaded or upload failed';
        return $errors;
    }
    
    // Check file size
    if ($file['size'] > MAX_FILE_SIZE) {
        $errors[] = 'File size exceeds maximum limit of ' . formatFileSize(MAX_FILE_SIZE);
    }
    
    // Check file extension
    $fileExtension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    if (!in_array($fileExtension, ALLOWED_EXTENSIONS)) {
        $errors[] = 'File type not allowed. Allowed types: ' . implode(', ', ALLOWED_EXTENSIONS);
    }
    
    return $errors;
}

function logActivity($action, $details = '') {
    $logFile = LOGS_DIR . 'activity.log';
    $timestamp = date('Y-m-d H:i:s');
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    
    $logEntry = sprintf(
        "[%s] IP: %s | Action: %s | Details: %s | User-Agent: %s\n",
        $timestamp,
        $ip,
        $action,
        $details,
        $userAgent
    );
    
    error_log($logEntry, 3, $logFile);
}

// Initialize API client
$apiClient = new ApiClient();

// Set timezone
date_default_timezone_set('UTC');

// Create required directories
$directories = [UPLOAD_DIR, LOGS_DIR, REPORTS_DIR];
foreach ($directories as $dir) {
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
}
?>
