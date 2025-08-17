<?php
/**
 * API Endpoints for Frontend-Backend Communication
 * Handles AJAX requests and returns JSON responses
 */

// Include required classes
require_once '../config/database.php';
require_once '../classes/Database.php';
require_once '../classes/EmailManager.php';
require_once '../classes/ThreatManager.php';
require_once '../classes/AuthManager.php';

// Set content type to JSON
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Initialize classes
$database = new Database();
$emailManager = new EmailManager($database);
$threatManager = new ThreatManager($database);
$authManager = new AuthManager($database);

// Get endpoint and action
$endpoint = $_GET['endpoint'] ?? '';
$action = $_GET['action'] ?? '';
$method = $_SERVER['REQUEST_METHOD'];

try {
    // Route requests based on endpoint
    switch ($endpoint) {
        case 'dashboard':
            handleDashboardRequests($action, $method, $threatManager, $emailManager);
            break;
            
        case 'email':
            handleEmailRequests($action, $method, $emailManager);
            break;
            
        case 'threat':
            handleThreatRequests($action, $method, $threatManager);
            break;
            
        case 'setup':
            handleSetupRequests($action, $method, $database);
            break;
            
        case 'system':
            handleSystemRequests($action, $method, $database);
            break;
            
        default:
            throw new Exception('Invalid endpoint');
    }
    
} catch (Exception $e) {
    error_log("API Error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage()
    ]);
}

/**
 * Handle dashboard-related requests
 */
function handleDashboardRequests($action, $method, $threatManager, $emailManager) {
    switch ($action) {
        case 'statistics':
            if ($method === 'GET') {
                $days = $_GET['days'] ?? 30;
                $threatStats = $threatManager->getThreatStatistics($days);
                $emailStats = $emailManager->getEmailStatistics($days);
                $alerts = $threatManager->getActiveAlerts();
                
                echo json_encode([
                    'success' => true,
                    'data' => [
                        'threats' => $threatStats,
                        'emails' => $emailStats,
                        'alerts' => $alerts,
                        'generated_at' => date('Y-m-d H:i:s')
                    ]
                ]);
            }
            break;
            
        case 'alerts':
            if ($method === 'GET') {
                $alerts = $threatManager->getActiveAlerts();
                echo json_encode([
                    'success' => true,
                    'data' => $alerts
                ]);
            }
            break;
            
        case 'patterns':
            if ($method === 'GET') {
                $days = $_GET['days'] ?? 30;
                $patterns = $threatManager->getThreatPatterns($days);
                echo json_encode([
                    'success' => true,
                    'data' => $patterns
                ]);
            }
            break;
            
        default:
            throw new Exception('Invalid dashboard action');
    }
}

/**
 * Handle email-related requests
 */
function handleEmailRequests($action, $method, $emailManager) {
    switch ($action) {
        case 'upload':
            if ($method === 'POST') {
                if (!isset($_FILES['email_file'])) {
                    throw new Exception('No file uploaded');
                }
                
                $customRules = json_decode($_POST['custom_rules'] ?? '[]', true);
                $result = $emailManager->uploadAndAnalyzeEmail($_FILES['email_file'], $customRules);
                
                echo json_encode($result);
            }
            break;
            
        case 'history':
            if ($method === 'GET') {
                $filters = [
                    'risk_level' => $_GET['risk_level'] ?? '',
                    'date_from' => $_GET['date_from'] ?? '',
                    'date_to' => $_GET['date_to'] ?? '',
                    'sender' => $_GET['sender'] ?? '',
                    'subject' => $_GET['subject'] ?? ''
                ];
                
                $limit = min(100, max(1, (int)($_GET['limit'] ?? 50)));
                $offset = max(0, (int)($_GET['offset'] ?? 0));
                
                $history = $emailManager->getEmailHistory($filters, $limit, $offset);
                
                echo json_encode([
                    'success' => true,
                    'data' => $history,
                    'pagination' => [
                        'limit' => $limit,
                        'offset' => $offset,
                        'has_more' => count($history) === $limit
                    ]
                ]);
            }
            break;
            
        case 'details':
            if ($method === 'GET') {
                $emailId = $_GET['email_id'] ?? '';
                if (!$emailId) {
                    throw new Exception('Email ID required');
                }
                
                $details = $emailManager->getEmailAnalysis($emailId);
                
                if (!$details) {
                    http_response_code(404);
                    echo json_encode([
                        'success' => false,
                        'error' => 'Email not found'
                    ]);
                    return;
                }
                
                echo json_encode([
                    'success' => true,
                    'data' => $details
                ]);
            }
            break;
            
        case 'quarantine':
            if ($method === 'POST') {
                $data = json_decode(file_get_contents('php://input'), true);
                $emailId = $data['email_id'] ?? '';
                $reason = $data['reason'] ?? 'Manual quarantine';
                $userId = $_SESSION['user_id'] ?? 'unknown';
                
                if (!$emailId) {
                    throw new Exception('Email ID required');
                }
                
                $result = $emailManager->quarantineEmail($emailId, $reason, $userId);
                echo json_encode($result);
            } elseif ($method === 'DELETE') {
                $data = json_decode(file_get_contents('php://input'), true);
                $emailId = $data['email_id'] ?? '';
                $userId = $_SESSION['user_id'] ?? 'unknown';
                
                if (!$emailId) {
                    throw new Exception('Email ID required');
                }
                
                $result = $emailManager->releaseFromQuarantine($emailId, $userId);
                echo json_encode($result);
            }
            break;
            
        case 'export':
            if ($method === 'POST') {
                $data = json_decode(file_get_contents('php://input'), true);
                $filters = $data['filters'] ?? [];
                $format = $data['format'] ?? 'json';
                
                $result = $emailManager->exportEmailData($filters, $format);
                echo json_encode($result);
            }
            break;
            
        default:
            throw new Exception('Invalid email action');
    }
}

/**
 * Handle threat-related requests
 */
function handleThreatRequests($action, $method, $threatManager) {
    switch ($action) {
        case 'history':
            if ($method === 'GET') {
                $filters = [
                    'severity' => $_GET['severity'] ?? '',
                    'category' => $_GET['category'] ?? '',
                    'threat_type' => $_GET['threat_type'] ?? '',
                    'date_from' => $_GET['date_from'] ?? '',
                    'date_to' => $_GET['date_to'] ?? '',
                    'email_sender' => $_GET['email_sender'] ?? ''
                ];
                
                // Remove empty filters
                $filters = array_filter($filters, function($value) {
                    return $value !== '';
                });
                
                $limit = min(100, max(1, (int)($_GET['limit'] ?? 50)));
                $offset = max(0, (int)($_GET['offset'] ?? 0));
                
                $history = $threatManager->getThreatHistory($filters, $limit, $offset);
                
                echo json_encode([
                    'success' => true,
                    'data' => $history,
                    'pagination' => [
                        'limit' => $limit,
                        'offset' => $offset,
                        'has_more' => count($history) === $limit
                    ]
                ]);
            }
            break;
            
        case 'details':
            if ($method === 'GET') {
                $emailId = $_GET['email_id'] ?? '';
                if (!$emailId) {
                    throw new Exception('Email ID required');
                }
                
                $details = $threatManager->getThreatDetails($emailId);
                
                echo json_encode([
                    'success' => true,
                    'data' => $details
                ]);
            }
            break;
            
        case 'scan':
            if ($method === 'POST') {
                $data = json_decode(file_get_contents('php://input'), true);
                $content = $data['content'] ?? '';
                $contentType = $data['content_type'] ?? 'text';
                $customRules = $data['custom_rules'] ?? [];
                
                if (!$content) {
                    throw new Exception('Content required');
                }
                
                $result = $threatManager->scanContent($content, $contentType, $customRules);
                echo json_encode($result);
            }
            break;
            
        case 'intelligence':
            if ($method === 'GET') {
                $intelligence = $threatManager->getThreatIntelligence();
                echo json_encode([
                    'success' => true,
                    'data' => $intelligence
                ]);
            }
            break;
            
        case 'quarantine':
            if ($method === 'GET') {
                $quarantineData = $threatManager->getQuarantineData();
                echo json_encode([
                    'success' => true,
                    'data' => $quarantineData
                ]);
            }
            break;
            
        case 'export':
            if ($method === 'POST') {
                $data = json_decode(file_get_contents('php://input'), true);
                $filters = $data['filters'] ?? [];
                $format = $data['format'] ?? 'json';
                
                $result = $threatManager->exportThreatData($filters, $format);
                echo json_encode($result);
            }
            break;
            
        case 'report':
            if ($method === 'POST') {
                $data = json_decode(file_get_contents('php://input'), true);
                $startDate = $data['start_date'] ?? date('Y-m-d', strtotime('-30 days'));
                $endDate = $data['end_date'] ?? date('Y-m-d');
                
                $report = $threatManager->generateThreatReport($startDate, $endDate);
                
                if ($report) {
                    echo json_encode([
                        'success' => true,
                        'data' => $report
                    ]);
                } else {
                    throw new Exception('Failed to generate report');
                }
            }
            break;
            
        default:
            throw new Exception('Invalid threat action');
    }
}

/**
 * Handle setup-related requests
 */
function handleSetupRequests($action, $method, $database) {
    switch ($action) {
        case 'rules':
            if ($method === 'GET') {
                $sql = "SELECT * FROM setup_rules WHERE is_active = 1 ORDER BY severity DESC, created_at DESC";
                $rules = $database->fetchAll($sql);
                
                echo json_encode([
                    'success' => true,
                    'data' => $rules
                ]);
            } elseif ($method === 'POST') {
                $data = json_decode(file_get_contents('php://input'), true);
                
                $requiredFields = ['rule_name', 'phrase', 'severity'];
                foreach ($requiredFields as $field) {
                    if (empty($data[$field])) {
                        throw new Exception("Missing required field: $field");
                    }
                }
                
                $sql = "INSERT INTO setup_rules (rule_name, start_segment, end_segment, phrase, rule_type, severity, is_active, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, NOW())";
                
                $database->execute($sql, [
                    $data['rule_name'],
                    $data['start_segment'] ?? '<body',
                    $data['end_segment'] ?? '</body>',
                    $data['phrase'],
                    $data['rule_type'] ?? 'single_line',
                    $data['severity'],
                    $data['is_active'] ?? true
                ]);
                
                echo json_encode([
                    'success' => true,
                    'message' => 'Rule created successfully',
                    'rule_id' => $database->lastInsertId()
                ]);
            } elseif ($method === 'PUT') {
                $data = json_decode(file_get_contents('php://input'), true);
                $ruleId = $data['id'] ?? '';
                
                if (!$ruleId) {
                    throw new Exception('Rule ID required');
                }
                
                $updateFields = [];
                $params = [];
                
                $allowedFields = ['rule_name', 'start_segment', 'end_segment', 'phrase', 'rule_type', 'severity', 'is_active'];
                
                foreach ($allowedFields as $field) {
                    if (array_key_exists($field, $data)) {
                        $updateFields[] = "$field = ?";
                        $params[] = $data[$field];
                    }
                }
                
                if (empty($updateFields)) {
                    throw new Exception('No fields to update');
                }
                
                $updateFields[] = "updated_at = NOW()";
                $params[] = $ruleId;
                
                $sql = "UPDATE setup_rules SET " . implode(', ', $updateFields) . " WHERE id = ?";
                $database->execute($sql, $params);
                
                echo json_encode([
                    'success' => true,
                    'message' => 'Rule updated successfully'
                ]);
            } elseif ($method === 'DELETE') {
                $ruleId = $_GET['id'] ?? '';
                
                if (!$ruleId) {
                    throw new Exception('Rule ID required');
                }
                
                $sql = "UPDATE setup_rules SET is_active = 0, updated_at = NOW() WHERE id = ?";
                $database->execute($sql, [$ruleId]);
                
                echo json_encode([
                    'success' => true,
                    'message' => 'Rule deactivated successfully'
                ]);
            }
            break;
            
        case 'upload_rules':
            if ($method === 'POST') {
                if (!isset($_FILES['rules_file'])) {
                    throw new Exception('No file uploaded');
                }
                
                // This would integrate with the Python API to process the setup file
                // For now, return a placeholder response
                echo json_encode([
                    'success' => true,
                    'message' => 'Rules file uploaded successfully'
                ]);
            }
            break;
            
        default:
            throw new Exception('Invalid setup action');
    }
}

/**
 * Handle system-related requests
 */
function handleSystemRequests($action, $method, $database) {
    switch ($action) {
        case 'health':
            if ($method === 'GET') {
                $health = $database->healthCheck();
                $stats = $database->getDatabaseStats();
                
                echo json_encode([
                    'success' => true,
                    'data' => [
                        'database' => $health,
                        'statistics' => $stats,
                        'timestamp' => date('Y-m-d H:i:s')
                    ]
                ]);
            }
            break;
            
        case 'cleanup':
            if ($method === 'POST') {
                $data = json_decode(file_get_contents('php://input'), true);
                $days = $data['retention_days'] ?? 90;
                
                $success = $database->cleanup($days);
                
                echo json_encode([
                    'success' => $success,
                    'message' => $success ? 'Cleanup completed successfully' : 'Cleanup failed'
                ]);
            }
            break;
            
        case 'optimize':
            if ($method === 'POST') {
                $success = $database->optimizeTables();
                
                echo json_encode([
                    'success' => $success,
                    'message' => $success ? 'Database optimized successfully' : 'Optimization failed'
                ]);
            }
            break;
            
        default:
            throw new Exception('Invalid system action');
    }
}

/**
 * Validate request authentication
 */
function validateAuth() {
    session_start();
    if (!isset($_SESSION['user_authenticated'])) {
        http_response_code(401);
        echo json_encode([
            'success' => false,
            'error' => 'Authentication required'
        ]);
        exit();
    }
}

/**
 * Log API request
 */
function logApiRequest($endpoint, $action, $method) {
    error_log("API Request: $method $endpoint/$action - User: " . ($_SESSION['user_id'] ?? 'anonymous') . " - IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
}
