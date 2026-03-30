<?php
/**
 * PHP API Interface for the Phishing Detection Platform
 * Handles communication with Python backend API
 */

require_once 'config.php';

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: ' . ($_ENV['ALLOWED_ORIGIN'] ?? 'http://localhost:3000'));
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

class PhishingApiHandler {
    private $apiClient;
    
    public function __construct() {
        $this->apiClient = new ApiClient();
    }
    
    /**
     * Handle API requests
     */
    public function handleRequest() {
        try {
            $action = $_GET['action'] ?? '';
            
            switch ($action) {
                case 'dashboard-stats':
                    return $this->getDashboardStats();
                
                case 'upload-email':
                    return $this->uploadEmail();
                
                case 'analyze-email':
                    return $this->analyzeEmail();
                
                case 'bulk-analyze':
                    return $this->bulkAnalyze();
                
                case 'analysis-history':
                    return $this->getAnalysisHistory();
                
                case 'search':
                    return $this->searchAnalyses();
                
                case 'export-report':
                    return $this->exportReport();
                
                case 'quarantine':
                    return $this->quarantineEmail();
                
                case 'threat-patterns':
                    return $this->getThreatPatterns();
                
                case 'add-pattern':
                    return $this->addThreatPattern();
                
                case 'upload-setup':
                    return $this->uploadSetupFile();
                
                default:
                    throw new Exception('Invalid action');
            }
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage());
        }
    }
    
    private function getDashboardStats() {
        $response = $this->apiClient->get('/dashboard-stats');
        
        if (!$response['success']) {
            throw new Exception('Failed to fetch dashboard statistics');
        }
        
        return $this->successResponse($response['data']);
    }
    
    private function uploadEmail() {
        if (!isset($_FILES['email_file'])) {
            throw new Exception('No file uploaded');
        }
        
        $file = $_FILES['email_file'];
        $errors = validateFileUpload($file);
        
        if (!empty($errors)) {
            throw new Exception(implode(', ', $errors));
        }
        
        // Move uploaded file to temporary location
        $tempPath = UPLOAD_DIR . uniqid() . '_' . basename($file['name']);
        if (!move_uploaded_file($file['tmp_name'], $tempPath)) {
            throw new Exception('Failed to save uploaded file');
        }
        
        try {
            $response = $this->apiClient->postFile('/analyze-email', ['file' => $tempPath]);
            
            // Clean up temporary file
            if (file_exists($tempPath)) {
                unlink($tempPath);
            }
            
            if (!$response['success']) {
                throw new Exception('Email analysis failed: ' . ($response['data']['error'] ?? 'Unknown error'));
            }
            
            // Log activity
            logActivity('EMAIL_UPLOAD', 'File: ' . $file['name']);
            
            return $this->successResponse($response['data']);
            
        } catch (Exception $e) {
            // Clean up on error
            if (file_exists($tempPath)) {
                unlink($tempPath);
            }
            throw $e;
        }
    }
    
    private function analyzeEmail() {
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (empty($input['email_content'])) {
            throw new Exception('Email content required');
        }
        
        $response = $this->apiClient->post('/analyze-email', $input);
        
        if (!$response['success']) {
            throw new Exception('Email analysis failed: ' . ($response['data']['error'] ?? 'Unknown error'));
        }
        
        logActivity('EMAIL_ANALYSIS', 'Content analysis performed');
        
        return $this->successResponse($response['data']);
    }
    
    private function bulkAnalyze() {
        if (!isset($_FILES['files'])) {
            throw new Exception('No files uploaded');
        }
        
        $files = $_FILES['files'];
        $tempPaths = [];
        
        try {
            // Process multiple files
            if (is_array($files['name'])) {
                for ($i = 0; $i < count($files['name']); $i++) {
                    if ($files['error'][$i] === UPLOAD_ERR_OK) {
                        $tempPath = UPLOAD_DIR . uniqid() . '_' . basename($files['name'][$i]);
                        if (move_uploaded_file($files['tmp_name'][$i], $tempPath)) {
                            $tempPaths[] = $tempPath;
                        }
                    }
                }
            } else {
                // Single file
                $tempPath = UPLOAD_DIR . uniqid() . '_' . basename($files['name']);
                if (move_uploaded_file($files['tmp_name'], $tempPath)) {
                    $tempPaths[] = $tempPath;
                }
            }
            
            if (empty($tempPaths)) {
                throw new Exception('No valid files to process');
            }
            
            $response = $this->apiClient->postFile('/bulk-analyze', ['files' => $tempPaths]);
            
            // Clean up temporary files
            foreach ($tempPaths as $path) {
                if (file_exists($path)) {
                    unlink($path);
                }
            }
            
            if (!$response['success']) {
                throw new Exception('Bulk analysis failed: ' . ($response['data']['error'] ?? 'Unknown error'));
            }
            
            logActivity('BULK_ANALYSIS', 'Processed ' . count($tempPaths) . ' files');
            
            return $this->successResponse($response['data']);
            
        } catch (Exception $e) {
            // Clean up on error
            foreach ($tempPaths as $path) {
                if (file_exists($path)) {
                    unlink($path);
                }
            }
            throw $e;
        }
    }
    
    private function getAnalysisHistory() {
        $params = [
            'page' => $_GET['page'] ?? 1,
            'per_page' => $_GET['per_page'] ?? ITEMS_PER_PAGE,
            'risk_level' => $_GET['risk_level'] ?? null
        ];
        
        $response = $this->apiClient->get('/analysis-history', array_filter($params));
        
        if (!$response['success']) {
            throw new Exception('Failed to fetch analysis history');
        }
        
        return $this->successResponse($response['data']);
    }
    
    private function searchAnalyses() {
        $params = [
            'q' => $_GET['q'] ?? '',
            'type' => $_GET['type'] ?? 'all',
            'page' => $_GET['page'] ?? 1,
            'per_page' => $_GET['per_page'] ?? ITEMS_PER_PAGE
        ];
        
        if (empty($params['q'])) {
            throw new Exception('Search query required');
        }
        
        $response = $this->apiClient->get('/search', $params);
        
        if (!$response['success']) {
            throw new Exception('Search failed: ' . ($response['data']['error'] ?? 'Unknown error'));
        }
        
        logActivity('SEARCH', 'Query: ' . $params['q']);
        
        return $this->successResponse($response['data']);
    }
    
    private function exportReport() {
        $input = json_decode(file_get_contents('php://input'), true);
        
        $data = [
            'format' => $input['format'] ?? 'pdf',
            'date_from' => $input['date_from'] ?? null,
            'date_to' => $input['date_to'] ?? null,
            'risk_levels' => $input['risk_levels'] ?? []
        ];
        
        $response = $this->apiClient->post('/export-report', $data);
        
        if (!$response['success']) {
            throw new Exception('Report export failed: ' . ($response['data']['error'] ?? 'Unknown error'));
        }
        
        logActivity('REPORT_EXPORT', 'Format: ' . $data['format']);
        
        return $this->successResponse($response['data']);
    }
    
    private function quarantineEmail() {
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (empty($input['analysis_id'])) {
            throw new Exception('Analysis ID required');
        }
        
        $data = [
            'analysis_id' => $input['analysis_id'],
            'reason' => $input['reason'] ?? 'Quarantined via web interface'
        ];
        
        $response = $this->apiClient->post('/quarantine', $data);
        
        if (!$response['success']) {
            throw new Exception('Quarantine failed: ' . ($response['data']['error'] ?? 'Unknown error'));
        }
        
        logActivity('EMAIL_QUARANTINE', 'Analysis ID: ' . $data['analysis_id']);
        
        return $this->successResponse($response['data']);
    }
    
    private function getThreatPatterns() {
        $response = $this->apiClient->get('/threat-patterns');
        
        if (!$response['success']) {
            throw new Exception('Failed to fetch threat patterns');
        }
        
        return $this->successResponse($response['data']);
    }
    
    private function addThreatPattern() {
        $input = json_decode(file_get_contents('php://input'), true);
        
        $requiredFields = ['segment_start', 'segment_end', 'pattern'];
        foreach ($requiredFields as $field) {
            if (empty($input[$field])) {
                throw new Exception("Field '$field' is required");
            }
        }
        
        $response = $this->apiClient->post('/threat-patterns', $input);
        
        if (!$response['success']) {
            throw new Exception('Failed to add threat pattern: ' . ($response['data']['error'] ?? 'Unknown error'));
        }
        
        logActivity('PATTERN_ADD', 'Pattern: ' . $input['pattern']);
        
        return $this->successResponse($response['data']);
    }
    
    private function uploadSetupFile() {
        if (!isset($_FILES['setup_file'])) {
            throw new Exception('No setup file uploaded');
        }
        
        $file = $_FILES['setup_file'];
        $errors = validateFileUpload($file);
        
        if (!empty($errors)) {
            throw new Exception(implode(', ', $errors));
        }
        
        $tempPath = UPLOAD_DIR . uniqid() . '_' . basename($file['name']);
        if (!move_uploaded_file($file['tmp_name'], $tempPath)) {
            throw new Exception('Failed to save uploaded file');
        }
        
        try {
            $response = $this->apiClient->postFile('/upload-setup', ['file' => $tempPath]);
            
            if (file_exists($tempPath)) {
                unlink($tempPath);
            }
            
            if (!$response['success']) {
                throw new Exception('Setup file processing failed: ' . ($response['data']['error'] ?? 'Unknown error'));
            }
            
            logActivity('SETUP_UPLOAD', 'File: ' . $file['name']);
            
            return $this->successResponse($response['data']);
            
        } catch (Exception $e) {
            if (file_exists($tempPath)) {
                unlink($tempPath);
            }
            throw $e;
        }
    }
    
    private function successResponse($data) {
        return [
            'success' => true,
            'data' => $data,
            'timestamp' => date('c')
        ];
    }
    
    private function errorResponse($message, $code = 400) {
        http_response_code($code);
        return [
            'success' => false,
            'error' => $message,
            'timestamp' => date('c')
        ];
    }
}

// Handle the request
try {
    $handler = new PhishingApiHandler();
    $result = $handler->handleRequest();
    echo json_encode($result);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage(),
        'timestamp' => date('c')
    ]);
}
?>
