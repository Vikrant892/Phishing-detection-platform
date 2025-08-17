<?php
/**
 * Email Processor Class
 * Handles email file processing and communication with Python backend
 */

class EmailProcessor {
    private $db;
    private $apiBaseUrl;
    private $uploadDir;
    private $allowedTypes;
    private $maxFileSize;
    
    public function __construct($db) {
        $this->db = $db;
        $this->apiBaseUrl = 'http://localhost:8000/api/v1';
        $this->uploadDir = __DIR__ . '/../../uploads/';
        $this->allowedTypes = ['.eml', '.msg', '.txt', '.mbox', '.zip'];
        $this->maxFileSize = 100 * 1024 * 1024; // 100MB
        
        // Create upload directory if it doesn't exist
        if (!is_dir($this->uploadDir)) {
            mkdir($this->uploadDir, 0755, true);
        }
    }
    
    /**
     * Process uploaded email file
     */
    public function processUploadedFile($fileData) {
        try {
            // Validate file upload
            $validation = $this->validateUpload($fileData);
            if (!$validation['success']) {
                return $validation;
            }
            
            // Save file temporarily
            $savedFile = $this->saveUploadedFile($fileData);
            if (!$savedFile['success']) {
                return $savedFile;
            }
            
            $filePath = $savedFile['file_path'];
            
            // Send to Python backend for analysis
            $analysisResult = $this->analyzeWithBackend($filePath, $fileData['name']);
            
            // Clean up temporary file
            if (file_exists($filePath)) {
                unlink($filePath);
            }
            
            if ($analysisResult['success']) {
                // Store result in local database
                $this->storeAnalysisResult($analysisResult['data']);
                
                return [
                    'success' => true,
                    'message' => 'Email analysis completed successfully',
                    'data' => $analysisResult['data']
                ];
            } else {
                return $analysisResult;
            }
            
        } catch (Exception $e) {
            error_log("Email processing error: " . $e->getMessage());
            return [
                'success' => false,
                'message' => 'Email processing failed',
                'error' => $e->getMessage()
            ];
        }
    }
    
    /**
     * Process batch of files
     */
    public function processBatchFiles($files) {
        $results = [];
        $successCount = 0;
        $failCount = 0;
        
        foreach ($files as $file) {
            $result = $this->processUploadedFile($file);
            $results[] = [
                'filename' => $file['name'],
                'result' => $result
            ];
            
            if ($result['success']) {
                $successCount++;
            } else {
                $failCount++;
            }
        }
        
        return [
            'success' => $successCount > 0,
            'message' => "Processed {$successCount} files successfully, {$failCount} failed",
            'data' => [
                'total_files' => count($files),
                'successful' => $successCount,
                'failed' => $failCount,
                'results' => $results
            ]
        ];
    }
    
    /**
     * Get processing history
     */
    public function getProcessingHistory($limit = 50) {
        try {
            $analyses = $this->db->getRecentAnalyses($limit);
            
            // Add processing metadata
            foreach ($analyses as &$analysis) {
                if ($analysis['analysis_data']) {
                    $metadata = $analysis['analysis_data']['processing_metadata'] ?? [];
                    $analysis['processing_time'] = $metadata['processing_time'] ?? 0;
                    $analysis['file_size'] = $metadata['file_size'] ?? 0;
                    $analysis['original_filename'] = $metadata['original_filename'] ?? 'Unknown';
                }
            }
            
            return [
                'success' => true,
                'data' => $analyses
            ];
            
        } catch (Exception $e) {
            error_log("Failed to get processing history: " . $e->getMessage());
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }
    
    /**
     * Analyze email content directly
     */
    public function analyzeEmailContent($content, $contentType = 'eml') {
        try {
            $apiUrl = $this->apiBaseUrl . '/analyze/content';
            
            $postData = [
                'content' => $content,
                'content_type' => $contentType
            ];
            
            $response = $this->makeApiRequest($apiUrl, 'POST', $postData);
            
            if ($response['success']) {
                // Store result in local database
                $this->storeAnalysisResult($response['data']);
            }
            
            return $response;
            
        } catch (Exception $e) {
            error_log("Content analysis error: " . $e->getMessage());
            return [
                'success' => false,
                'message' => 'Content analysis failed',
                'error' => $e->getMessage()
            ];
        }
    }
    
    /**
     * Get supported file types
     */
    public function getSupportedTypes() {
        return $this->allowedTypes;
    }
    
    /**
     * Get file size limit
     */
    public function getMaxFileSize() {
        return $this->maxFileSize;
    }
    
    /**
     * Validate file upload
     */
    private function validateUpload($fileData) {
        // Check for upload errors
        if ($fileData['error'] !== UPLOAD_ERR_OK) {
            $errorMessages = [
                UPLOAD_ERR_INI_SIZE => 'File exceeds upload_max_filesize',
                UPLOAD_ERR_FORM_SIZE => 'File exceeds MAX_FILE_SIZE',
                UPLOAD_ERR_PARTIAL => 'File was only partially uploaded',
                UPLOAD_ERR_NO_FILE => 'No file was uploaded',
                UPLOAD_ERR_NO_TMP_DIR => 'Missing temporary folder',
                UPLOAD_ERR_CANT_WRITE => 'Failed to write file to disk',
                UPLOAD_ERR_EXTENSION => 'Upload stopped by extension'
            ];
            
            return [
                'success' => false,
                'message' => 'Upload failed',
                'error' => $errorMessages[$fileData['error']] ?? 'Unknown upload error'
            ];
        }
        
        // Check file size
        if ($fileData['size'] > $this->maxFileSize) {
            return [
                'success' => false,
                'message' => 'File too large',
                'error' => 'File size exceeds ' . $this->formatFileSize($this->maxFileSize)
            ];
        }
        
        // Check file type
        $fileExt = strtolower(pathinfo($fileData['name'], PATHINFO_EXTENSION));
        if (!in_array('.' . $fileExt, $this->allowedTypes)) {
            return [
                'success' => false,
                'message' => 'Unsupported file type',
                'error' => 'Allowed types: ' . implode(', ', $this->allowedTypes)
            ];
        }
        
        // Basic file content validation
        if ($fileData['size'] == 0) {
            return [
                'success' => false,
                'message' => 'Empty file',
                'error' => 'File appears to be empty'
            ];
        }
        
        return ['success' => true];
    }
    
    /**
     * Save uploaded file temporarily
     */
    private function saveUploadedFile($fileData) {
        try {
            $filename = $this->sanitizeFilename($fileData['name']);
            $timestamp = date('Y-m-d_H-i-s');
            $finalFilename = $timestamp . '_' . $filename;
            $filePath = $this->uploadDir . $finalFilename;
            
            if (!move_uploaded_file($fileData['tmp_name'], $filePath)) {
                return [
                    'success' => false,
                    'message' => 'Failed to save file',
                    'error' => 'Could not move uploaded file'
                ];
            }
            
            return [
                'success' => true,
                'file_path' => $filePath,
                'filename' => $finalFilename,
                'original_name' => $fileData['name']
            ];
            
        } catch (Exception $e) {
            return [
                'success' => false,
                'message' => 'File save failed',
                'error' => $e->getMessage()
            ];
        }
    }
    
    /**
     * Analyze file with Python backend
     */
    private function analyzeWithBackend($filePath, $originalFilename) {
        try {
            $apiUrl = $this->apiBaseUrl . '/analyze/upload';
            
            // Prepare file for upload
            $fileContent = file_get_contents($filePath);
            $boundary = uniqid();
            
            $postData = "--$boundary\r\n";
            $postData .= "Content-Disposition: form-data; name=\"file\"; filename=\"$originalFilename\"\r\n";
            $postData .= "Content-Type: application/octet-stream\r\n\r\n";
            $postData .= $fileContent . "\r\n";
            $postData .= "--$boundary--\r\n";
            
            $context = stream_context_create([
                'http' => [
                    'method' => 'POST',
                    'header' => [
                        "Content-Type: multipart/form-data; boundary=$boundary",
                        "Content-Length: " . strlen($postData)
                    ],
                    'content' => $postData,
                    'timeout' => 300 // 5 minutes
                ]
            ]);
            
            $response = file_get_contents($apiUrl, false, $context);
            
            if ($response === false) {
                return [
                    'success' => false,
                    'message' => 'Backend communication failed',
                    'error' => 'Could not connect to analysis backend'
                ];
            }
            
            $result = json_decode($response, true);
            
            if (json_last_error() !== JSON_ERROR_NONE) {
                return [
                    'success' => false,
                    'message' => 'Invalid response from backend',
                    'error' => 'Response parsing failed'
                ];
            }
            
            return $result;
            
        } catch (Exception $e) {
            error_log("Backend analysis error: " . $e->getMessage());
            return [
                'success' => false,
                'message' => 'Backend analysis failed',
                'error' => $e->getMessage()
            ];
        }
    }
    
    /**
     * Make API request to Python backend
     */
    private function makeApiRequest($url, $method = 'GET', $data = null) {
        try {
            $options = [
                'http' => [
                    'method' => $method,
                    'header' => [
                        'Content-Type: application/json',
                        'Accept: application/json'
                    ],
                    'timeout' => 120
                ]
            ];
            
            if ($data && in_array($method, ['POST', 'PUT', 'PATCH'])) {
                $jsonData = json_encode($data);
                $options['http']['content'] = $jsonData;
                $options['http']['header'][] = 'Content-Length: ' . strlen($jsonData);
            }
            
            $context = stream_context_create($options);
            $response = file_get_contents($url, false, $context);
            
            if ($response === false) {
                return [
                    'success' => false,
                    'message' => 'API request failed',
                    'error' => 'Could not connect to backend'
                ];
            }
            
            $result = json_decode($response, true);
            
            if (json_last_error() !== JSON_ERROR_NONE) {
                return [
                    'success' => false,
                    'message' => 'Invalid API response',
                    'error' => 'Response parsing failed'
                ];
            }
            
            return $result;
            
        } catch (Exception $e) {
            error_log("API request error: " . $e->getMessage());
            return [
                'success' => false,
                'message' => 'API request failed',
                'error' => $e->getMessage()
            ];
        }
    }
    
    /**
     * Store analysis result in local database
     */
    private function storeAnalysisResult($analysisData) {
        try {
            return $this->db->storeEmailAnalysis($analysisData);
        } catch (Exception $e) {
            error_log("Failed to store analysis result: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Sanitize filename
     */
    private function sanitizeFilename($filename) {
        // Remove path components
        $filename = basename($filename);
        
        // Replace dangerous characters
        $filename = preg_replace('/[^\w\-_\.]/', '_', $filename);
        
        // Remove multiple underscores
        $filename = preg_replace('/_+/', '_', $filename);
        
        // Ensure filename is not empty
        if (empty($filename) || $filename === '_') {
            $filename = 'file_' . uniqid();
        }
        
        // Limit filename length
        if (strlen($filename) > 255) {
            $ext = pathinfo($filename, PATHINFO_EXTENSION);
            $name = pathinfo($filename, PATHINFO_FILENAME);
            $filename = substr($name, 0, 250 - strlen($ext)) . '.' . $ext;
        }
        
        return $filename;
    }
    
    /**
     * Format file size
     */
    private function formatFileSize($bytes) {
        $units = ['B', 'KB', 'MB', 'GB'];
        $i = 0;
        
        while ($bytes >= 1024 && $i < count($units) - 1) {
            $bytes /= 1024;
            $i++;
        }
        
        return round($bytes, 2) . ' ' . $units[$i];
    }
    
    /**
     * Check backend health
     */
    public function checkBackendHealth() {
        try {
            $healthUrl = 'http://localhost:8000/health';
            $response = $this->makeApiRequest($healthUrl);
            
            return [
                'success' => $response['success'] ?? false,
                'status' => $response['success'] ? 'online' : 'offline',
                'data' => $response['data'] ?? null
            ];
            
        } catch (Exception $e) {
            return [
                'success' => false,
                'status' => 'offline',
                'error' => $e->getMessage()
            ];
        }
    }
}
?>
