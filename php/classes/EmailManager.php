<?php

/**
 * Email Management Class
 * Handles email-related operations and analysis management
 */
class EmailManager
{
    private $database;
    private $pythonApiUrl;
    
    public function __construct(Database $database)
    {
        $this->database = $database;
        $this->pythonApiUrl = 'http://localhost:8000/api';
    }
    
    /**
     * Upload and analyze email file
     */
    public function uploadAndAnalyzeEmail($file, $customRules = [])
    {
        try {
            // Validate file
            $validation = $this->validateEmailFile($file);
            if (!$validation['valid']) {
                return [
                    'success' => false,
                    'error' => $validation['error']
                ];
            }
            
            // Upload to Python API
            $uploadResult = $this->uploadToPythonApi($file);
            if (!$uploadResult['success']) {
                return $uploadResult;
            }
            
            // Analyze email
            $analysisResult = $this->analyzeEmailViaPython($uploadResult['filepath'], $customRules);
            
            return $analysisResult;
            
        } catch (Exception $e) {
            error_log("Email upload/analysis error: " . $e->getMessage());
            return [
                'success' => false,
                'error' => 'Failed to process email: ' . $e->getMessage()
            ];
        }
    }
    
    /**
     * Validate email file
     */
    private function validateEmailFile($file)
    {
        $allowedExtensions = ['eml', 'msg', 'txt'];
        $maxFileSize = 10 * 1024 * 1024; // 10MB
        
        // Check file upload errors
        if ($file['error'] !== UPLOAD_ERR_OK) {
            return [
                'valid' => false,
                'error' => 'File upload error: ' . $this->getUploadErrorMessage($file['error'])
            ];
        }
        
        // Check file size
        if ($file['size'] > $maxFileSize) {
            return [
                'valid' => false,
                'error' => 'File size exceeds limit (10MB maximum)'
            ];
        }
        
        // Check file extension
        $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        if (!in_array($extension, $allowedExtensions)) {
            return [
                'valid' => false,
                'error' => 'Invalid file type. Allowed: ' . implode(', ', $allowedExtensions)
            ];
        }
        
        // Check MIME type
        $allowedMimes = [
            'text/plain',
            'message/rfc822',
            'application/octet-stream'
        ];
        
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mimeType = finfo_file($finfo, $file['tmp_name']);
        finfo_close($finfo);
        
        if (!in_array($mimeType, $allowedMimes)) {
            return [
                'valid' => false,
                'error' => 'Invalid MIME type: ' . $mimeType
            ];
        }
        
        return ['valid' => true];
    }
    
    /**
     * Upload file to Python API
     */
    private function uploadToPythonApi($file)
    {
        try {
            $curl = curl_init();
            
            $cFile = new CURLFile($file['tmp_name'], $file['type'], $file['name']);
            $postData = ['file' => $cFile];
            
            curl_setopt_array($curl, [
                CURLOPT_URL => $this->pythonApiUrl . '/email/upload',
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $postData,
                CURLOPT_TIMEOUT => 30,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_HTTPHEADER => [
                    'Accept: application/json'
                ]
            ]);
            
            $response = curl_exec($curl);
            $httpCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
            $error = curl_error($curl);
            curl_close($curl);
            
            if ($error) {
                throw new Exception("CURL error: $error");
            }
            
            if ($httpCode !== 200) {
                throw new Exception("HTTP error: $httpCode");
            }
            
            $data = json_decode($response, true);
            
            if (!$data || $data['status'] !== 'success') {
                throw new Exception("API error: " . ($data['error'] ?? 'Unknown error'));
            }
            
            return [
                'success' => true,
                'filepath' => $data['data']['filepath'] ?? '',
                'filename' => $data['data']['filename'] ?? '',
                'email_id' => $data['data']['email_id'] ?? ''
            ];
            
        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => 'Upload failed: ' . $e->getMessage()
            ];
        }
    }
    
    /**
     * Analyze email via Python API
     */
    private function analyzeEmailViaPython($filepath, $customRules = [])
    {
        try {
            $postData = [
                'filepath' => $filepath,
                'setup_rules' => $customRules,
                'use_database_rules' => true
            ];
            
            $curl = curl_init();
            
            curl_setopt_array($curl, [
                CURLOPT_URL => $this->pythonApiUrl . '/email/analyze',
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => json_encode($postData),
                CURLOPT_TIMEOUT => 60,
                CURLOPT_HTTPHEADER => [
                    'Content-Type: application/json',
                    'Accept: application/json'
                ]
            ]);
            
            $response = curl_exec($curl);
            $httpCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
            $error = curl_error($curl);
            curl_close($curl);
            
            if ($error) {
                throw new Exception("CURL error: $error");
            }
            
            if ($httpCode !== 200) {
                throw new Exception("HTTP error: $httpCode");
            }
            
            $data = json_decode($response, true);
            
            if (!$data || $data['status'] !== 'success') {
                throw new Exception("Analysis failed: " . ($data['error'] ?? 'Unknown error'));
            }
            
            return [
                'success' => true,
                'analysis' => $data['data']
            ];
            
        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => 'Analysis failed: ' . $e->getMessage()
            ];
        }
    }
    
    /**
     * Get email analysis from database
     */
    public function getEmailAnalysis($emailId)
    {
        try {
            $sql = "SELECT * FROM email_analysis WHERE email_id = ?";
            $email = $this->database->fetchRow($sql, [$emailId]);
            
            if (!$email) {
                return null;
            }
            
            // Get associated threats
            $sql = "SELECT * FROM detected_threats WHERE email_id = ? ORDER BY severity DESC, detected_at DESC";
            $threats = $this->database->fetchAll($sql, [$emailId]);
            
            // Parse JSON fields
            $email['headers'] = json_decode($email['headers'] ?? '{}', true);
            $email['body_content'] = json_decode($email['body_content'] ?? '{}', true);
            $email['attachments'] = json_decode($email['attachments'] ?? '[]', true);
            $email['analysis_result'] = json_decode($email['analysis_result'] ?? '{}', true);
            
            return [
                'email' => $email,
                'threats' => $threats
            ];
            
        } catch (Exception $e) {
            error_log("Get email analysis error: " . $e->getMessage());
            return null;
        }
    }
    
    /**
     * Get email history with filtering
     */
    public function getEmailHistory($filters = [], $limit = 50, $offset = 0)
    {
        try {
            $conditions = [];
            $params = [];
            
            // Build WHERE conditions
            if (!empty($filters['risk_level'])) {
                $conditions['risk_level'] = $filters['risk_level'];
            }
            
            if (!empty($filters['date_from'])) {
                $conditions[] = "analysis_date >= ?";
                $params[] = $filters['date_from'];
            }
            
            if (!empty($filters['date_to'])) {
                $conditions[] = "analysis_date <= ?";
                $params[] = $filters['date_to'];
            }
            
            if (!empty($filters['sender'])) {
                $conditions[] = "sender_address LIKE ?";
                $params[] = '%' . $this->database->escapeLike($filters['sender']) . '%';
            }
            
            if (!empty($filters['subject'])) {
                $conditions[] = "subject LIKE ?";
                $params[] = '%' . $this->database->escapeLike($filters['subject']) . '%';
            }
            
            // Build query
            $sql = "SELECT 
                        ea.*,
                        COUNT(dt.id) as threat_count,
                        GROUP_CONCAT(DISTINCT dt.category) as categories
                    FROM email_analysis ea
                    LEFT JOIN detected_threats dt ON ea.email_id = dt.email_id";
            
            if (!empty($conditions)) {
                $whereClause = $this->database->buildWhereClause($conditions, $params);
                $sql .= " $whereClause";
            }
            
            $sql .= " GROUP BY ea.id
                     ORDER BY ea.analysis_date DESC
                     LIMIT ? OFFSET ?";
            
            $params[] = $limit;
            $params[] = $offset;
            
            $results = $this->database->fetchAll($sql, $params);
            
            // Parse JSON fields
            foreach ($results as &$result) {
                $result['analysis_result'] = json_decode($result['analysis_result'] ?? '{}', true);
            }
            
            return $results;
            
        } catch (Exception $e) {
            error_log("Get email history error: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Get email statistics
     */
    public function getEmailStatistics($days = 30)
    {
        try {
            $stats = [];
            
            // Total emails analyzed
            $sql = "SELECT COUNT(*) as total FROM email_analysis WHERE analysis_date >= DATE_SUB(NOW(), INTERVAL ? DAY)";
            $result = $this->database->fetchRow($sql, [$days]);
            $stats['total_emails'] = $result['total'] ?? 0;
            
            // Risk level distribution
            $sql = "SELECT 
                        risk_level,
                        COUNT(*) as count
                    FROM email_analysis 
                    WHERE analysis_date >= DATE_SUB(NOW(), INTERVAL ? DAY)
                    GROUP BY risk_level";
            $riskData = $this->database->fetchAll($sql, [$days]);
            $stats['risk_distribution'] = [];
            foreach ($riskData as $row) {
                $stats['risk_distribution'][$row['risk_level']] = $row['count'];
            }
            
            // Daily trend
            $sql = "SELECT 
                        DATE(analysis_date) as date,
                        COUNT(*) as email_count,
                        AVG(threat_score) as avg_threat_score
                    FROM email_analysis 
                    WHERE analysis_date >= DATE_SUB(NOW(), INTERVAL ? DAY)
                    GROUP BY DATE(analysis_date)
                    ORDER BY date DESC";
            $stats['daily_trend'] = $this->database->fetchAll($sql, [$days]);
            
            // Top threat categories
            $sql = "SELECT 
                        dt.category,
                        COUNT(*) as count
                    FROM detected_threats dt
                    JOIN email_analysis ea ON dt.email_id = ea.email_id
                    WHERE ea.analysis_date >= DATE_SUB(NOW(), INTERVAL ? DAY)
                    GROUP BY dt.category
                    ORDER BY count DESC
                    LIMIT 10";
            $stats['top_categories'] = $this->database->fetchAll($sql, [$days]);
            
            return $stats;
            
        } catch (Exception $e) {
            error_log("Get email statistics error: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Quarantine email
     */
    public function quarantineEmail($emailId, $reason, $userId)
    {
        try {
            // Check if email exists
            $sql = "SELECT email_id FROM email_analysis WHERE email_id = ?";
            $email = $this->database->fetchRow($sql, [$emailId]);
            
            if (!$email) {
                return [
                    'success' => false,
                    'error' => 'Email not found'
                ];
            }
            
            // Insert quarantine record
            $sql = "INSERT INTO quarantine (email_id, quarantine_reason, quarantined_by, quarantine_date, status)
                    VALUES (?, ?, ?, NOW(), 'quarantined')
                    ON DUPLICATE KEY UPDATE 
                        quarantine_reason = VALUES(quarantine_reason),
                        quarantined_by = VALUES(quarantined_by),
                        quarantine_date = NOW(),
                        status = 'quarantined'";
            
            $this->database->execute($sql, [$emailId, $reason, $userId]);
            
            return ['success' => true];
            
        } catch (Exception $e) {
            error_log("Quarantine email error: " . $e->getMessage());
            return [
                'success' => false,
                'error' => 'Failed to quarantine email'
            ];
        }
    }
    
    /**
     * Release email from quarantine
     */
    public function releaseFromQuarantine($emailId, $userId)
    {
        try {
            $sql = "UPDATE quarantine 
                    SET status = 'released', release_date = NOW()
                    WHERE email_id = ? AND status = 'quarantined'";
            
            $stmt = $this->database->execute($sql, [$emailId]);
            
            if ($stmt->rowCount() > 0) {
                return ['success' => true];
            } else {
                return [
                    'success' => false,
                    'error' => 'Email not in quarantine or not found'
                ];
            }
            
        } catch (Exception $e) {
            error_log("Release from quarantine error: " . $e->getMessage());
            return [
                'success' => false,
                'error' => 'Failed to release email from quarantine'
            ];
        }
    }
    
    /**
     * Delete email analysis
     */
    public function deleteEmailAnalysis($emailId, $userId)
    {
        try {
            $this->database->beginTransaction();
            
            // Update quarantine status if exists
            $sql = "UPDATE quarantine SET status = 'deleted' WHERE email_id = ?";
            $this->database->execute($sql, [$emailId]);
            
            // Delete email analysis (cascades to threats)
            $sql = "DELETE FROM email_analysis WHERE email_id = ?";
            $stmt = $this->database->execute($sql, [$emailId]);
            
            if ($stmt->rowCount() === 0) {
                $this->database->rollback();
                return [
                    'success' => false,
                    'error' => 'Email not found'
                ];
            }
            
            $this->database->commit();
            
            return ['success' => true];
            
        } catch (Exception $e) {
            $this->database->rollback();
            error_log("Delete email analysis error: " . $e->getMessage());
            return [
                'success' => false,
                'error' => 'Failed to delete email analysis'
            ];
        }
    }
    
    /**
     * Get upload error message
     */
    private function getUploadErrorMessage($errorCode)
    {
        $messages = [
            UPLOAD_ERR_INI_SIZE => 'File exceeds upload_max_filesize',
            UPLOAD_ERR_FORM_SIZE => 'File exceeds MAX_FILE_SIZE',
            UPLOAD_ERR_PARTIAL => 'File was only partially uploaded',
            UPLOAD_ERR_NO_FILE => 'No file was uploaded',
            UPLOAD_ERR_NO_TMP_DIR => 'Missing temporary folder',
            UPLOAD_ERR_CANT_WRITE => 'Failed to write file to disk',
            UPLOAD_ERR_EXTENSION => 'File upload stopped by extension'
        ];
        
        return $messages[$errorCode] ?? 'Unknown upload error';
    }
    
    /**
     * Export email data
     */
    public function exportEmailData($filters = [], $format = 'json')
    {
        try {
            $emails = $this->getEmailHistory($filters, 10000, 0); // Large limit for export
            
            switch ($format) {
                case 'csv':
                    return $this->exportToCsv($emails);
                case 'json':
                default:
                    return [
                        'success' => true,
                        'data' => json_encode([
                            'emails' => $emails,
                            'exported_at' => date('Y-m-d H:i:s'),
                            'filters' => $filters
                        ], JSON_PRETTY_PRINT)
                    ];
            }
            
        } catch (Exception $e) {
            error_log("Export email data error: " . $e->getMessage());
            return [
                'success' => false,
                'error' => 'Failed to export data'
            ];
        }
    }
    
    /**
     * Export to CSV format
     */
    private function exportToCsv($emails)
    {
        $csv = "Email ID,Filename,Sender,Subject,Risk Level,Threat Score,Analysis Date,Threat Count\n";
        
        foreach ($emails as $email) {
            $row = [
                $email['email_id'],
                $email['filename'],
                $email['sender_address'],
                str_replace('"', '""', $email['subject'] ?? ''),
                $email['risk_level'],
                $email['threat_score'],
                $email['analysis_date'],
                $email['threat_count'] ?? 0
            ];
            
            $csv .= '"' . implode('","', $row) . "\"\n";
        }
        
        return [
            'success' => true,
            'data' => $csv
        ];
    }
}

