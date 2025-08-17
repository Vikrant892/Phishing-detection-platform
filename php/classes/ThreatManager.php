<?php

/**
 * Threat Management Class
 * Handles threat detection, analysis, and management operations
 */
class ThreatManager
{
    private $database;
    private $pythonApiUrl;
    
    public function __construct(Database $database)
    {
        $this->database = $database;
        $this->pythonApiUrl = 'http://localhost:8000/api';
    }
    
    /**
     * Get threat statistics for dashboard
     */
    public function getThreatStatistics($days = 30)
    {
        try {
            $stats = [];
            
            // Total threats detected
            $sql = "SELECT COUNT(*) as total FROM detected_threats 
                    WHERE detected_at >= DATE_SUB(NOW(), INTERVAL ? DAY)";
            $result = $this->database->fetchRow($sql, [$days]);
            $stats['total_threats'] = $result['total'] ?? 0;
            
            // Threats by severity
            $sql = "SELECT 
                        severity,
                        COUNT(*) as count
                    FROM detected_threats 
                    WHERE detected_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
                    GROUP BY severity";
            $severityData = $this->database->fetchAll($sql, [$days]);
            $stats['severity_distribution'] = [];
            foreach ($severityData as $row) {
                $stats['severity_distribution'][$row['severity']] = $row['count'];
            }
            
            // Threats by category
            $sql = "SELECT 
                        category,
                        COUNT(*) as count
                    FROM detected_threats 
                    WHERE detected_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
                    GROUP BY category
                    ORDER BY count DESC
                    LIMIT 10";
            $stats['category_distribution'] = $this->database->fetchAll($sql, [$days]);
            
            // Daily threat trend
            $sql = "SELECT 
                        DATE(detected_at) as date,
                        COUNT(*) as threat_count,
                        COUNT(CASE WHEN severity IN ('high', 'critical') THEN 1 END) as high_risk_count
                    FROM detected_threats 
                    WHERE detected_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
                    GROUP BY DATE(detected_at)
                    ORDER BY date DESC";
            $stats['daily_trend'] = $this->database->fetchAll($sql, [$days]);
            
            // Most common threat types
            $sql = "SELECT 
                        threat_type,
                        COUNT(*) as count,
                        AVG(CASE WHEN severity = 'critical' THEN 4
                                 WHEN severity = 'high' THEN 3
                                 WHEN severity = 'medium' THEN 2
                                 ELSE 1 END) as avg_severity_score
                    FROM detected_threats 
                    WHERE detected_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
                    GROUP BY threat_type
                    ORDER BY count DESC
                    LIMIT 15";
            $stats['top_threat_types'] = $this->database->fetchAll($sql, [$days]);
            
            // Recent critical threats
            $sql = "SELECT 
                        dt.*,
                        ea.filename,
                        ea.sender_address,
                        ea.subject
                    FROM detected_threats dt
                    JOIN email_analysis ea ON dt.email_id = ea.email_id
                    WHERE dt.severity = 'critical' 
                    AND dt.detected_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
                    ORDER BY dt.detected_at DESC
                    LIMIT 10";
            $stats['recent_critical'] = $this->database->fetchAll($sql);
            
            return $stats;
            
        } catch (Exception $e) {
            error_log("Get threat statistics error: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Get detailed threat information
     */
    public function getThreatDetails($emailId)
    {
        try {
            $sql = "SELECT 
                        dt.*,
                        ea.filename,
                        ea.sender_address,
                        ea.subject,
                        ea.risk_level,
                        ea.threat_score
                    FROM detected_threats dt
                    JOIN email_analysis ea ON dt.email_id = ea.email_id
                    WHERE dt.email_id = ?
                    ORDER BY dt.severity DESC, dt.detected_at DESC";
            
            return $this->database->fetchAll($sql, [$emailId]);
            
        } catch (Exception $e) {
            error_log("Get threat details error: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Get threat history with filtering
     */
    public function getThreatHistory($filters = [], $limit = 50, $offset = 0)
    {
        try {
            $conditions = [];
            $params = [];
            
            // Build WHERE conditions
            if (!empty($filters['severity'])) {
                if (is_array($filters['severity'])) {
                    $conditions[] = "dt.severity IN (" . str_repeat('?,', count($filters['severity']) - 1) . "?)";
                    $params = array_merge($params, $filters['severity']);
                } else {
                    $conditions[] = "dt.severity = ?";
                    $params[] = $filters['severity'];
                }
            }
            
            if (!empty($filters['category'])) {
                $conditions[] = "dt.category = ?";
                $params[] = $filters['category'];
            }
            
            if (!empty($filters['threat_type'])) {
                $conditions[] = "dt.threat_type LIKE ?";
                $params[] = '%' . $this->database->escapeLike($filters['threat_type']) . '%';
            }
            
            if (!empty($filters['date_from'])) {
                $conditions[] = "dt.detected_at >= ?";
                $params[] = $filters['date_from'];
            }
            
            if (!empty($filters['date_to'])) {
                $conditions[] = "dt.detected_at <= ?";
                $params[] = $filters['date_to'];
            }
            
            if (!empty($filters['email_sender'])) {
                $conditions[] = "ea.sender_address LIKE ?";
                $params[] = '%' . $this->database->escapeLike($filters['email_sender']) . '%';
            }
            
            // Build query
            $sql = "SELECT 
                        dt.*,
                        ea.filename,
                        ea.sender_address,
                        ea.subject,
                        ea.risk_level,
                        ea.threat_score,
                        ea.analysis_date
                    FROM detected_threats dt
                    JOIN email_analysis ea ON dt.email_id = ea.email_id";
            
            if (!empty($conditions)) {
                $sql .= " WHERE " . implode(' AND ', $conditions);
            }
            
            $sql .= " ORDER BY dt.detected_at DESC LIMIT ? OFFSET ?";
            $params[] = $limit;
            $params[] = $offset;
            
            return $this->database->fetchAll($sql, $params);
            
        } catch (Exception $e) {
            error_log("Get threat history error: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Get threat patterns and analysis
     */
    public function getThreatPatterns($days = 30)
    {
        try {
            $patterns = [];
            
            // Temporal patterns (threats by hour)
            $sql = "SELECT 
                        HOUR(detected_at) as hour,
                        COUNT(*) as threat_count,
                        AVG(CASE WHEN severity = 'critical' THEN 4
                                 WHEN severity = 'high' THEN 3
                                 WHEN severity = 'medium' THEN 2
                                 ELSE 1 END) as avg_severity
                    FROM detected_threats 
                    WHERE detected_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
                    GROUP BY HOUR(detected_at)
                    ORDER BY hour";
            $patterns['hourly'] = $this->database->fetchAll($sql, [$days]);
            
            // Day of week patterns
            $sql = "SELECT 
                        DAYNAME(detected_at) as day_name,
                        DAYOFWEEK(detected_at) as day_num,
                        COUNT(*) as threat_count
                    FROM detected_threats 
                    WHERE detected_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
                    GROUP BY DAYOFWEEK(detected_at), DAYNAME(detected_at)
                    ORDER BY day_num";
            $patterns['weekly'] = $this->database->fetchAll($sql, [$days]);
            
            // Sender domain patterns
            $sql = "SELECT 
                        SUBSTRING_INDEX(SUBSTRING_INDEX(ea.sender_address, '@', -1), '>', 1) as domain,
                        COUNT(DISTINCT ea.email_id) as email_count,
                        COUNT(dt.id) as threat_count,
                        AVG(ea.threat_score) as avg_threat_score
                    FROM email_analysis ea
                    JOIN detected_threats dt ON ea.email_id = dt.email_id
                    WHERE ea.analysis_date >= DATE_SUB(NOW(), INTERVAL ? DAY)
                    AND ea.sender_address != ''
                    GROUP BY domain
                    HAVING threat_count > 1
                    ORDER BY threat_count DESC
                    LIMIT 20";
            $patterns['domains'] = $this->database->fetchAll($sql, [$days]);
            
            // Threat correlation patterns
            $sql = "SELECT 
                        dt1.category as category1,
                        dt2.category as category2,
                        COUNT(*) as co_occurrence_count
                    FROM detected_threats dt1
                    JOIN detected_threats dt2 ON dt1.email_id = dt2.email_id AND dt1.id < dt2.id
                    WHERE dt1.detected_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
                    GROUP BY dt1.category, dt2.category
                    HAVING co_occurrence_count > 2
                    ORDER BY co_occurrence_count DESC
                    LIMIT 15";
            $patterns['correlations'] = $this->database->fetchAll($sql, [$days]);
            
            return $patterns;
            
        } catch (Exception $e) {
            error_log("Get threat patterns error: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Get active alerts
     */
    public function getActiveAlerts()
    {
        try {
            $alerts = [];
            
            // High-risk emails in last 24 hours
            $sql = "SELECT 
                        ea.*,
                        COUNT(dt.id) as threat_count
                    FROM email_analysis ea
                    LEFT JOIN detected_threats dt ON ea.email_id = dt.email_id
                    WHERE ea.risk_level IN ('high', 'critical')
                    AND ea.analysis_date >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
                    GROUP BY ea.email_id
                    ORDER BY ea.threat_score DESC, ea.analysis_date DESC
                    LIMIT 20";
            $alerts['high_risk_emails'] = $this->database->fetchAll($sql);
            
            // Threat spikes (unusual activity)
            $sql = "SELECT 
                        threat_type,
                        category,
                        COUNT(*) as occurrence_count,
                        MAX(detected_at) as last_occurrence
                    FROM detected_threats 
                    WHERE detected_at >= DATE_SUB(NOW(), INTERVAL 2 HOUR)
                    GROUP BY threat_type, category
                    HAVING COUNT(*) > 3
                    ORDER BY occurrence_count DESC";
            $alerts['threat_spikes'] = $this->database->fetchAll($sql);
            
            // Quarantine alerts
            $sql = "SELECT 
                        COUNT(*) as quarantined_count
                    FROM quarantine 
                    WHERE quarantine_date >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
                    AND status = 'quarantined'";
            $result = $this->database->fetchRow($sql);
            $alerts['quarantine_count'] = $result['quarantined_count'] ?? 0;
            
            return $alerts;
            
        } catch (Exception $e) {
            error_log("Get active alerts error: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Get quarantine management data
     */
    public function getQuarantineData()
    {
        try {
            $data = [];
            
            // Quarantined emails
            $sql = "SELECT 
                        q.*,
                        ea.filename,
                        ea.sender_address,
                        ea.subject,
                        ea.threat_score,
                        ea.risk_level
                    FROM quarantine q
                    JOIN email_analysis ea ON q.email_id = ea.email_id
                    WHERE q.status = 'quarantined'
                    ORDER BY q.quarantine_date DESC";
            $data['quarantined_emails'] = $this->database->fetchAll($sql);
            
            // Quarantine statistics
            $sql = "SELECT 
                        status,
                        COUNT(*) as count
                    FROM quarantine
                    GROUP BY status";
            $statusData = $this->database->fetchAll($sql);
            $data['status_counts'] = [];
            foreach ($statusData as $row) {
                $data['status_counts'][$row['status']] = $row['count'];
            }
            
            // Recent quarantine activity
            $sql = "SELECT 
                        DATE(quarantine_date) as date,
                        COUNT(*) as quarantined_count
                    FROM quarantine
                    WHERE quarantine_date >= DATE_SUB(NOW(), INTERVAL 30 DAY)
                    GROUP BY DATE(quarantine_date)
                    ORDER BY date DESC";
            $data['recent_activity'] = $this->database->fetchAll($sql);
            
            return $data;
            
        } catch (Exception $e) {
            error_log("Get quarantine data error: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Scan arbitrary content for threats
     */
    public function scanContent($content, $contentType = 'text', $customRules = [])
    {
        try {
            $postData = [
                'content' => $content,
                'content_type' => $contentType,
                'setup_rules' => $customRules
            ];
            
            $curl = curl_init();
            
            curl_setopt_array($curl, [
                CURLOPT_URL => $this->pythonApiUrl . '/threat/scan',
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => json_encode($postData),
                CURLOPT_TIMEOUT => 30,
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
                throw new Exception("Scan failed: " . ($data['error'] ?? 'Unknown error'));
            }
            
            return [
                'success' => true,
                'analysis' => $data['data']
            ];
            
        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => 'Content scan failed: ' . $e->getMessage()
            ];
        }
    }
    
    /**
     * Export threat data
     */
    public function exportThreatData($filters = [], $format = 'json')
    {
        try {
            $threats = $this->getThreatHistory($filters, 10000, 0);
            
            switch ($format) {
                case 'csv':
                    return $this->exportToCsv($threats);
                case 'json':
                default:
                    return [
                        'success' => true,
                        'data' => json_encode([
                            'threats' => $threats,
                            'exported_at' => date('Y-m-d H:i:s'),
                            'filters' => $filters
                        ], JSON_PRETTY_PRINT)
                    ];
            }
            
        } catch (Exception $e) {
            error_log("Export threat data error: " . $e->getMessage());
            return [
                'success' => false,
                'error' => 'Failed to export data'
            ];
        }
    }
    
    /**
     * Export to CSV format
     */
    private function exportToCsv($threats)
    {
        $csv = "Email ID,Filename,Sender,Threat Type,Severity,Category,Description,Evidence,Location,Detected At\n";
        
        foreach ($threats as $threat) {
            $row = [
                $threat['email_id'],
                $threat['filename'],
                $threat['sender_address'],
                $threat['threat_type'],
                $threat['severity'],
                $threat['category'],
                str_replace('"', '""', $threat['description'] ?? ''),
                str_replace('"', '""', $threat['evidence'] ?? ''),
                $threat['location'],
                $threat['detected_at']
            ];
            
            $csv .= '"' . implode('","', $row) . "\"\n";
        }
        
        return [
            'success' => true,
            'data' => $csv
        ];
    }
    
    /**
     * Get threat intelligence summary
     */
    public function getThreatIntelligence()
    {
        try {
            $intel = [];
            
            // Trending threats
            $sql = "SELECT 
                        threat_type,
                        COUNT(*) as current_count,
                        COUNT(CASE WHEN detected_at >= DATE_SUB(NOW(), INTERVAL 7 DAY) THEN 1 END) as recent_count
                    FROM detected_threats 
                    WHERE detected_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
                    GROUP BY threat_type
                    HAVING current_count > 5
                    ORDER BY (recent_count / current_count) DESC";
            $intel['trending_threats'] = $this->database->fetchAll($sql);
            
            // Emerging patterns
            $sql = "SELECT 
                        pattern_matched,
                        COUNT(*) as frequency,
                        COUNT(DISTINCT email_id) as unique_emails
                    FROM detected_threats 
                    WHERE pattern_matched IS NOT NULL 
                    AND pattern_matched != ''
                    AND detected_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                    GROUP BY pattern_matched
                    HAVING frequency > 2
                    ORDER BY frequency DESC
                    LIMIT 10";
            $intel['emerging_patterns'] = $this->database->fetchAll($sql);
            
            // Risk indicators
            $sql = "SELECT 
                        COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical_count,
                        COUNT(CASE WHEN severity = 'high' THEN 1 END) as high_count,
                        COUNT(CASE WHEN detected_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR) THEN 1 END) as last_24h_count,
                        AVG(CASE WHEN severity = 'critical' THEN 4
                                 WHEN severity = 'high' THEN 3
                                 WHEN severity = 'medium' THEN 2
                                 ELSE 1 END) as avg_risk_score
                    FROM detected_threats 
                    WHERE detected_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)";
            $intel['risk_indicators'] = $this->database->fetchRow($sql);
            
            return $intel;
            
        } catch (Exception $e) {
            error_log("Get threat intelligence error: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Generate threat report
     */
    public function generateThreatReport($startDate, $endDate)
    {
        try {
            $report = [
                'period' => [
                    'start' => $startDate,
                    'end' => $endDate
                ],
                'generated_at' => date('Y-m-d H:i:s')
            ];
            
            // Summary statistics
            $sql = "SELECT 
                        COUNT(DISTINCT ea.email_id) as total_emails,
                        COUNT(dt.id) as total_threats,
                        COUNT(CASE WHEN dt.severity = 'critical' THEN 1 END) as critical_threats,
                        COUNT(CASE WHEN dt.severity = 'high' THEN 1 END) as high_threats,
                        AVG(ea.threat_score) as avg_threat_score
                    FROM email_analysis ea
                    LEFT JOIN detected_threats dt ON ea.email_id = dt.email_id
                    WHERE ea.analysis_date BETWEEN ? AND ?";
            $report['summary'] = $this->database->fetchRow($sql, [$startDate, $endDate]);
            
            // Top threats
            $sql = "SELECT 
                        threat_type,
                        category,
                        severity,
                        COUNT(*) as count
                    FROM detected_threats 
                    WHERE detected_at BETWEEN ? AND ?
                    GROUP BY threat_type, category, severity
                    ORDER BY count DESC
                    LIMIT 20";
            $report['top_threats'] = $this->database->fetchAll($sql, [$startDate, $endDate]);
            
            // Daily breakdown
            $sql = "SELECT 
                        DATE(ea.analysis_date) as date,
                        COUNT(DISTINCT ea.email_id) as emails,
                        COUNT(dt.id) as threats,
                        AVG(ea.threat_score) as avg_score
                    FROM email_analysis ea
                    LEFT JOIN detected_threats dt ON ea.email_id = dt.email_id
                    WHERE ea.analysis_date BETWEEN ? AND ?
                    GROUP BY DATE(ea.analysis_date)
                    ORDER BY date";
            $report['daily_breakdown'] = $this->database->fetchAll($sql, [$startDate, $endDate]);
            
            return $report;
            
        } catch (Exception $e) {
            error_log("Generate threat report error: " . $e->getMessage());
            return null;
        }
    }
}

