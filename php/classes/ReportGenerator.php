<?php
/**
 * Report Generator Class
 * Handles report generation and export functionality
 */

class ReportGenerator {
    private $db;
    private $exportDir;
    
    public function __construct($db) {
        $this->db = $db;
        $this->exportDir = __DIR__ . '/../../exports/';
        
        // Create export directory if it doesn't exist
        if (!is_dir($this->exportDir)) {
            mkdir($this->exportDir, 0755, true);
        }
    }
    
    /**
     * Generate report based on type and parameters
     */
    public function generateReport($reportType, $dateRange = 30, $format = 'html', $options = []) {
        try {
            switch ($reportType) {
                case 'summary':
                    return $this->generateSummaryReport($dateRange, $format, $options);
                case 'detailed':
                    return $this->generateDetailedReport($dateRange, $format, $options);
                case 'trends':
                    return $this->generateTrendsReport($dateRange, $format, $options);
                case 'quarantine':
                    return $this->generateQuarantineReport($dateRange, $format, $options);
                case 'sender_analysis':
                    return $this->generateSenderAnalysisReport($dateRange, $format, $options);
                default:
                    return [
                        'success' => false,
                        'message' => 'Unknown report type',
                        'error' => 'Supported types: summary, detailed, trends, quarantine, sender_analysis'
                    ];
            }
        } catch (Exception $e) {
            error_log("Report generation failed: " . $e->getMessage());
            return [
                'success' => false,
                'message' => 'Report generation failed',
                'error' => $e->getMessage()
            ];
        }
    }
    
    /**
     * Generate summary report
     */
    private function generateSummaryReport($dateRange, $format, $options) {
        $startDate = date('Y-m-d', strtotime("-{$dateRange} days"));
        $endDate = date('Y-m-d');
        
        // Get basic statistics
        $stats = $this->db->getThreatStatistics($dateRange);
        
        // Get threat level breakdown
        $threatBreakdown = $this->getThreatLevelBreakdown($startDate, $endDate);
        
        // Get top senders by threat count
        $topThreats = $this->getTopThreatSenders($startDate, $endDate, 10);
        
        // Get daily summary
        $dailySummary = $this->getDailySummary($startDate, $endDate);
        
        $reportData = [
            'report_type' => 'summary',
            'date_range' => [
                'start' => $startDate,
                'end' => $endDate,
                'days' => $dateRange
            ],
            'generated_at' => date('Y-m-d H:i:s'),
            'statistics' => $stats,
            'threat_breakdown' => $threatBreakdown,
            'top_threats' => $topThreats,
            'daily_summary' => $dailySummary
        ];
        
        return $this->formatReport($reportData, $format);
    }
    
    /**
     * Generate detailed report
     */
    private function generateDetailedReport($dateRange, $format, $options) {
        $startDate = date('Y-m-d', strtotime("-{$dateRange} days"));
        $endDate = date('Y-m-d');
        
        // Get all analyses in date range
        $analyses = $this->getDetailedAnalyses($startDate, $endDate);
        
        // Get pattern matches
        $patternMatches = $this->getPatternMatchSummary($startDate, $endDate);
        
        // Get attachment analysis
        $attachmentAnalysis = $this->getAttachmentAnalysis($startDate, $endDate);
        
        $reportData = [
            'report_type' => 'detailed',
            'date_range' => [
                'start' => $startDate,
                'end' => $endDate,
                'days' => $dateRange
            ],
            'generated_at' => date('Y-m-d H:i:s'),
            'total_analyses' => count($analyses),
            'analyses' => $analyses,
            'pattern_matches' => $patternMatches,
            'attachment_analysis' => $attachmentAnalysis
        ];
        
        return $this->formatReport($reportData, $format);
    }
    
    /**
     * Generate trends report
     */
    private function generateTrendsReport($dateRange, $format, $options) {
        $startDate = date('Y-m-d', strtotime("-{$dateRange} days"));
        $endDate = date('Y-m-d');
        
        // Get daily trends
        $dailyTrends = $this->getDailyThreatTrends($startDate, $endDate);
        
        // Get weekly aggregation
        $weeklyTrends = $this->getWeeklyTrends($startDate, $endDate);
        
        // Get sender trends
        $senderTrends = $this->getSenderTrends($startDate, $endDate);
        
        // Get threat type trends
        $threatTypeTrends = $this->getThreatTypeTrends($startDate, $endDate);
        
        $reportData = [
            'report_type' => 'trends',
            'date_range' => [
                'start' => $startDate,
                'end' => $endDate,
                'days' => $dateRange
            ],
            'generated_at' => date('Y-m-d H:i:s'),
            'daily_trends' => $dailyTrends,
            'weekly_trends' => $weeklyTrends,
            'sender_trends' => $senderTrends,
            'threat_type_trends' => $threatTypeTrends
        ];
        
        return $this->formatReport($reportData, $format);
    }
    
    /**
     * Generate quarantine report
     */
    private function generateQuarantineReport($dateRange, $format, $options) {
        $startDate = date('Y-m-d', strtotime("-{$dateRange} days"));
        $endDate = date('Y-m-d');
        
        // Get quarantined emails
        $quarantinedEmails = $this->getQuarantinedEmails($startDate, $endDate);
        
        // Get quarantine statistics
        $quarantineStats = $this->getQuarantineStatistics($startDate, $endDate);
        
        // Get release/action history
        $actionHistory = $this->getQuarantineActionHistory($startDate, $endDate);
        
        $reportData = [
            'report_type' => 'quarantine',
            'date_range' => [
                'start' => $startDate,
                'end' => $endDate,
                'days' => $dateRange
            ],
            'generated_at' => date('Y-m-d H:i:s'),
            'quarantine_statistics' => $quarantineStats,
            'quarantined_emails' => $quarantinedEmails,
            'action_history' => $actionHistory
        ];
        
        return $this->formatReport($reportData, $format);
    }
    
    /**
     * Generate sender analysis report
     */
    private function generateSenderAnalysisReport($dateRange, $format, $options) {
        $startDate = date('Y-m-d', strtotime("-{$dateRange} days"));
        $endDate = date('Y-m-d');
        
        // Get sender statistics
        $senderStats = $this->getSenderStatistics($startDate, $endDate);
        
        // Get reputation analysis
        $reputationAnalysis = $this->getReputationAnalysis();
        
        // Get new senders
        $newSenders = $this->getNewSenders($startDate, $endDate);
        
        $reportData = [
            'report_type' => 'sender_analysis',
            'date_range' => [
                'start' => $startDate,
                'end' => $endDate,
                'days' => $dateRange
            ],
            'generated_at' => date('Y-m-d H:i:s'),
            'sender_statistics' => $senderStats,
            'reputation_analysis' => $reputationAnalysis,
            'new_senders' => $newSenders
        ];
        
        return $this->formatReport($reportData, $format);
    }
    
    /**
     * Export report to file
     */
    public function exportReport($reportData, $format, $filename = null) {
        try {
            if (!$filename) {
                $timestamp = date('Y-m-d_H-i-s');
                $filename = "threat_report_{$reportData['report_type']}_{$timestamp}.{$format}";
            }
            
            $filePath = $this->exportDir . $filename;
            
            switch ($format) {
                case 'json':
                    $content = json_encode($reportData, JSON_PRETTY_PRINT);
                    break;
                case 'csv':
                    $content = $this->convertToCSV($reportData);
                    break;
                case 'html':
                    $content = $this->convertToHTML($reportData);
                    break;
                case 'txt':
                    $content = $this->convertToText($reportData);
                    break;
                default:
                    throw new Exception("Unsupported export format: {$format}");
            }
            
            if (file_put_contents($filePath, $content) === false) {
                throw new Exception("Failed to write report file");
            }
            
            return [
                'success' => true,
                'message' => 'Report exported successfully',
                'file_path' => $filePath,
                'filename' => $filename,
                'file_size' => filesize($filePath)
            ];
            
        } catch (Exception $e) {
            error_log("Report export failed: " . $e->getMessage());
            return [
                'success' => false,
                'message' => 'Report export failed',
                'error' => $e->getMessage()
            ];
        }
    }
    
    /**
     * Get recent reports
     */
    public function getRecentReports($limit = 10) {
        $reports = [];
        $files = glob($this->exportDir . "threat_report_*");
        
        // Sort by modification time
        usort($files, function($a, $b) {
            return filemtime($b) - filemtime($a);
        });
        
        $files = array_slice($files, 0, $limit);
        
        foreach ($files as $file) {
            $filename = basename($file);
            $reports[] = [
                'filename' => $filename,
                'file_path' => $file,
                'file_size' => filesize($file),
                'created_at' => date('Y-m-d H:i:s', filemtime($file)),
                'format' => pathinfo($file, PATHINFO_EXTENSION)
            ];
        }
        
        return $reports;
    }
    
    /**
     * Format report based on output format
     */
    private function formatReport($reportData, $format) {
        switch ($format) {
            case 'json':
                return [
                    'success' => true,
                    'data' => $reportData,
                    'format' => 'json'
                ];
            case 'html':
                return [
                    'success' => true,
                    'data' => $reportData,
                    'html' => $this->convertToHTML($reportData),
                    'format' => 'html'
                ];
            default:
                return [
                    'success' => true,
                    'data' => $reportData,
                    'format' => $format
                ];
        }
    }
    
    /**
     * Get threat level breakdown
     */
    private function getThreatLevelBreakdown($startDate, $endDate) {
        try {
            $stmt = $this->db->connection->prepare("
                SELECT 
                    threat_level,
                    COUNT(*) as count,
                    AVG(risk_score) as avg_risk_score,
                    MIN(risk_score) as min_risk_score,
                    MAX(risk_score) as max_risk_score
                FROM email_analyses 
                WHERE DATE(analysis_timestamp) BETWEEN ? AND ?
                GROUP BY threat_level
                ORDER BY count DESC
            ");
            
            $stmt->execute([$startDate, $endDate]);
            return $stmt->fetchAll();
            
        } catch (Exception $e) {
            error_log("Failed to get threat level breakdown: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Get top threat senders
     */
    private function getTopThreatSenders($startDate, $endDate, $limit) {
        try {
            $stmt = $this->db->connection->prepare("
                SELECT 
                    sender,
                    COUNT(*) as total_emails,
                    SUM(CASE WHEN risk_score >= 40 THEN 1 ELSE 0 END) as threat_emails,
                    AVG(risk_score) as avg_risk_score,
                    MAX(risk_score) as max_risk_score,
                    COUNT(CASE WHEN is_quarantined = 1 THEN 1 END) as quarantined_count
                FROM email_analyses 
                WHERE DATE(analysis_timestamp) BETWEEN ? AND ?
                AND sender != ''
                GROUP BY sender
                HAVING threat_emails > 0
                ORDER BY threat_emails DESC, avg_risk_score DESC
                LIMIT ?
            ");
            
            $stmt->execute([$startDate, $endDate, $limit]);
            return $stmt->fetchAll();
            
        } catch (Exception $e) {
            error_log("Failed to get top threat senders: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Get daily summary
     */
    private function getDailySummary($startDate, $endDate) {
        try {
            $stmt = $this->db->connection->prepare("
                SELECT 
                    DATE(analysis_timestamp) as date,
                    COUNT(*) as total_emails,
                    SUM(CASE WHEN risk_score >= 40 THEN 1 ELSE 0 END) as threat_emails,
                    SUM(CASE WHEN risk_score >= 80 THEN 1 ELSE 0 END) as critical_threats,
                    AVG(risk_score) as avg_risk_score
                FROM email_analyses 
                WHERE DATE(analysis_timestamp) BETWEEN ? AND ?
                GROUP BY DATE(analysis_timestamp)
                ORDER BY date ASC
            ");
            
            $stmt->execute([$startDate, $endDate]);
            return $stmt->fetchAll();
            
        } catch (Exception $e) {
            error_log("Failed to get daily summary: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Convert report to HTML format
     */
    private function convertToHTML($reportData) {
        $html = "<!DOCTYPE html>\n<html>\n<head>\n";
        $html .= "<title>Threat Analysis Report - {$reportData['report_type']}</title>\n";
        $html .= "<style>\n";
        $html .= "body { font-family: Arial, sans-serif; margin: 20px; }\n";
        $html .= "table { border-collapse: collapse; width: 100%; margin: 20px 0; }\n";
        $html .= "th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n";
        $html .= "th { background-color: #f2f2f2; }\n";
        $html .= ".header { background-color: #007bff; color: white; padding: 20px; }\n";
        $html .= ".section { margin: 20px 0; }\n";
        $html .= ".critical { color: #dc3545; font-weight: bold; }\n";
        $html .= ".high { color: #fd7e14; font-weight: bold; }\n";
        $html .= ".medium { color: #ffc107; font-weight: bold; }\n";
        $html .= "</style>\n";
        $html .= "</head>\n<body>\n";
        
        // Header
        $html .= "<div class='header'>\n";
        $html .= "<h1>Threat Analysis Report</h1>\n";
        $html .= "<p>Report Type: " . ucfirst($reportData['report_type']) . "</p>\n";
        $html .= "<p>Date Range: {$reportData['date_range']['start']} to {$reportData['date_range']['end']}</p>\n";
        $html .= "<p>Generated: {$reportData['generated_at']}</p>\n";
        $html .= "</div>\n";
        
        // Statistics section
        if (isset($reportData['statistics'])) {
            $stats = $reportData['statistics'];
            $html .= "<div class='section'>\n";
            $html .= "<h2>Summary Statistics</h2>\n";
            $html .= "<table>\n";
            $html .= "<tr><th>Metric</th><th>Value</th></tr>\n";
            $html .= "<tr><td>Total Emails</td><td>" . ($stats['total_emails'] ?? 0) . "</td></tr>\n";
            $html .= "<tr><td>Threat Emails</td><td class='critical'>" . ($stats['threat_emails'] ?? 0) . "</td></tr>\n";
            $html .= "<tr><td>Critical Threats</td><td class='critical'>" . ($stats['critical_threats'] ?? 0) . "</td></tr>\n";
            $html .= "<tr><td>High Threats</td><td class='high'>" . ($stats['high_threats'] ?? 0) . "</td></tr>\n";
            $html .= "<tr><td>Medium Threats</td><td class='medium'>" . ($stats['medium_threats'] ?? 0) . "</td></tr>\n";
            $html .= "<tr><td>Quarantined</td><td>" . ($stats['quarantined_emails'] ?? 0) . "</td></tr>\n";
            $html .= "<tr><td>Detection Rate</td><td>" . round(($stats['detection_rate'] ?? 0), 2) . "%</td></tr>\n";
            $html .= "</table>\n";
            $html .= "</div>\n";
        }
        
        // Add other sections based on report type
        $html .= "</body>\n</html>";
        
        return $html;
    }
    
    /**
     * Convert report to CSV format
     */
    private function convertToCSV($reportData) {
        $csv = "Threat Analysis Report - " . ucfirst($reportData['report_type']) . "\n";
        $csv .= "Generated: {$reportData['generated_at']}\n";
        $csv .= "Date Range: {$reportData['date_range']['start']} to {$reportData['date_range']['end']}\n\n";
        
        // Add statistics if available
        if (isset($reportData['statistics'])) {
            $csv .= "Summary Statistics\n";
            $csv .= "Metric,Value\n";
            foreach ($reportData['statistics'] as $key => $value) {
                $csv .= "$key," . (is_numeric($value) ? $value : '"' . $value . '"') . "\n";
            }
            $csv .= "\n";
        }
        
        return $csv;
    }
    
    /**
     * Convert report to text format
     */
    private function convertToText($reportData) {
        $text = "THREAT ANALYSIS REPORT\n";
        $text .= "=====================\n\n";
        $text .= "Report Type: " . ucfirst($reportData['report_type']) . "\n";
        $text .= "Generated: {$reportData['generated_at']}\n";
        $text .= "Date Range: {$reportData['date_range']['start']} to {$reportData['date_range']['end']}\n";
        $text .= "Period: {$reportData['date_range']['days']} days\n\n";
        
        // Add statistics
        if (isset($reportData['statistics'])) {
            $text .= "SUMMARY STATISTICS\n";
            $text .= "------------------\n";
            foreach ($reportData['statistics'] as $key => $value) {
                $text .= ucwords(str_replace('_', ' ', $key)) . ": " . $value . "\n";
            }
            $text .= "\n";
        }
        
        return $text;
    }
    
    // Additional helper methods for specific data queries...
    private function getDetailedAnalyses($startDate, $endDate) {
        // Implementation for detailed analyses query
        return [];
    }
    
    private function getPatternMatchSummary($startDate, $endDate) {
        // Implementation for pattern match summary
        return [];
    }
    
    private function getAttachmentAnalysis($startDate, $endDate) {
        // Implementation for attachment analysis
        return [];
    }
    
    private function getDailyThreatTrends($startDate, $endDate) {
        // Implementation for daily threat trends
        return [];
    }
    
    private function getWeeklyTrends($startDate, $endDate) {
        // Implementation for weekly trends
        return [];
    }
    
    private function getSenderTrends($startDate, $endDate) {
        // Implementation for sender trends
        return [];
    }
    
    private function getThreatTypeTrends($startDate, $endDate) {
        // Implementation for threat type trends
        return [];
    }
    
    private function getQuarantinedEmails($startDate, $endDate) {
        // Implementation for quarantined emails query
        return [];
    }
    
    private function getQuarantineStatistics($startDate, $endDate) {
        // Implementation for quarantine statistics
        return [];
    }
    
    private function getQuarantineActionHistory($startDate, $endDate) {
        // Implementation for quarantine action history
        return [];
    }
    
    private function getSenderStatistics($startDate, $endDate) {
        // Implementation for sender statistics
        return [];
    }
    
    private function getReputationAnalysis() {
        // Implementation for reputation analysis
        return [];
    }
    
    private function getNewSenders($startDate, $endDate) {
        // Implementation for new senders query
        return [];
    }
}
?>
