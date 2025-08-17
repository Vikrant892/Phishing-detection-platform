<!-- Reports Page -->
<div class="row mb-4">
    <div class="col-12">
        <div class="d-flex justify-content-between align-items-center">
            <h1 class="h3 mb-0">
                <i class="fas fa-chart-line me-2 text-primary"></i>
                Reports & Analytics
            </h1>
            <div class="d-flex gap-2">
                <button class="btn btn-outline-primary btn-sm" onclick="Reports.refreshData()">
                    <i class="fas fa-sync-alt me-1"></i>Refresh
                </button>
                <button class="btn btn-success btn-sm" data-bs-toggle="modal" data-bs-target="#generateReportModal">
                    <i class="fas fa-plus me-1"></i>Generate Report
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Report Generation Section -->
<div class="row mb-4">
    <div class="col-12">
        <div class="card shadow">
            <div class="card-header py-3">
                <h6 class="m-0 fw-bold text-primary">
                    <i class="fas fa-magic me-2"></i>Quick Report Generation
                </h6>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-lg-3 col-md-6 mb-3">
                        <div class="card border-0 bg-light h-100">
                            <div class="card-body text-center">
                                <i class="fas fa-chart-pie fa-2x text-primary mb-2"></i>
                                <h6>Summary Report</h6>
                                <p class="small text-muted mb-3">Overall threat statistics and trends</p>
                                <button class="btn btn-primary btn-sm" 
                                        onclick="Reports.generateQuickReport('summary')">
                                    Generate
                                </button>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-3 col-md-6 mb-3">
                        <div class="card border-0 bg-light h-100">
                            <div class="card-body text-center">
                                <i class="fas fa-list-alt fa-2x text-info mb-2"></i>
                                <h6>Detailed Report</h6>
                                <p class="small text-muted mb-3">Comprehensive analysis breakdown</p>
                                <button class="btn btn-info btn-sm" 
                                        onclick="Reports.generateQuickReport('detailed')">
                                    Generate
                                </button>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-3 col-md-6 mb-3">
                        <div class="card border-0 bg-light h-100">
                            <div class="card-body text-center">
                                <i class="fas fa-chart-line fa-2x text-success mb-2"></i>
                                <h6>Trends Report</h6>
                                <p class="small text-muted mb-3">Historical patterns and forecasts</p>
                                <button class="btn btn-success btn-sm" 
                                        onclick="Reports.generateQuickReport('trends')">
                                    Generate
                                </button>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-3 col-md-6 mb-3">
                        <div class="card border-0 bg-light h-100">
                            <div class="card-body text-center">
                                <i class="fas fa-ban fa-2x text-warning mb-2"></i>
                                <h6>Quarantine Report</h6>
                                <p class="small text-muted mb-3">Quarantined emails and actions</p>
                                <button class="btn btn-warning btn-sm" 
                                        onclick="Reports.generateQuickReport('quarantine')">
                                    Generate
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Analytics Dashboard -->
<div class="row mb-4">
    <!-- Threat Overview Chart -->
    <div class="col-xl-8">
        <div class="card shadow mb-4">
            <div class="card-header py-3 d-flex justify-content-between align-items-center">
                <h6 class="m-0 fw-bold text-primary">
                    <i class="fas fa-chart-area me-2"></i>Threat Analysis Overview
                </h6>
                <div class="dropdown">
                    <button class="btn btn-sm btn-outline-primary dropdown-toggle" 
                            data-bs-toggle="dropdown">
                        Last 30 Days
                    </button>
                    <ul class="dropdown-menu">
                        <li><a class="dropdown-item" href="#" onclick="Reports.changePeriod(7)">Last 7 Days</a></li>
                        <li><a class="dropdown-item" href="#" onclick="Reports.changePeriod(30)">Last 30 Days</a></li>
                        <li><a class="dropdown-item" href="#" onclick="Reports.changePeriod(90)">Last 90 Days</a></li>
                        <li><a class="dropdown-item" href="#" onclick="Reports.changePeriod(365)">Last Year</a></li>
                    </ul>
                </div>
            </div>
            <div class="card-body">
                <canvas id="threatOverviewChart" height="100"></canvas>
            </div>
        </div>
    </div>
    
    <!-- Key Metrics -->
    <div class="col-xl-4">
        <div class="row">
            <!-- Total Analyzed -->
            <div class="col-12 mb-3">
                <div class="card bg-primary text-white shadow h-100">
                    <div class="card-body">
                        <div class="d-flex justify-content-between">
                            <div>
                                <div class="h5 mb-0" id="totalAnalyzedCount">0</div>
                                <div class="small">Total Analyzed</div>
                            </div>
                            <div>
                                <i class="fas fa-envelope fa-2x opacity-75"></i>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Threats Blocked -->
            <div class="col-12 mb-3">
                <div class="card bg-danger text-white shadow h-100">
                    <div class="card-body">
                        <div class="d-flex justify-content-between">
                            <div>
                                <div class="h5 mb-0" id="threatsBlockedCount">0</div>
                                <div class="small">Threats Blocked</div>
                            </div>
                            <div>
                                <i class="fas fa-shield-alt fa-2x opacity-75"></i>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Detection Rate -->
            <div class="col-12 mb-3">
                <div class="card bg-success text-white shadow h-100">
                    <div class="card-body">
                        <div class="d-flex justify-content-between">
                            <div>
                                <div class="h5 mb-0" id="detectionRate">0%</div>
                                <div class="small">Detection Rate</div>
                            </div>
                            <div>
                                <i class="fas fa-percentage fa-2x opacity-75"></i>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Detailed Analytics -->
<div class="row mb-4">
    <!-- Threat Types Distribution -->
    <div class="col-xl-6">
        <div class="card shadow mb-4">
            <div class="card-header py-3">
                <h6 class="m-0 fw-bold text-primary">
                    <i class="fas fa-chart-pie me-2"></i>Threat Types Distribution
                </h6>
            </div>
            <div class="card-body">
                <canvas id="threatTypesChart"></canvas>
                <div class="mt-3">
                    <div class="row small">
                        <div class="col-6">
                            <div class="d-flex align-items-center mb-2">
                                <div class="me-2" style="width: 12px; height: 12px; background-color: #dc3545;"></div>
                                <span>Phishing</span>
                            </div>
                            <div class="d-flex align-items-center mb-2">
                                <div class="me-2" style="width: 12px; height: 12px; background-color: #fd7e14;"></div>
                                <span>Malware</span>
                            </div>
                        </div>
                        <div class="col-6">
                            <div class="d-flex align-items-center mb-2">
                                <div class="me-2" style="width: 12px; height: 12px; background-color: #ffc107;"></div>
                                <span>Social Engineering</span>
                            </div>
                            <div class="d-flex align-items-center mb-2">
                                <div class="me-2" style="width: 12px; height: 12px; background-color: #6c757d;"></div>
                                <span>Other</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Top Threat Sources -->
    <div class="col-xl-6">
        <div class="card shadow mb-4">
            <div class="card-header py-3">
                <h6 class="m-0 fw-bold text-primary">
                    <i class="fas fa-exclamation-triangle me-2"></i>Top Threat Sources
                </h6>
            </div>
            <div class="card-body" style="max-height: 350px; overflow-y: auto;">
                <div id="topThreatSources">
                    <!-- Will be populated by JavaScript -->
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Recent Reports -->
<div class="row mb-4">
    <div class="col-12">
        <div class="card shadow">
            <div class="card-header py-3 d-flex justify-content-between align-items-center">
                <h6 class="m-0 fw-bold text-primary">
                    <i class="fas fa-file-alt me-2"></i>Recent Reports
                </h6>
                <button class="btn btn-sm btn-outline-danger" onclick="Reports.cleanupOldReports()">
                    <i class="fas fa-trash me-1"></i>Cleanup Old Reports
                </button>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-hover" id="recentReportsTable">
                        <thead class="table-light">
                            <tr>
                                <th>Report Name</th>
                                <th>Type</th>
                                <th>Generated</th>
                                <th>Format</th>
                                <th>Size</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="recentReportsBody">
                            <?php if (!empty($page_data['recent_reports'])): ?>
                                <?php foreach ($page_data['recent_reports'] as $report): ?>
                                <tr>
                                    <td>
                                        <i class="fas fa-file-alt me-2 text-primary"></i>
                                        <?php echo htmlspecialchars($report['filename']); ?>
                                    </td>
                                    <td>
                                        <?php
                                        $type = 'Unknown';
                                        if (strpos($report['filename'], 'summary') !== false) $type = 'Summary';
                                        elseif (strpos($report['filename'], 'detailed') !== false) $type = 'Detailed';
                                        elseif (strpos($report['filename'], 'trends') !== false) $type = 'Trends';
                                        elseif (strpos($report['filename'], 'quarantine') !== false) $type = 'Quarantine';
                                        echo $type;
                                        ?>
                                    </td>
                                    <td>
                                        <small><?php echo timeAgo($report['created_at']); ?></small>
                                    </td>
                                    <td>
                                        <span class="badge bg-secondary">
                                            <?php echo strtoupper($report['format']); ?>
                                        </span>
                                    </td>
                                    <td>
                                        <?php echo formatFileSize($report['file_size']); ?>
                                    </td>
                                    <td>
                                        <div class="btn-group btn-group-sm">
                                            <button class="btn btn-outline-primary" 
                                                    onclick="Reports.downloadReport('<?php echo htmlspecialchars($report['filename']); ?>')"
                                                    title="Download">
                                                <i class="fas fa-download"></i>
                                            </button>
                                            <button class="btn btn-outline-info" 
                                                    onclick="Reports.previewReport('<?php echo htmlspecialchars($report['filename']); ?>')"
                                                    title="Preview">
                                                <i class="fas fa-eye"></i>
                                            </button>
                                            <button class="btn btn-outline-danger" 
                                                    onclick="Reports.deleteReport('<?php echo htmlspecialchars($report['filename']); ?>')"
                                                    title="Delete">
                                                <i class="fas fa-trash"></i>
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            <?php else: ?>
                            <tr>
                                <td colspan="6" class="text-center text-muted py-4">
                                    <i class="fas fa-file-alt fa-2x mb-2"></i><br>
                                    No reports generated yet. Click "Generate Report" to create your first report.
                                </td>
                            </tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Generate Report Modal -->
<div class="modal fade" id="generateReportModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">
                    <i class="fas fa-chart-line me-2"></i>Generate Custom Report
                </h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <form id="customReportForm">
                    <div class="row">
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label for="reportType" class="form-label">Report Type</label>
                                <select class="form-select" id="reportType" name="report_type" required>
                                    <option value="">Select report type...</option>
                                    <option value="summary">Summary Report</option>
                                    <option value="detailed">Detailed Analysis</option>
                                    <option value="trends">Threat Trends</option>
                                    <option value="quarantine">Quarantine Report</option>
                                    <option value="sender_analysis">Sender Analysis</option>
                                </select>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label for="reportFormat" class="form-label">Export Format</label>
                                <select class="form-select" id="reportFormat" name="format">
                                    <option value="html">HTML</option>
                                    <option value="json">JSON</option>
                                    <option value="csv">CSV</option>
                                    <option value="txt">Plain Text</option>
                                </select>
                            </div>
                        </div>
                    </div>
                    
                    <div class="row">
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label for="dateRange" class="form-label">Date Range</label>
                                <select class="form-select" id="dateRange" name="date_range">
                                    <option value="7">Last 7 days</option>
                                    <option value="30" selected>Last 30 days</option>
                                    <option value="90">Last 90 days</option>
                                    <option value="365">Last year</option>
                                </select>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label for="reportName" class="form-label">Report Name (Optional)</label>
                                <input type="text" class="form-control" id="reportName" name="report_name" 
                                       placeholder="Custom report name">
                            </div>
                        </div>
                    </div>
                    
                    <div class="mb-3">
                        <label class="form-label">Include Sections</label>
                        <div class="row">
                            <div class="col-md-6">
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="includeStatistics" checked>
                                    <label class="form-check-label" for="includeStatistics">
                                        Statistics Summary
                                    </label>
                                </div>
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="includeTrends" checked>
                                    <label class="form-check-label" for="includeTrends">
                                        Trend Analysis
                                    </label>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="includeThreats" checked>
                                    <label class="form-check-label" for="includeThreats">
                                        Threat Details
                                    </label>
                                </div>
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="includeCharts">
                                    <label class="form-check-label" for="includeCharts">
                                        Charts & Graphs
                                    </label>
                                </div>
                            </div>
                        </div>
                    </div>
                </form>
                
                <div id="reportGenerationProgress" class="d-none">
                    <div class="progress mb-3">
                        <div class="progress-bar progress-bar-striped progress-bar-animated" 
                             role="progressbar" style="width: 0%"></div>
                    </div>
                    <div class="text-center">
                        <small class="text-muted">Generating report...</small>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                <button type="button" class="btn btn-primary" onclick="Reports.generateCustomReport()">
                    <i class="fas fa-cog me-1"></i>Generate Report
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Report Preview Modal -->
<div class="modal fade" id="reportPreviewModal" tabindex="-1">
    <div class="modal-dialog modal-fullscreen">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">
                    <i class="fas fa-eye me-2"></i>Report Preview
                </h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div id="reportPreviewContent">
                    <!-- Report content will be loaded here -->
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                <button type="button" class="btn btn-primary" id="downloadPreviewedReport">
                    <i class="fas fa-download me-1"></i>Download
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Reports-specific styles -->
<style>
.opacity-75 {
    opacity: 0.75;
}

.card.bg-primary .card-body,
.card.bg-danger .card-body,
.card.bg-success .card-body,
.card.bg-warning .card-body {
    color: white;
}

#threatOverviewChart {
    max-height: 400px;
}

#threatTypesChart {
    max-height: 250px;
}

.progress-bar-animated {
    animation: progress-bar-stripes 1s linear infinite;
}

@keyframes progress-bar-stripes {
    0% { background-position: 1rem 0; }
    100% { background-position: 0 0; }
}

.threat-source-item {
    border-left: 4px solid;
    padding: 10px;
    margin-bottom: 10px;
    background-color: rgba(0,0,0,0.05);
    border-radius: 0 5px 5px 0;
}

.threat-source-item.critical {
    border-left-color: #dc3545;
}

.threat-source-item.high {
    border-left-color: #fd7e14;
}

.threat-source-item.medium {
    border-left-color: #ffc107;
}

.threat-source-item.low {
    border-left-color: #6c757d;
}

@media (max-width: 768px) {
    .modal-fullscreen {
        width: 100vw;
        height: 100vh;
        margin: 0;
        border: 0;
        border-radius: 0;
    }
    
    .table-responsive {
        font-size: 0.875rem;
    }
    
    .btn-group-sm > .btn {
        padding: 0.25rem 0.5rem;
        font-size: 0.75rem;
    }
}
</style>
