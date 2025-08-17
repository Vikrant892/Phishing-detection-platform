<div class="email-analysis-container">
    <!-- Page Header -->
    <div class="d-flex justify-content-between align-items-center mb-4">
        <div>
            <h1 class="h3 mb-0">Email Analysis</h1>
            <p class="text-muted">Upload and analyze emails for phishing threats</p>
        </div>
        <div class="d-flex gap-2">
            <button class="btn btn-outline-secondary" onclick="viewHistory()">
                <i class="fas fa-history me-1"></i>
                Analysis History
            </button>
            <button class="btn btn-success" onclick="bulkAnalysis()">
                <i class="fas fa-layer-group me-1"></i>
                Bulk Analysis
            </button>
        </div>
    </div>

    <div class="row">
        <!-- Upload Section -->
        <div class="col-lg-8">
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0">
                        <i class="fas fa-upload me-2"></i>
                        Email Upload & Analysis
                    </h5>
                </div>
                <div class="card-body">
                    <!-- File Upload Area -->
                    <div class="upload-area" id="uploadArea">
                        <div class="upload-content text-center">
                            <i class="fas fa-cloud-upload-alt fa-3x text-primary mb-3"></i>
                            <h5>Drop email files here or click to browse</h5>
                            <p class="text-muted">Supported formats: .eml, .msg, .txt (Max 10MB)</p>
                            <input type="file" id="emailFileInput" accept=".eml,.msg,.txt" multiple style="display: none;">
                            <button class="btn btn-primary" onclick="document.getElementById('emailFileInput').click()">
                                <i class="fas fa-folder-open me-2"></i>
                                Browse Files
                            </button>
                        </div>
                    </div>

                    <!-- Selected Files -->
                    <div id="selectedFiles" class="mt-3" style="display: none;">
                        <h6>Selected Files:</h6>
                        <div id="filesList"></div>
                    </div>

                    <!-- Analysis Options -->
                    <div class="analysis-options mt-4">
                        <h6>Analysis Options:</h6>
                        <div class="row">
                            <div class="col-md-6">
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="useCustomRules" checked>
                                    <label class="form-check-label" for="useCustomRules">
                                        Use custom detection rules
                                    </label>
                                </div>
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="deepAnalysis" checked>
                                    <label class="form-check-label" for="deepAnalysis">
                                        Enable deep content analysis
                                    </label>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="autoQuarantine">
                                    <label class="form-check-label" for="autoQuarantine">
                                        Auto-quarantine critical threats
                                    </label>
                                </div>
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="generateReport" checked>
                                    <label class="form-check-label" for="generateReport">
                                        Generate detailed report
                                    </label>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Action Buttons -->
                    <div class="mt-4 d-flex gap-2">
                        <button class="btn btn-success" id="analyzeBtn" onclick="startAnalysis()" disabled>
                            <i class="fas fa-search me-2"></i>
                            Analyze Email(s)
                        </button>
                        <button class="btn btn-outline-secondary" onclick="clearSelection()">
                            <i class="fas fa-times me-2"></i>
                            Clear Selection
                        </button>
                    </div>

                    <!-- Progress Bar -->
                    <div id="analysisProgress" class="mt-3" style="display: none;">
                        <div class="d-flex justify-content-between align-items-center mb-2">
                            <span>Analysis Progress</span>
                            <span id="progressText">0%</span>
                        </div>
                        <div class="progress">
                            <div class="progress-bar progress-bar-striped progress-bar-animated" 
                                 id="progressBar" style="width: 0%"></div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Analysis Results -->
            <div id="analysisResults" class="mt-4" style="display: none;">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">
                            <i class="fas fa-chart-line me-2"></i>
                            Analysis Results
                        </h5>
                        <div class="btn-group btn-group-sm">
                            <button class="btn btn-outline-primary" onclick="exportResults('json')">
                                <i class="fas fa-download me-1"></i>
                                JSON
                            </button>
                            <button class="btn btn-outline-primary" onclick="exportResults('csv')">
                                <i class="fas fa-file-csv me-1"></i>
                                CSV
                            </button>
                            <button class="btn btn-outline-primary" onclick="exportResults('pdf')">
                                <i class="fas fa-file-pdf me-1"></i>
                                PDF
                            </button>
                        </div>
                    </div>
                    <div class="card-body">
                        <div id="resultsContent"></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Sidebar -->
        <div class="col-lg-4">
            <!-- Quick Stats -->
            <div class="card mb-3">
                <div class="card-header">
                    <h6 class="mb-0">Today's Activity</h6>
                </div>
                <div class="card-body">
                    <div class="stat-item d-flex justify-content-between mb-2">
                        <span>Emails Analyzed</span>
                        <span class="badge bg-primary" id="todayAnalyzed">-</span>
                    </div>
                    <div class="stat-item d-flex justify-content-between mb-2">
                        <span>Threats Found</span>
                        <span class="badge bg-danger" id="todayThreats">-</span>
                    </div>
                    <div class="stat-item d-flex justify-content-between mb-2">
                        <span>Quarantined</span>
                        <span class="badge bg-warning" id="todayQuarantined">-</span>
                    </div>
                    <div class="stat-item d-flex justify-content-between">
                        <span>Clean Emails</span>
                        <span class="badge bg-success" id="todayClean">-</span>
                    </div>
                </div>
            </div>

            <!-- Analysis Tips -->
            <div class="card mb-3">
                <div class="card-header">
                    <h6 class="mb-0">
                        <i class="fas fa-lightbulb me-2"></i>
                        Analysis Tips
                    </h6>
                </div>
                <div class="card-body">
                    <div class="tip-item mb-3">
                        <div class="fw-semibold text-success">
                            <i class="fas fa-check-circle me-2"></i>
                            Best Practices
                        </div>
                        <small class="text-muted">
                            • Upload original email files (.eml format preferred)<br>
                            • Enable deep analysis for comprehensive scanning<br>
                            • Review results before taking action
                        </small>
                    </div>
                    
                    <div class="tip-item mb-3">
                        <div class="fw-semibold text-warning">
                            <i class="fas fa-exclamation-triangle me-2"></i>
                            Watch For
                        </div>
                        <small class="text-muted">
                            • Suspicious sender domains<br>
                            • Urgent language patterns<br>
                            • Unexpected attachments<br>
                            • Link mismatches
                        </small>
                    </div>

                    <div class="tip-item">
                        <div class="fw-semibold text-info">
                            <i class="fas fa-info-circle me-2"></i>
                            File Limits
                        </div>
                        <small class="text-muted">
                            Maximum file size: 10MB<br>
                            Bulk analysis: Up to 50 files<br>
                            Supported formats: EML, MSG, TXT
                        </small>
                    </div>
                </div>
            </div>

            <!-- Recent Analysis -->
            <div class="card">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <h6 class="mb-0">Recent Analysis</h6>
                    <a href="?page=threat_history" class="btn btn-sm btn-outline-primary">
                        View All
                    </a>
                </div>
                <div class="card-body">
                    <div id="recentAnalysis">
                        <div class="text-center text-muted py-3">
                            <i class="fas fa-history fa-2x mb-2"></i>
                            <p>Loading recent analysis...</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Bulk Analysis Modal -->
<div class="modal fade" id="bulkAnalysisModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Bulk Email Analysis</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div class="mb-3">
                    <label for="bulkFiles" class="form-label">Select Multiple Email Files</label>
                    <input type="file" class="form-control" id="bulkFiles" multiple accept=".eml,.msg,.txt">
                    <div class="form-text">You can select up to 50 files at once (10MB each)</div>
                </div>
                
                <div class="mb-3">
                    <label class="form-label">Processing Options</label>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="bulkDeepAnalysis" checked>
                        <label class="form-check-label" for="bulkDeepAnalysis">
                            Enable deep analysis for all files
                        </label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="bulkAutoQuarantine">
                        <label class="form-check-label" for="bulkAutoQuarantine">
                            Auto-quarantine high-risk emails
                        </label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="bulkGenerateReport" checked>
                        <label class="form-check-label" for="bulkGenerateReport">
                            Generate summary report
                        </label>
                    </div>
                </div>

                <div id="bulkProgress" style="display: none;">
                    <div class="mb-2">
                        <div class="d-flex justify-content-between">
                            <span>Processing files...</span>
                            <span id="bulkProgressText">0/0</span>
                        </div>
                    </div>
                    <div class="progress mb-3">
                        <div class="progress-bar" id="bulkProgressBar" style="width: 0%"></div>
                    </div>
                    <div id="bulkCurrentFile" class="small text-muted"></div>
                </div>

                <div id="bulkResults" style="display: none;">
                    <h6>Bulk Analysis Results</h6>
                    <div id="bulkResultsContent"></div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                <button type="button" class="btn btn-primary" onclick="startBulkAnalysis()">
                    <i class="fas fa-play me-1"></i>
                    Start Bulk Analysis
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Result Details Modal -->
<div class="modal fade" id="resultDetailsModal" tabindex="-1">
    <div class="modal-dialog modal-xl">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Analysis Details</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div id="detailsContent">
                    <div class="text-center">
                        <div class="spinner-border" role="status"></div>
                        <p class="mt-2">Loading details...</p>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                <button type="button" class="btn btn-warning" onclick="quarantineFromDetails()">
                    <i class="fas fa-lock me-1"></i>
                    Quarantine
                </button>
                <button type="button" class="btn btn-primary" onclick="exportDetails()">
                    <i class="fas fa-download me-1"></i>
                    Export
                </button>
            </div>
        </div>
    </div>
</div>

<script>
// Initialize email analysis functionality
document.addEventListener('DOMContentLoaded', function() {
    initializeEmailAnalysis();
    loadRecentAnalysis();
    updateTodayStats();
});
</script>
