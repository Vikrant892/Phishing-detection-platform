<!-- Email Analysis Page -->
<div class="row mb-4">
    <div class="col-12">
        <div class="d-flex justify-content-between align-items-center">
            <h1 class="h3 mb-0">
                <i class="fas fa-search me-2 text-primary"></i>
                Email Analysis
            </h1>
            <div class="d-flex gap-2">
                <button class="btn btn-outline-primary btn-sm" onclick="Analysis.refreshHistory()">
                    <i class="fas fa-sync-alt me-1"></i>Refresh
                </button>
                <button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#batchUploadModal">
                    <i class="fas fa-layer-group me-1"></i>Batch Upload
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Upload Section -->
<div class="row mb-4">
    <div class="col-12">
        <div class="card shadow">
            <div class="card-header py-3">
                <h6 class="m-0 fw-bold text-primary">
                    <i class="fas fa-upload me-2"></i>Upload Email for Analysis
                </h6>
            </div>
            <div class="card-body">
                <!-- Upload Form -->
                <form id="emailUploadForm" enctype="multipart/form-data">
                    <div class="row">
                        <div class="col-lg-8">
                            <div class="mb-3">
                                <label for="emailFile" class="form-label">
                                    Select Email File
                                    <span class="text-muted">
                                        (<?php echo implode(', ', $page_data['supported_types'] ?? ['.eml', '.msg', '.txt']); ?>)
                                    </span>
                                </label>
                                <input type="file" class="form-control" id="emailFile" name="email_file" 
                                       accept="<?php echo implode(',', $page_data['supported_types'] ?? ['.eml', '.msg', '.txt']); ?>"
                                       required>
                                <div class="form-text">
                                    Maximum file size: <?php echo formatFileSize(MAX_FILE_SIZE); ?>
                                </div>
                            </div>
                        </div>
                        <div class="col-lg-4">
                            <div class="mb-3">
                                <label class="form-label">Analysis Options</label>
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="deepAnalysis" checked>
                                    <label class="form-check-label" for="deepAnalysis">
                                        Deep Analysis
                                    </label>
                                </div>
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="attachmentScan" checked>
                                    <label class="form-check-label" for="attachmentScan">
                                        Scan Attachments
                                    </label>
                                </div>
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="urlAnalysis" checked>
                                    <label class="form-check-label" for="urlAnalysis">
                                        URL Analysis
                                    </label>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Drag and Drop Area -->
                    <div class="mb-3">
                        <div class="border-dashed border-2 border-primary p-4 text-center" 
                             id="dropZone" 
                             ondrop="Analysis.handleDrop(event)" 
                             ondragover="Analysis.handleDragOver(event)"
                             ondragleave="Analysis.handleDragLeave(event)">
                            <i class="fas fa-cloud-upload-alt fa-3x text-primary mb-3"></i>
                            <h5>Drag and drop your email file here</h5>
                            <p class="text-muted">or click the browse button above to select a file</p>
                        </div>
                    </div>
                    
                    <!-- Submit Button -->
                    <div class="d-flex justify-content-between align-items-center">
                        <div class="form-text">
                            <i class="fas fa-info-circle me-1"></i>
                            Analysis typically takes 30-60 seconds per email
                        </div>
                        <button type="submit" class="btn btn-primary" id="analyzeBtn">
                            <i class="fas fa-search me-2"></i>Analyze Email
                        </button>
                    </div>
                </form>
                
                <!-- Upload Result -->
                <div id="uploadResult" class="mt-3" style="display: none;"></div>
            </div>
        </div>
    </div>
</div>

<!-- Quick Analysis Section -->
<div class="row mb-4">
    <div class="col-12">
        <div class="card shadow">
            <div class="card-header py-3">
                <h6 class="m-0 fw-bold text-primary">
                    <i class="fas fa-bolt me-2"></i>Quick Content Analysis
                </h6>
            </div>
            <div class="card-body">
                <form id="contentAnalysisForm">
                    <div class="mb-3">
                        <label for="emailContent" class="form-label">Paste Email Content</label>
                        <textarea class="form-control" id="emailContent" name="content" 
                                  rows="8" placeholder="Paste raw email content here..."></textarea>
                    </div>
                    <div class="row">
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label for="contentType" class="form-label">Content Type</label>
                                <select class="form-select" id="contentType" name="content_type">
                                    <option value="eml">EML Format</option>
                                    <option value="txt">Plain Text</option>
                                </select>
                            </div>
                        </div>
                        <div class="col-md-6 d-flex align-items-end">
                            <button type="submit" class="btn btn-outline-primary">
                                <i class="fas fa-search me-2"></i>Analyze Content
                            </button>
                        </div>
                    </div>
                </form>
            </div>
        </div>
    </div>
</div>

<!-- Analysis History -->
<div class="row mb-4">
    <div class="col-12">
        <div class="card shadow">
            <div class="card-header py-3 d-flex justify-content-between align-items-center">
                <h6 class="m-0 fw-bold text-primary">
                    <i class="fas fa-history me-2"></i>Analysis History
                </h6>
                <div class="d-flex gap-2">
                    <div class="input-group input-group-sm" style="width: 250px;">
                        <input type="text" class="form-control" id="historySearch" 
                               placeholder="Search by sender, subject...">
                        <button class="btn btn-outline-secondary" onclick="Analysis.searchHistory()">
                            <i class="fas fa-search"></i>
                        </button>
                    </div>
                    <div class="dropdown">
                        <button class="btn btn-sm btn-outline-secondary dropdown-toggle" 
                                data-bs-toggle="dropdown">
                            <i class="fas fa-filter me-1"></i>Filter
                        </button>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="#" onclick="Analysis.filterHistory('all')">All Results</a></li>
                            <li><a class="dropdown-item" href="#" onclick="Analysis.filterHistory('critical')">Critical Threats</a></li>
                            <li><a class="dropdown-item" href="#" onclick="Analysis.filterHistory('high')">High Risk</a></li>
                            <li><a class="dropdown-item" href="#" onclick="Analysis.filterHistory('quarantined')">Quarantined</a></li>
                        </ul>
                    </div>
                </div>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-hover" id="analysisHistoryTable">
                        <thead class="table-light">
                            <tr>
                                <th>Date</th>
                                <th>File</th>
                                <th>Sender</th>
                                <th>Subject</th>
                                <th>Risk Score</th>
                                <th>Threat Level</th>
                                <th>Status</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="analysisHistoryBody">
                            <?php if (!empty($page_data['analysis_history'])): ?>
                                <?php foreach ($page_data['analysis_history'] as $analysis): ?>
                                <tr data-email-hash="<?php echo htmlspecialchars($analysis['email_hash']); ?>">
                                    <td>
                                        <small><?php echo formatTimestamp($analysis['analysis_timestamp'], 'M j, H:i'); ?></small>
                                    </td>
                                    <td>
                                        <div class="text-truncate" style="max-width: 120px;">
                                            <?php 
                                            $filename = $analysis['original_filename'] ?? $analysis['source_file'] ?? 'Unknown';
                                            echo htmlspecialchars(truncateText($filename, 20));
                                            ?>
                                        </div>
                                    </td>
                                    <td>
                                        <div class="text-truncate" style="max-width: 150px;" 
                                             title="<?php echo htmlspecialchars($analysis['sender']); ?>">
                                            <?php echo htmlspecialchars(truncateText($analysis['sender'], 25)); ?>
                                        </div>
                                    </td>
                                    <td>
                                        <div class="text-truncate" style="max-width: 200px;" 
                                             title="<?php echo htmlspecialchars($analysis['subject']); ?>">
                                            <?php echo htmlspecialchars(truncateText($analysis['subject'], 30)); ?>
                                        </div>
                                    </td>
                                    <td>
                                        <span class="badge bg-<?php echo getRiskScoreClass($analysis['risk_score']); ?>">
                                            <?php echo round($analysis['risk_score'], 1); ?>
                                        </span>
                                    </td>
                                    <td>
                                        <span class="badge bg-<?php echo getThreatLevelClass($analysis['threat_level']); ?>">
                                            <?php echo ucfirst($analysis['threat_level']); ?>
                                        </span>
                                    </td>
                                    <td>
                                        <?php if ($analysis['is_quarantined']): ?>
                                        <span class="badge bg-warning">
                                            <i class="fas fa-ban me-1"></i>Quarantined
                                        </span>
                                        <?php else: ?>
                                        <span class="badge bg-success">
                                            <i class="fas fa-check me-1"></i>Active
                                        </span>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <div class="btn-group btn-group-sm">
                                            <button class="btn btn-outline-primary" 
                                                    onclick="Analysis.viewDetails('<?php echo $analysis['email_hash']; ?>')"
                                                    title="View Details">
                                                <i class="fas fa-eye"></i>
                                            </button>
                                            <button class="btn btn-outline-info" 
                                                    onclick="Analysis.exportAnalysis('<?php echo $analysis['email_hash']; ?>')"
                                                    title="Export">
                                                <i class="fas fa-download"></i>
                                            </button>
                                            <?php if (!$analysis['is_quarantined'] && $analysis['risk_score'] >= 40): ?>
                                            <button class="btn btn-outline-warning" 
                                                    onclick="Analysis.quarantine('<?php echo $analysis['email_hash']; ?>')"
                                                    title="Quarantine">
                                                <i class="fas fa-ban"></i>
                                            </button>
                                            <?php endif; ?>
                                        </div>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            <?php else: ?>
                            <tr>
                                <td colspan="8" class="text-center text-muted py-4">
                                    <i class="fas fa-search fa-2x mb-2"></i><br>
                                    No analysis results yet. Upload an email to get started.
                                </td>
                            </tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
                
                <!-- Pagination -->
                <nav aria-label="Analysis history pagination" class="mt-3">
                    <ul class="pagination justify-content-center" id="historyPagination">
                        <!-- Pagination will be populated by JavaScript -->
                    </ul>
                </nav>
            </div>
        </div>
    </div>
</div>

<!-- Batch Upload Modal -->
<div class="modal fade" id="batchUploadModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">
                    <i class="fas fa-layer-group me-2"></i>Batch Upload
                </h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <form id="batchUploadForm" enctype="multipart/form-data">
                    <div class="mb-3">
                        <label for="batchFiles" class="form-label">Select Multiple Email Files</label>
                        <input type="file" class="form-control" id="batchFiles" name="files[]" 
                               multiple accept=".eml,.msg,.txt,.mbox">
                        <div class="form-text">
                            You can select multiple email files or upload a ZIP archive containing email files.
                        </div>
                    </div>
                    
                    <div class="mb-3">
                        <label for="archiveFile" class="form-label">Or Upload Archive</label>
                        <input type="file" class="form-control" id="archiveFile" name="archive" 
                               accept=".zip,.rar,.7z">
                        <div class="form-text">
                            Upload a ZIP, RAR, or 7Z file containing email files.
                        </div>
                    </div>
                    
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle me-2"></i>
                        <strong>Batch Processing:</strong> Large batches may take several minutes to complete. 
                        You'll be notified when processing is finished.
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                <button type="button" class="btn btn-primary" onclick="Analysis.startBatchUpload()">
                    <i class="fas fa-upload me-1"></i>Start Batch Upload
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Analysis-specific styles -->
<style>
.border-dashed {
    border-style: dashed !important;
}

#dropZone {
    transition: all 0.3s ease;
    cursor: pointer;
}

#dropZone:hover,
#dropZone.dragover {
    background-color: rgba(0, 123, 255, 0.1);
    border-color: #0056b3 !important;
}

.table-responsive {
    max-height: 600px;
}

.risk-score-bar {
    height: 4px;
    border-radius: 2px;
    overflow: hidden;
}

.threat-indicator {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    display: inline-block;
    margin-right: 5px;
}

.threat-indicator.critical { background-color: #dc3545; }
.threat-indicator.high { background-color: #fd7e14; }
.threat-indicator.medium { background-color: #ffc107; }
.threat-indicator.low { background-color: #6c757d; }
.threat-indicator.minimal { background-color: #28a745; }

@media (max-width: 768px) {
    .table-responsive {
        font-size: 0.875rem;
    }
    
    .btn-group-sm > .btn, .btn-sm {
        padding: 0.25rem 0.5rem;
        font-size: 0.75rem;
    }
    
    .text-truncate {
        max-width: 100px !important;
    }
}

/* Upload progress styling */
.upload-progress {
    background: linear-gradient(45deg, #007bff, #0056b3);
    animation: progress-animation 2s linear infinite;
}

@keyframes progress-animation {
    0% { background-position: 0 0; }
    100% { background-position: 40px 40px; }
}
</style>
