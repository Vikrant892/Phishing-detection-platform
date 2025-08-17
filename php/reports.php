<?php
/**
 * Reports and Analysis History page
 */

// Get filter parameters
$page = (int)($_GET['page'] ?? 1);
$riskLevel = $_GET['risk_level'] ?? null;
$searchQuery = $_GET['search'] ?? '';
$dateFrom = $_GET['date_from'] ?? '';
$dateTo = $_GET['date_to'] ?? '';

$analyses = [];
$totalCount = 0;
$pagination = [];
$error = null;

try {
    // Build API parameters
    $params = [
        'page' => $page,
        'per_page' => ITEMS_PER_PAGE
    ];
    
    if ($riskLevel) {
        $params['risk_level'] = $riskLevel;
    }
    
    if ($searchQuery) {
        // Use search endpoint
        $params['q'] = $searchQuery;
        $params['type'] = $_GET['search_type'] ?? 'all';
        $response = $apiClient->get('/search', $params);
    } else {
        // Use analysis history endpoint
        $response = $apiClient->get('/analysis-history', $params);
    }
    
    if ($response['success']) {
        $data = $response['data'];
        $analyses = $data['analyses'] ?? $data['results'] ?? [];
        $pagination = $data['pagination'] ?? [];
        $totalCount = $pagination['total'] ?? 0;
    } else {
        throw new Exception('Failed to fetch data');
    }
    
} catch (Exception $e) {
    $error = $e->getMessage();
}

// Handle export requests
if (isset($_GET['export'])) {
    try {
        $exportData = [
            'format' => $_GET['format'] ?? 'pdf',
            'date_from' => $dateFrom,
            'date_to' => $dateTo,
            'risk_levels' => $riskLevel ? [$riskLevel] : []
        ];
        
        $response = $apiClient->post('/export-report', $exportData);
        
        if ($response['success']) {
            // Redirect to download (in a real scenario, you'd handle file download)
            $successMessage = "Report export initiated. Check your downloads folder.";
        } else {
            throw new Exception('Export failed');
        }
        
    } catch (Exception $e) {
        $error = "Export failed: " . $e->getMessage();
    }
}
?>

<div class="container-fluid">
    <!-- Page Header -->
    <div class="row mb-4">
        <div class="col-12">
            <div class="d-flex justify-content-between align-items-center">
                <h1 class="h3 mb-0 text-gray-800">
                    <i class="fas fa-chart-bar me-2"></i>
                    Reports & Analysis History
                </h1>
                <div class="btn-group">
                    <button type="button" class="btn btn-primary dropdown-toggle" data-bs-toggle="dropdown">
                        <i class="fas fa-download me-1"></i>
                        Export Report
                    </button>
                    <ul class="dropdown-menu">
                        <li><a class="dropdown-item" href="#" onclick="exportReport('pdf')">
                            <i class="fas fa-file-pdf me-2"></i>PDF Report</a></li>
                        <li><a class="dropdown-item" href="#" onclick="exportReport('excel')">
                            <i class="fas fa-file-excel me-2"></i>Excel Report</a></li>
                        <li><a class="dropdown-item" href="#" onclick="exportReport('csv')">
                            <i class="fas fa-file-csv me-2"></i>CSV Export</a></li>
                    </ul>
                </div>
            </div>
        </div>
    </div>

    <?php if (isset($error)): ?>
    <div class="row mb-4">
        <div class="col-12">
            <div class="alert alert-danger alert-dismissible fade show">
                <i class="fas fa-exclamation-triangle me-2"></i>
                <?php echo htmlspecialchars($error); ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <?php if (isset($successMessage)): ?>
    <div class="row mb-4">
        <div class="col-12">
            <div class="alert alert-success alert-dismissible fade show">
                <i class="fas fa-check-circle me-2"></i>
                <?php echo htmlspecialchars($successMessage); ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <!-- Filters -->
    <div class="row mb-4">
        <div class="col-12">
            <div class="card shadow-sm">
                <div class="card-body">
                    <form method="GET" class="row g-3" id="filters-form">
                        <input type="hidden" name="page" value="reports">
                        
                        <div class="col-md-3">
                            <label for="search" class="form-label">Search</label>
                            <div class="input-group">
                                <input type="text" class="form-control" id="search" name="search" 
                                       placeholder="Search emails..." value="<?php echo htmlspecialchars($searchQuery); ?>">
                                <select class="form-select" name="search_type" style="max-width: 120px;">
                                    <option value="all" <?php echo ($_GET['search_type'] ?? 'all') === 'all' ? 'selected' : ''; ?>>All</option>
                                    <option value="subject" <?php echo ($_GET['search_type'] ?? '') === 'subject' ? 'selected' : ''; ?>>Subject</option>
                                    <option value="sender" <?php echo ($_GET['search_type'] ?? '') === 'sender' ? 'selected' : ''; ?>>Sender</option>
                                    <option value="content" <?php echo ($_GET['search_type'] ?? '') === 'content' ? 'selected' : ''; ?>>Content</option>
                                </select>
                            </div>
                        </div>
                        
                        <div class="col-md-2">
                            <label for="risk_level" class="form-label">Risk Level</label>
                            <select class="form-select" id="risk_level" name="risk_level">
                                <option value="">All Levels</option>
                                <option value="HIGH" <?php echo $riskLevel === 'HIGH' ? 'selected' : ''; ?>>High Risk</option>
                                <option value="MEDIUM" <?php echo $riskLevel === 'MEDIUM' ? 'selected' : ''; ?>>Medium Risk</option>
                                <option value="LOW" <?php echo $riskLevel === 'LOW' ? 'selected' : ''; ?>>Low Risk</option>
                            </select>
                        </div>
                        
                        <div class="col-md-2">
                            <label for="date_from" class="form-label">From Date</label>
                            <input type="date" class="form-control" id="date_from" name="date_from" 
                                   value="<?php echo htmlspecialchars($dateFrom); ?>">
                        </div>
                        
                        <div class="col-md-2">
                            <label for="date_to" class="form-label">To Date</label>
                            <input type="date" class="form-control" id="date_to" name="date_to" 
                                   value="<?php echo htmlspecialchars($dateTo); ?>">
                        </div>
                        
                        <div class="col-md-3 d-flex align-items-end">
                            <div class="btn-group w-100">
                                <button type="submit" class="btn btn-primary">
                                    <i class="fas fa-search me-1"></i>
                                    Apply Filters
                                </button>
                                <a href="index.php?page=reports" class="btn btn-outline-secondary">
                                    <i class="fas fa-times me-1"></i>
                                    Clear
                                </a>
                            </div>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <!-- Analysis Summary -->
    <div class="row mb-4">
        <div class="col-md-3">
            <div class="card border-left-primary shadow h-100 py-2">
                <div class="card-body">
                    <div class="row no-gutters align-items-center">
                        <div class="col mr-2">
                            <div class="text-xs font-weight-bold text-primary text-uppercase mb-1">
                                Total Results
                            </div>
                            <div class="h5 mb-0 font-weight-bold text-gray-800">
                                <?php echo number_format($totalCount); ?>
                            </div>
                        </div>
                        <div class="col-auto">
                            <i class="fas fa-list fa-2x text-gray-300"></i>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="col-md-3">
            <div class="card border-left-danger shadow h-100 py-2">
                <div class="card-body">
                    <div class="row no-gutters align-items-center">
                        <div class="col mr-2">
                            <div class="text-xs font-weight-bold text-danger text-uppercase mb-1">
                                High Risk
                            </div>
                            <div class="h5 mb-0 font-weight-bold text-gray-800" id="high-risk-summary">
                                <?php 
                                $highRiskCount = array_filter($analyses, function($a) { 
                                    return $a['risk_level'] === 'HIGH'; 
                                });
                                echo count($highRiskCount);
                                ?>
                            </div>
                        </div>
                        <div class="col-auto">
                            <i class="fas fa-exclamation-triangle fa-2x text-gray-300"></i>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="col-md-3">
            <div class="card border-left-warning shadow h-100 py-2">
                <div class="card-body">
                    <div class="row no-gutters align-items-center">
                        <div class="col mr-2">
                            <div class="text-xs font-weight-bold text-warning text-uppercase mb-1">
                                Medium Risk
                            </div>
                            <div class="h5 mb-0 font-weight-bold text-gray-800" id="medium-risk-summary">
                                <?php 
                                $mediumRiskCount = array_filter($analyses, function($a) { 
                                    return $a['risk_level'] === 'MEDIUM'; 
                                });
                                echo count($mediumRiskCount);
                                ?>
                            </div>
                        </div>
                        <div class="col-auto">
                            <i class="fas fa-exclamation-circle fa-2x text-gray-300"></i>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="col-md-3">
            <div class="card border-left-info shadow h-100 py-2">
                <div class="card-body">
                    <div class="row no-gutters align-items-center">
                        <div class="col mr-2">
                            <div class="text-xs font-weight-bold text-info text-uppercase mb-1">
                                Quarantined
                            </div>
                            <div class="h5 mb-0 font-weight-bold text-gray-800" id="quarantined-summary">
                                <?php 
                                $quarantinedCount = array_filter($analyses, function($a) { 
                                    return $a['is_quarantined'] ?? false; 
                                });
                                echo count($quarantinedCount);
                                ?>
                            </div>
                        </div>
                        <div class="col-auto">
                            <i class="fas fa-lock fa-2x text-gray-300"></i>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Analysis Results -->
    <div class="row">
        <div class="col-12">
            <div class="card shadow">
                <div class="card-header">
                    <div class="d-flex justify-content-between align-items-center">
                        <h6 class="m-0 font-weight-bold text-primary">
                            Analysis Results
                            <?php if ($searchQuery): ?>
                            <span class="text-muted">- Search: "<?php echo htmlspecialchars($searchQuery); ?>"</span>
                            <?php endif; ?>
                        </h6>
                        <div class="d-flex gap-2">
                            <select id="bulk-action" class="form-select form-select-sm" style="width: auto;">
                                <option value="">Bulk Actions</option>
                                <option value="quarantine">Quarantine Selected</option>
                                <option value="export">Export Selected</option>
                            </select>
                            <button class="btn btn-sm btn-primary" onclick="executeBulkAction()">
                                <i class="fas fa-play me-1"></i>
                                Execute
                            </button>
                        </div>
                    </div>
                </div>
                <div class="card-body p-0">
                    <?php if (empty($analyses)): ?>
                    <div class="text-center py-5">
                        <i class="fas fa-inbox fa-3x text-gray-300 mb-3"></i>
                        <h5 class="text-muted">No analyses found</h5>
                        <p class="text-muted">Try adjusting your filters or search criteria.</p>
                        <a href="index.php?page=upload" class="btn btn-primary">
                            <i class="fas fa-upload me-1"></i>
                            Analyze New Email
                        </a>
                    </div>
                    <?php else: ?>
                    <div class="table-responsive">
                        <table class="table table-hover mb-0">
                            <thead class="bg-light">
                                <tr>
                                    <th>
                                        <div class="form-check">
                                            <input class="form-check-input" type="checkbox" id="select-all" 
                                                   onchange="toggleAllCheckboxes(this)">
                                        </div>
                                    </th>
                                    <th>Date</th>
                                    <th>Subject</th>
                                    <th>Sender</th>
                                    <th>Risk Level</th>
                                    <th>Threat Score</th>
                                    <th>Threats</th>
                                    <th>Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($analyses as $analysis): ?>
                                <?php 
                                $threatScore = formatThreatScore($analysis['threat_score']); 
                                $isQuarantined = $analysis['is_quarantined'] ?? false;
                                ?>
                                <tr class="<?php echo $threatScore['score'] >= 70 ? 'table-danger' : ''; ?>">
                                    <td>
                                        <div class="form-check">
                                            <input class="form-check-input analysis-checkbox" type="checkbox" 
                                                   value="<?php echo $analysis['analysis_id']; ?>">
                                        </div>
                                    </td>
                                    <td>
                                        <small><?php echo formatDateTime($analysis['created_at']); ?></small>
                                    </td>
                                    <td>
                                        <div class="text-truncate" style="max-width: 250px;" 
                                             title="<?php echo htmlspecialchars($analysis['email_subject']); ?>">
                                            <?php echo htmlspecialchars($analysis['email_subject']); ?>
                                        </div>
                                    </td>
                                    <td>
                                        <div class="text-truncate" style="max-width: 200px;" 
                                             title="<?php echo htmlspecialchars($analysis['email_sender']); ?>">
                                            <?php echo htmlspecialchars($analysis['email_sender']); ?>
                                        </div>
                                    </td>
                                    <td>
                                        <span class="badge bg-<?php echo $threatScore['class']; ?>">
                                            <?php echo $threatScore['level']; ?>
                                        </span>
                                    </td>
                                    <td>
                                        <div class="d-flex align-items-center">
                                            <div class="progress me-2" style="width: 60px; height: 16px;">
                                                <div class="progress-bar bg-<?php echo $threatScore['class']; ?>" 
                                                     style="width: <?php echo $threatScore['percentage']; ?>%"></div>
                                            </div>
                                            <small class="fw-bold"><?php echo $threatScore['score']; ?>%</small>
                                        </div>
                                    </td>
                                    <td>
                                        <span class="badge bg-<?php echo $analysis['threats_found'] > 0 ? 'danger' : 'success'; ?>">
                                            <?php echo $analysis['threats_found']; ?>
                                        </span>
                                    </td>
                                    <td>
                                        <?php if ($isQuarantined): ?>
                                        <span class="badge bg-warning">
                                            <i class="fas fa-lock me-1"></i>
                                            Quarantined
                                        </span>
                                        <?php else: ?>
                                        <span class="badge bg-success">Active</span>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <div class="btn-group btn-group-sm">
                                            <button class="btn btn-outline-primary" 
                                                    onclick="viewAnalysisDetails('<?php echo $analysis['analysis_id']; ?>')" 
                                                    title="View Details">
                                                <i class="fas fa-eye"></i>
                                            </button>
                                            <?php if (!$isQuarantined && $analysis['threat_score'] >= 40): ?>
                                            <button class="btn btn-outline-warning" 
                                                    onclick="quarantineEmail('<?php echo $analysis['analysis_id']; ?>')" 
                                                    title="Quarantine">
                                                <i class="fas fa-lock"></i>
                                            </button>
                                            <?php endif; ?>
                                            <button class="btn btn-outline-secondary" 
                                                    onclick="exportAnalysis('<?php echo $analysis['analysis_id']; ?>')" 
                                                    title="Export">
                                                <i class="fas fa-download"></i>
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                    
                    <!-- Pagination -->
                    <?php if ($pagination['pages'] > 1): ?>
                    <div class="card-footer">
                        <div class="d-flex justify-content-between align-items-center">
                            <div class="text-muted">
                                Showing <?php echo (($pagination['page'] - 1) * $pagination['per_page'] + 1); ?> 
                                to <?php echo min($pagination['page'] * $pagination['per_page'], $pagination['total']); ?> 
                                of <?php echo number_format($pagination['total']); ?> results
                            </div>
                            
                            <nav>
                                <ul class="pagination pagination-sm mb-0">
                                    <?php
                                    $currentPage = $pagination['page'];
                                    $totalPages = $pagination['pages'];
                                    $queryParams = $_GET;
                                    
                                    // Previous page
                                    if ($currentPage > 1):
                                        $queryParams['page'] = $currentPage - 1;
                                        $prevUrl = 'index.php?' . http_build_query($queryParams);
                                    ?>
                                    <li class="page-item">
                                        <a class="page-link" href="<?php echo $prevUrl; ?>">Previous</a>
                                    </li>
                                    <?php endif; ?>
                                    
                                    <?php
                                    // Page numbers
                                    $startPage = max(1, $currentPage - 2);
                                    $endPage = min($totalPages, $currentPage + 2);
                                    
                                    for ($i = $startPage; $i <= $endPage; $i++):
                                        $queryParams['page'] = $i;
                                        $pageUrl = 'index.php?' . http_build_query($queryParams);
                                    ?>
                                    <li class="page-item <?php echo $i === $currentPage ? 'active' : ''; ?>">
                                        <a class="page-link" href="<?php echo $pageUrl; ?>"><?php echo $i; ?></a>
                                    </li>
                                    <?php endfor; ?>
                                    
                                    <?php
                                    // Next page
                                    if ($currentPage < $totalPages):
                                        $queryParams['page'] = $currentPage + 1;
                                        $nextUrl = 'index.php?' . http_build_query($queryParams);
                                    ?>
                                    <li class="page-item">
                                        <a class="page-link" href="<?php echo $nextUrl; ?>">Next</a>
                                    </li>
                                    <?php endif; ?>
                                </ul>
                            </nav>
                        </div>
                    </div>
                    <?php endif; ?>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Export Modal -->
<div class="modal fade" id="exportModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Export Report</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <form id="export-form">
                    <div class="mb-3">
                        <label for="export-format" class="form-label">Format</label>
                        <select class="form-select" id="export-format" name="format" required>
                            <option value="pdf">PDF Report</option>
                            <option value="excel">Excel Spreadsheet</option>
                            <option value="csv">CSV Export</option>
                        </select>
                    </div>
                    <div class="mb-3">
                        <label for="export-date-from" class="form-label">From Date</label>
                        <input type="date" class="form-control" id="export-date-from" name="date_from">
                    </div>
                    <div class="mb-3">
                        <label for="export-date-to" class="form-label">To Date</label>
                        <input type="date" class="form-control" id="export-date-to" name="date_to">
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Risk Levels</label>
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" id="export-high" value="HIGH">
                            <label class="form-check-label" for="export-high">High Risk</label>
                        </div>
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" id="export-medium" value="MEDIUM">
                            <label class="form-check-label" for="export-medium">Medium Risk</label>
                        </div>
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" id="export-low" value="LOW">
                            <label class="form-check-label" for="export-low">Low Risk</label>
                        </div>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                <button type="button" class="btn btn-primary" onclick="processExport()">
                    <i class="fas fa-download me-1"></i>
                    Export
                </button>
            </div>
        </div>
    </div>
</div>

<script>
function exportReport(format) {
    document.getElementById('export-format').value = format;
    const modal = new bootstrap.Modal(document.getElementById('exportModal'));
    modal.show();
}

function processExport() {
    const form = document.getElementById('export-form');
    const formData = new FormData(form);
    
    // Get selected risk levels
    const riskLevels = [];
    document.querySelectorAll('input[type="checkbox"]:checked').forEach(cb => {
        if (cb.value && ['HIGH', 'MEDIUM', 'LOW'].includes(cb.value)) {
            riskLevels.push(cb.value);
        }
    });
    
    const exportData = {
        format: formData.get('format'),
        date_from: formData.get('date_from'),
        date_to: formData.get('date_to'),
        risk_levels: riskLevels
    };
    
    fetch('api.php?action=export-report', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(exportData)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showAlert('success', 'Report export initiated successfully');
            bootstrap.Modal.getInstance(document.getElementById('exportModal')).hide();
        } else {
            showAlert('danger', 'Export failed: ' + data.error);
        }
    })
    .catch(error => {
        showAlert('danger', 'Export request failed');
    });
}

function toggleAllCheckboxes(masterCheckbox) {
    const checkboxes = document.querySelectorAll('.analysis-checkbox');
    checkboxes.forEach(cb => cb.checked = masterCheckbox.checked);
}

function executeBulkAction() {
    const action = document.getElementById('bulk-action').value;
    if (!action) return;
    
    const selected = Array.from(document.querySelectorAll('.analysis-checkbox:checked'))
                         .map(cb => cb.value);
    
    if (selected.length === 0) {
        showAlert('warning', 'Please select at least one analysis');
        return;
    }
    
    if (action === 'quarantine') {
        if (confirm(`Quarantine ${selected.length} selected emails?`)) {
            // Process quarantine for selected items
            selected.forEach(id => quarantineEmail(id));
        }
    } else if (action === 'export') {
        // Export selected items
        exportSelected(selected);
    }
}

function viewAnalysisDetails(analysisId) {
    // In a real application, this would open a detailed view modal
    window.open(`analysis-details.php?id=${analysisId}`, '_blank');
}
</script>
