<?php
/**
 * Settings page for threat patterns and system configuration
 */

$threatPatterns = [];
$error = null;
$success = null;

// Load threat patterns
try {
    $response = $apiClient->get('/threat-patterns');
    if ($response['success']) {
        $threatPatterns = $response['data']['patterns'] ?? [];
    }
} catch (Exception $e) {
    $error = "Failed to load threat patterns: " . $e->getMessage();
}

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        if (!verifyCsrfToken($_POST['csrf_token'])) {
            throw new Exception('Invalid CSRF token');
        }
        
        $action = $_POST['action'] ?? '';
        
        switch ($action) {
            case 'add_pattern':
                $patternData = [
                    'segment_start' => sanitizeInput($_POST['segment_start']),
                    'segment_end' => sanitizeInput($_POST['segment_end']),
                    'pattern' => sanitizeInput($_POST['pattern']),
                    'description' => sanitizeInput($_POST['description']),
                    'severity' => sanitizeInput($_POST['severity'])
                ];
                
                $response = $apiClient->post('/threat-patterns', $patternData);
                
                if (!$response['success']) {
                    throw new Exception('Failed to add pattern: ' . ($response['data']['error'] ?? 'Unknown error'));
                }
                
                $success = "Threat pattern added successfully";
                logActivity('PATTERN_ADD', 'Pattern: ' . $patternData['pattern']);
                
                // Reload patterns
                $response = $apiClient->get('/threat-patterns');
                if ($response['success']) {
                    $threatPatterns = $response['data']['patterns'] ?? [];
                }
                break;
                
            case 'upload_setup':
                if (!isset($_FILES['setup_file'])) {
                    throw new Exception('No file uploaded');
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
                    $response = $apiClient->postFile('/upload-setup', ['file' => $tempPath]);
                    
                    if (file_exists($tempPath)) {
                        unlink($tempPath);
                    }
                    
                    if (!$response['success']) {
                        throw new Exception('Setup file processing failed: ' . ($response['data']['error'] ?? 'Unknown error'));
                    }
                    
                    $success = "Setup file processed successfully. " . ($response['data']['patterns_count'] ?? 0) . " patterns added.";
                    logActivity('SETUP_UPLOAD', 'File: ' . $file['name']);
                    
                    // Reload patterns
                    $response = $apiClient->get('/threat-patterns');
                    if ($response['success']) {
                        $threatPatterns = $response['data']['patterns'] ?? [];
                    }
                    
                } catch (Exception $e) {
                    if (file_exists($tempPath)) {
                        unlink($tempPath);
                    }
                    throw $e;
                }
                break;
        }
    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}
?>

<div class="container-fluid">
    <!-- Page Header -->
    <div class="row mb-4">
        <div class="col-12">
            <div class="d-flex justify-content-between align-items-center">
                <h1 class="h3 mb-0 text-gray-800">
                    <i class="fas fa-cog me-2"></i>
                    System Settings
                </h1>
                <nav aria-label="breadcrumb">
                    <ol class="breadcrumb">
                        <li class="breadcrumb-item"><a href="index.php">Dashboard</a></li>
                        <li class="breadcrumb-item active">Settings</li>
                    </ol>
                </nav>
            </div>
        </div>
    </div>

    <?php if ($error): ?>
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

    <?php if ($success): ?>
    <div class="row mb-4">
        <div class="col-12">
            <div class="alert alert-success alert-dismissible fade show">
                <i class="fas fa-check-circle me-2"></i>
                <?php echo htmlspecialchars($success); ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <!-- Settings Tabs -->
    <div class="row">
        <div class="col-12">
            <ul class="nav nav-tabs" id="settingsTabs" role="tablist">
                <li class="nav-item" role="presentation">
                    <button class="nav-link active" id="patterns-tab" data-bs-toggle="tab" 
                            data-bs-target="#patterns" type="button" role="tab">
                        <i class="fas fa-search me-1"></i>
                        Threat Patterns
                    </button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="setup-tab" data-bs-toggle="tab" 
                            data-bs-target="#setup" type="button" role="tab">
                        <i class="fas fa-upload me-1"></i>
                        Setup Files
                    </button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="system-tab" data-bs-toggle="tab" 
                            data-bs-target="#system" type="button" role="tab">
                        <i class="fas fa-server me-1"></i>
                        System Config
                    </button>
                </li>
            </ul>

            <div class="tab-content" id="settingsTabContent">
                <!-- Threat Patterns Tab -->
                <div class="tab-pane fade show active" id="patterns" role="tabpanel">
                    <div class="row mt-4">
                        <!-- Add Pattern Form -->
                        <div class="col-lg-4 mb-4">
                            <div class="card shadow">
                                <div class="card-header">
                                    <h6 class="m-0 font-weight-bold text-primary">Add New Threat Pattern</h6>
                                </div>
                                <div class="card-body">
                                    <form method="post" id="add-pattern-form">
                                        <input type="hidden" name="action" value="add_pattern">
                                        <input type="hidden" name="csrf_token" value="<?php echo generateCsrfToken(); ?>">
                                        
                                        <div class="mb-3">
                                            <label for="segment_start" class="form-label">Segment Start</label>
                                            <input type="text" class="form-control" id="segment_start" 
                                                   name="segment_start" placeholder="<body" required>
                                            <div class="form-text">HTML tag where pattern search begins</div>
                                        </div>
                                        
                                        <div class="mb-3">
                                            <label for="segment_end" class="form-label">Segment End</label>
                                            <input type="text" class="form-control" id="segment_end" 
                                                   name="segment_end" placeholder="</body>" required>
                                            <div class="form-text">HTML tag where pattern search ends</div>
                                        </div>
                                        
                                        <div class="mb-3">
                                            <label for="pattern" class="form-label">Pattern</label>
                                            <input type="text" class="form-control" id="pattern" 
                                                   name="pattern" placeholder="suspicious phrase" required>
                                            <div class="form-text">Text pattern to detect</div>
                                        </div>
                                        
                                        <div class="mb-3">
                                            <label for="description" class="form-label">Description</label>
                                            <textarea class="form-control" id="description" name="description" 
                                                      rows="3" placeholder="Description of this threat pattern"></textarea>
                                        </div>
                                        
                                        <div class="mb-3">
                                            <label for="severity" class="form-label">Severity Level</label>
                                            <select class="form-select" id="severity" name="severity" required>
                                                <option value="LOW">Low</option>
                                                <option value="MEDIUM" selected>Medium</option>
                                                <option value="HIGH">High</option>
                                                <option value="CRITICAL">Critical</option>
                                            </select>
                                        </div>
                                        
                                        <div class="d-grid">
                                            <button type="submit" class="btn btn-primary">
                                                <i class="fas fa-plus me-1"></i>
                                                Add Pattern
                                            </button>
                                        </div>
                                    </form>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Existing Patterns -->
                        <div class="col-lg-8 mb-4">
                            <div class="card shadow">
                                <div class="card-header">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <h6 class="m-0 font-weight-bold text-primary">
                                            Threat Patterns (<?php echo count($threatPatterns); ?>)
                                        </h6>
                                        <button class="btn btn-sm btn-outline-primary" onclick="refreshPatterns()">
                                            <i class="fas fa-sync-alt me-1"></i>
                                            Refresh
                                        </button>
                                    </div>
                                </div>
                                <div class="card-body p-0">
                                    <?php if (empty($threatPatterns)): ?>
                                    <div class="text-center py-4">
                                        <i class="fas fa-search fa-3x text-gray-300 mb-3"></i>
                                        <h5 class="text-muted">No threat patterns found</h5>
                                        <p class="text-muted">Add patterns using the form or upload a setup file.</p>
                                    </div>
                                    <?php else: ?>
                                    <div class="table-responsive">
                                        <table class="table table-hover mb-0">
                                            <thead class="bg-light">
                                                <tr>
                                                    <th>Pattern</th>
                                                    <th>Segment</th>
                                                    <th>Severity</th>
                                                    <th>Description</th>
                                                    <th>Status</th>
                                                    <th>Actions</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <?php foreach ($threatPatterns as $pattern): ?>
                                                <tr>
                                                    <td>
                                                        <code><?php echo htmlspecialchars($pattern['pattern']); ?></code>
                                                    </td>
                                                    <td>
                                                        <small class="text-muted">
                                                            <?php echo htmlspecialchars($pattern['segment_start']); ?> ... 
                                                            <?php echo htmlspecialchars($pattern['segment_end']); ?>
                                                        </small>
                                                    </td>
                                                    <td>
                                                        <span class="badge bg-<?php 
                                                            echo $pattern['severity'] === 'CRITICAL' ? 'danger' : 
                                                                ($pattern['severity'] === 'HIGH' ? 'warning' : 
                                                                ($pattern['severity'] === 'MEDIUM' ? 'info' : 'secondary')); 
                                                        ?>">
                                                            <?php echo $pattern['severity']; ?>
                                                        </span>
                                                    </td>
                                                    <td>
                                                        <div class="text-truncate" style="max-width: 200px;" 
                                                             title="<?php echo htmlspecialchars($pattern['description'] ?? ''); ?>">
                                                            <?php echo htmlspecialchars($pattern['description'] ?? 'No description'); ?>
                                                        </div>
                                                    </td>
                                                    <td>
                                                        <span class="badge bg-<?php echo $pattern['is_active'] ? 'success' : 'secondary'; ?>">
                                                            <?php echo $pattern['is_active'] ? 'Active' : 'Inactive'; ?>
                                                        </span>
                                                    </td>
                                                    <td>
                                                        <div class="btn-group btn-group-sm">
                                                            <button class="btn btn-outline-primary" 
                                                                    onclick="editPattern(<?php echo $pattern['id']; ?>)" 
                                                                    title="Edit">
                                                                <i class="fas fa-edit"></i>
                                                            </button>
                                                            <button class="btn btn-outline-secondary" 
                                                                    onclick="togglePattern(<?php echo $pattern['id']; ?>)" 
                                                                    title="Toggle Status">
                                                                <i class="fas fa-power-off"></i>
                                                            </button>
                                                        </div>
                                                    </td>
                                                </tr>
                                                <?php endforeach; ?>
                                            </tbody>
                                        </table>
                                    </div>
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Setup Files Tab -->
                <div class="tab-pane fade" id="setup" role="tabpanel">
                    <div class="row mt-4">
                        <div class="col-lg-6 mb-4">
                            <div class="card shadow">
                                <div class="card-header">
                                    <h6 class="m-0 font-weight-bold text-primary">Upload Setup File</h6>
                                </div>
                                <div class="card-body">
                                    <form method="post" enctype="multipart/form-data" id="setup-upload-form">
                                        <input type="hidden" name="action" value="upload_setup">
                                        <input type="hidden" name="csrf_token" value="<?php echo generateCsrfToken(); ?>">
                                        
                                        <div class="mb-3">
                                            <label for="setup_file" class="form-label">Setup File</label>
                                            <input type="file" class="form-control" id="setup_file" name="setup_file" 
                                                   accept=".csv,.xlsx,.xls,.json" required>
                                            <div class="form-text">
                                                Supported formats: CSV, Excel, JSON (Max: <?php echo formatFileSize(MAX_FILE_SIZE); ?>)
                                            </div>
                                        </div>
                                        
                                        <div class="alert alert-info">
                                            <strong>File Format Requirements:</strong>
                                            <ul class="mb-0 mt-2">
                                                <li><strong>CSV/Excel:</strong> Columns: segment_start, segment_end, pattern, description, severity</li>
                                                <li><strong>JSON:</strong> Array of pattern objects with the same fields</li>
                                                <li><strong>Example:</strong> &lt;body, &lt;/body&gt;, "verify account", "Phishing pattern", "HIGH"</li>
                                            </ul>
                                        </div>
                                        
                                        <div class="d-grid">
                                            <button type="submit" class="btn btn-success">
                                                <i class="fas fa-upload me-1"></i>
                                                Upload & Process
                                            </button>
                                        </div>
                                    </form>
                                </div>
                            </div>
                        </div>
                        
                        <div class="col-lg-6 mb-4">
                            <div class="card shadow">
                                <div class="card-header">
                                    <h6 class="m-0 font-weight-bold text-primary">Sample Setup File</h6>
                                </div>
                                <div class="card-body">
                                    <p class="text-muted">Download a sample setup file to get started:</p>
                                    
                                    <div class="d-grid gap-2">
                                        <button class="btn btn-outline-primary" onclick="downloadSample('csv')">
                                            <i class="fas fa-file-csv me-1"></i>
                                            Download CSV Sample
                                        </button>
                                        <button class="btn btn-outline-success" onclick="downloadSample('excel')">
                                            <i class="fas fa-file-excel me-1"></i>
                                            Download Excel Sample
                                        </button>
                                        <button class="btn btn-outline-info" onclick="downloadSample('json')">
                                            <i class="fas fa-file me-1"></i>
                                            Download JSON Sample
                                        </button>
                                    </div>
                                    
                                    <div class="mt-3">
                                        <h6>Column Descriptions:</h6>
                                        <ul class="small text-muted">
                                            <li><strong>segment_start:</strong> HTML tag where search begins (e.g., &lt;body)</li>
                                            <li><strong>segment_end:</strong> HTML tag where search ends (e.g., &lt;/body&gt;)</li>
                                            <li><strong>pattern:</strong> Text pattern to detect</li>
                                            <li><strong>description:</strong> Human-readable description</li>
                                            <li><strong>severity:</strong> LOW, MEDIUM, HIGH, or CRITICAL</li>
                                        </ul>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- System Config Tab -->
                <div class="tab-pane fade" id="system" role="tabpanel">
                    <div class="row mt-4">
                        <div class="col-lg-6 mb-4">
                            <div class="card shadow">
                                <div class="card-header">
                                    <h6 class="m-0 font-weight-bold text-primary">System Status</h6>
                                </div>
                                <div class="card-body">
                                    <div class="row">
                                        <div class="col-sm-6 mb-3">
                                            <div class="d-flex justify-content-between">
                                                <span>API Service:</span>
                                                <span class="badge bg-success" id="api-status">Online</span>
                                            </div>
                                        </div>
                                        <div class="col-sm-6 mb-3">
                                            <div class="d-flex justify-content-between">
                                                <span>Database:</span>
                                                <span class="badge bg-success" id="db-status">Connected</span>
                                            </div>
                                        </div>
                                        <div class="col-sm-6 mb-3">
                                            <div class="d-flex justify-content-between">
                                                <span>ML Engine:</span>
                                                <span class="badge bg-success" id="ml-status">Active</span>
                                            </div>
                                        </div>
                                        <div class="col-sm-6 mb-3">
                                            <div class="d-flex justify-content-between">
                                                <span>Cache System:</span>
                                                <span class="badge bg-success" id="cache-status">Running</span>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <hr>
                                    
                                    <div class="d-grid gap-2">
                                        <button class="btn btn-outline-primary" onclick="checkSystemHealth()">
                                            <i class="fas fa-heartbeat me-1"></i>
                                            Check System Health
                                        </button>
                                        <button class="btn btn-outline-warning" onclick="clearCache()">
                                            <i class="fas fa-broom me-1"></i>
                                            Clear Cache
                                        </button>
                                        <button class="btn btn-outline-info" onclick="downloadLogs()">
                                            <i class="fas fa-download me-1"></i>
                                            Download Logs
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="col-lg-6 mb-4">
                            <div class="card shadow">
                                <div class="card-header">
                                    <h6 class="m-0 font-weight-bold text-primary">Configuration</h6>
                                </div>
                                <div class="card-body">
                                    <table class="table table-sm table-borderless">
                                        <tr>
                                            <td class="fw-bold">Application Version:</td>
                                            <td><?php echo APP_VERSION; ?></td>
                                        </tr>
                                        <tr>
                                            <td class="fw-bold">PHP Version:</td>
                                            <td><?php echo PHP_VERSION; ?></td>
                                        </tr>
                                        <tr>
                                            <td class="fw-bold">Max File Size:</td>
                                            <td><?php echo formatFileSize(MAX_FILE_SIZE); ?></td>
                                        </tr>
                                        <tr>
                                            <td class="fw-bold">Items Per Page:</td>
                                            <td><?php echo ITEMS_PER_PAGE; ?></td>
                                        </tr>
                                        <tr>
                                            <td class="fw-bold">Session Timeout:</td>
                                            <td><?php echo SESSION_TIMEOUT; ?>s</td>
                                        </tr>
                                        <tr>
                                            <td class="fw-bold">Allowed Extensions:</td>
                                            <td><?php echo implode(', ', ALLOWED_EXTENSIONS); ?></td>
                                        </tr>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
function refreshPatterns() {
    location.reload();
}

function editPattern(patternId) {
    // Implementation for editing patterns
    alert('Pattern editing feature coming soon!');
}

function togglePattern(patternId) {
    // Implementation for toggling pattern status
    alert('Pattern toggle feature coming soon!');
}

function downloadSample(format) {
    // Generate sample file download
    const samples = {
        csv: `segment_start,segment_end,pattern,description,severity
<body,</body>,"verify account","Account verification phishing",HIGH
<body,</body>,"suspended","Account suspension threat",HIGH
<body,</body>,"click here","Suspicious link text",MEDIUM`,
        json: JSON.stringify([
            {
                segment_start: "<body",
                segment_end: "</body>", 
                pattern: "verify account",
                description: "Account verification phishing",
                severity: "HIGH"
            }
        ], null, 2)
    };
    
    const content = samples[format] || samples.csv;
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `threat_patterns_sample.${format}`;
    a.click();
    URL.revokeObjectURL(url);
}

function checkSystemHealth() {
    fetch('api.php?action=health-check')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showAlert('success', 'System health check passed');
            } else {
                showAlert('warning', 'System health check failed');
            }
        })
        .catch(error => {
            showAlert('danger', 'Health check request failed');
        });
}

function clearCache() {
    if (confirm('Are you sure you want to clear the system cache?')) {
        showAlert('info', 'Cache clearing feature coming soon!');
    }
}

function downloadLogs() {
    showAlert('info', 'Log download feature coming soon!');
}
</script>
