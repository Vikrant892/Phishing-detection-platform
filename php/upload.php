<?php
/**
 * Email Upload and Analysis page
 */

$analysisResult = null;
$error = null;

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        if (isset($_POST['action'])) {
            switch ($_POST['action']) {
                case 'upload_file':
                    if (!verifyCsrfToken($_POST['csrf_token'])) {
                        throw new Exception('Invalid CSRF token');
                    }
                    
                    if (!isset($_FILES['email_file'])) {
                        throw new Exception('No file uploaded');
                    }
                    
                    $file = $_FILES['email_file'];
                    $errors = validateFileUpload($file);
                    
                    if (!empty($errors)) {
                        throw new Exception(implode(', ', $errors));
                    }
                    
                    // Process the uploaded file via API
                    $tempPath = UPLOAD_DIR . uniqid() . '_' . basename($file['name']);
                    if (!move_uploaded_file($file['tmp_name'], $tempPath)) {
                        throw new Exception('Failed to save uploaded file');
                    }
                    
                    try {
                        $response = $apiClient->postFile('/analyze-email', ['file' => $tempPath]);
                        
                        if (file_exists($tempPath)) {
                            unlink($tempPath);
                        }
                        
                        if (!$response['success']) {
                            throw new Exception('Analysis failed: ' . ($response['data']['error'] ?? 'Unknown error'));
                        }
                        
                        $analysisResult = $response['data'];
                        logActivity('EMAIL_ANALYSIS', 'File: ' . $file['name']);
                        
                    } catch (Exception $e) {
                        if (file_exists($tempPath)) {
                            unlink($tempPath);
                        }
                        throw $e;
                    }
                    break;
                    
                case 'analyze_content':
                    if (!verifyCsrfToken($_POST['csrf_token'])) {
                        throw new Exception('Invalid CSRF token');
                    }
                    
                    if (empty($_POST['email_content'])) {
                        throw new Exception('Email content is required');
                    }
                    
                    $response = $apiClient->post('/analyze-email', [
                        'email_content' => $_POST['email_content']
                    ]);
                    
                    if (!$response['success']) {
                        throw new Exception('Analysis failed: ' . ($response['data']['error'] ?? 'Unknown error'));
                    }
                    
                    $analysisResult = $response['data'];
                    logActivity('EMAIL_ANALYSIS', 'Content analysis');
                    break;
            }
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
                    <i class="fas fa-upload me-2"></i>
                    Email Analysis
                </h1>
                <nav aria-label="breadcrumb">
                    <ol class="breadcrumb">
                        <li class="breadcrumb-item"><a href="index.php">Dashboard</a></li>
                        <li class="breadcrumb-item active">Email Analysis</li>
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

    <?php if ($analysisResult): ?>
    <!-- Analysis Results -->
    <div class="row mb-4">
        <div class="col-12">
            <?php 
            $threatScore = formatThreatScore($analysisResult['threat_score']);
            $metadata = $analysisResult['email_metadata'] ?? [];
            ?>
            
            <div class="card shadow">
                <div class="card-header bg-<?php echo $threatScore['class']; ?> text-white">
                    <div class="d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">
                            <i class="fas fa-shield-alt me-2"></i>
                            Analysis Results - <?php echo $threatScore['level']; ?> Risk
                        </h5>
                        <div class="d-flex align-items-center gap-3">
                            <div class="fs-4 fw-bold">
                                <?php echo $threatScore['score']; ?>% Threat Score
                            </div>
                            <div class="btn-group">
                                <?php if ($analysisResult['threat_score'] >= 40): ?>
                                <button class="btn btn-light btn-sm" onclick="quarantineEmail('<?php echo $analysisResult['analysis_id']; ?>')">
                                    <i class="fas fa-lock me-1"></i>
                                    Quarantine
                                </button>
                                <?php endif; ?>
                                <button class="btn btn-light btn-sm" onclick="exportAnalysis('<?php echo $analysisResult['analysis_id']; ?>')">
                                    <i class="fas fa-download me-1"></i>
                                    Export
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="card-body">
                    <!-- Email Metadata -->
                    <div class="row mb-4">
                        <div class="col-md-6">
                            <h6 class="text-primary">Email Information</h6>
                            <table class="table table-sm table-borderless">
                                <tr>
                                    <td class="fw-bold">Subject:</td>
                                    <td><?php echo htmlspecialchars($metadata['subject'] ?? 'N/A'); ?></td>
                                </tr>
                                <tr>
                                    <td class="fw-bold">From:</td>
                                    <td><?php echo htmlspecialchars($metadata['sender'] ?? 'N/A'); ?></td>
                                </tr>
                                <tr>
                                    <td class="fw-bold">To:</td>
                                    <td><?php echo htmlspecialchars($metadata['recipient'] ?? 'N/A'); ?></td>
                                </tr>
                                <tr>
                                    <td class="fw-bold">Date:</td>
                                    <td><?php echo htmlspecialchars($metadata['date'] ?? 'N/A'); ?></td>
                                </tr>
                            </table>
                        </div>
                        <div class="col-md-6">
                            <h6 class="text-primary">Analysis Summary</h6>
                            <table class="table table-sm table-borderless">
                                <tr>
                                    <td class="fw-bold">Analysis ID:</td>
                                    <td><code><?php echo $analysisResult['analysis_id']; ?></code></td>
                                </tr>
                                <tr>
                                    <td class="fw-bold">Threats Found:</td>
                                    <td>
                                        <span class="badge bg-<?php echo $analysisResult['threats_found'] > 0 ? 'danger' : 'success'; ?>">
                                            <?php echo $analysisResult['threats_found']; ?>
                                        </span>
                                    </td>
                                </tr>
                                <tr>
                                    <td class="fw-bold">Risk Level:</td>
                                    <td>
                                        <span class="badge bg-<?php echo $threatScore['class']; ?>">
                                            <?php echo $threatScore['level']; ?>
                                        </span>
                                    </td>
                                </tr>
                                <tr>
                                    <td class="fw-bold">Analyzed:</td>
                                    <td><?php echo date('M d, Y H:i:s'); ?></td>
                                </tr>
                            </table>
                        </div>
                    </div>

                    <!-- Threat Details -->
                    <?php if (!empty($analysisResult['analysis_details']['threats'])): ?>
                    <div class="mb-4">
                        <h6 class="text-primary">Detected Threats</h6>
                        <div class="table-responsive">
                            <table class="table table-striped">
                                <thead>
                                    <tr>
                                        <th>Threat Type</th>
                                        <th>Severity</th>
                                        <th>Description</th>
                                        <th>Location</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($analysisResult['analysis_details']['threats'] as $threat): ?>
                                    <tr>
                                        <td>
                                            <span class="badge bg-secondary"><?php echo ucwords(str_replace('_', ' ', $threat['type'])); ?></span>
                                        </td>
                                        <td>
                                            <span class="badge bg-<?php 
                                                echo $threat['severity'] === 'high' ? 'danger' : 
                                                    ($threat['severity'] === 'medium' ? 'warning' : 'info'); 
                                            ?>">
                                                <?php echo ucfirst($threat['severity']); ?>
                                            </span>
                                        </td>
                                        <td><?php echo htmlspecialchars($threat['description']); ?></td>
                                        <td><code><?php echo htmlspecialchars($threat['location']); ?></code></td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                    <?php endif; ?>

                    <!-- Security Recommendations -->
                    <?php if (!empty($analysisResult['analysis_details']['recommendations'])): ?>
                    <div class="mb-4">
                        <h6 class="text-primary">Security Recommendations</h6>
                        <div class="alert alert-info">
                            <ul class="mb-0">
                                <?php foreach ($analysisResult['analysis_details']['recommendations'] as $recommendation): ?>
                                <li><?php echo htmlspecialchars($recommendation); ?></li>
                                <?php endforeach; ?>
                            </ul>
                        </div>
                    </div>
                    <?php endif; ?>

                    <!-- Score Breakdown -->
                    <?php if (!empty($analysisResult['analysis_details']['score_breakdown'])): ?>
                    <div>
                        <h6 class="text-primary">Threat Score Breakdown</h6>
                        <div class="row">
                            <?php foreach ($analysisResult['analysis_details']['score_breakdown'] as $category => $score): ?>
                            <div class="col-md-4 mb-2">
                                <div class="d-flex justify-content-between">
                                    <span><?php echo ucwords(str_replace('_', ' ', $category)); ?>:</span>
                                    <strong><?php echo $score; ?></strong>
                                </div>
                                <div class="progress" style="height: 6px;">
                                    <div class="progress-bar" style="width: <?php echo min($score, 100); ?>%"></div>
                                </div>
                            </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <!-- Upload Forms -->
    <div class="row">
        <!-- File Upload -->
        <div class="col-lg-6 mb-4">
            <div class="card shadow">
                <div class="card-header">
                    <h6 class="m-0 font-weight-bold text-primary">
                        <i class="fas fa-file-upload me-2"></i>
                        Upload Email File
                    </h6>
                </div>
                <div class="card-body">
                    <form method="post" enctype="multipart/form-data" id="file-upload-form">
                        <input type="hidden" name="action" value="upload_file">
                        <input type="hidden" name="csrf_token" value="<?php echo generateCsrfToken(); ?>">
                        
                        <div class="mb-3">
                            <label for="email_file" class="form-label">Select Email File</label>
                            <input type="file" class="form-control" id="email_file" name="email_file" 
                                   accept=".eml,.msg,.txt" required>
                            <div class="form-text">
                                Supported formats: EML, MSG, TXT (Max: <?php echo formatFileSize(MAX_FILE_SIZE); ?>)
                            </div>
                        </div>
                        
                        <div class="d-grid gap-2">
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-search me-2"></i>
                                Analyze File
                            </button>
                            <div class="progress d-none" id="file-upload-progress">
                                <div class="progress-bar" role="progressbar" style="width: 0%"></div>
                            </div>
                        </div>
                    </form>
                </div>
            </div>
        </div>

        <!-- Content Analysis -->
        <div class="col-lg-6 mb-4">
            <div class="card shadow">
                <div class="card-header">
                    <h6 class="m-0 font-weight-bold text-primary">
                        <i class="fas fa-edit me-2"></i>
                        Analyze Email Content
                    </h6>
                </div>
                <div class="card-body">
                    <form method="post" id="content-analysis-form">
                        <input type="hidden" name="action" value="analyze_content">
                        <input type="hidden" name="csrf_token" value="<?php echo generateCsrfToken(); ?>">
                        
                        <div class="mb-3">
                            <label for="email_content" class="form-label">Email Content</label>
                            <textarea class="form-control" id="email_content" name="email_content" 
                                      rows="12" placeholder="Paste email content here..." required></textarea>
                            <div class="form-text">
                                Paste the raw email content including headers
                            </div>
                        </div>
                        
                        <div class="d-grid gap-2">
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-search me-2"></i>
                                Analyze Content
                            </button>
                            <div class="progress d-none" id="content-analysis-progress">
                                <div class="progress-bar" role="progressbar" style="width: 0%"></div>
                            </div>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <!-- Analysis History -->
    <div class="row">
        <div class="col-12">
            <div class="card shadow">
                <div class="card-header">
                    <div class="d-flex justify-content-between align-items-center">
                        <h6 class="m-0 font-weight-bold text-primary">Recent Analyses</h6>
                        <a href="index.php?page=reports" class="btn btn-sm btn-primary">
                            View All Reports
                        </a>
                    </div>
                </div>
                <div class="card-body">
                    <div id="recent-analyses-container" class="table-responsive">
                        <!-- Recent analyses will be loaded via AJAX -->
                        <div class="text-center py-4">
                            <div class="spinner-border text-primary" role="status">
                                <span class="visually-hidden">Loading...</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function() {
    // Load recent analyses
    loadRecentAnalyses();
    
    // Form submission handlers with progress tracking
    handleFormSubmissions();
});

function loadRecentAnalyses() {
    fetch('api.php?action=analysis-history&per_page=5')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                displayRecentAnalyses(data.data.analyses);
            } else {
                document.getElementById('recent-analyses-container').innerHTML = 
                    '<div class="alert alert-warning">Failed to load recent analyses</div>';
            }
        })
        .catch(error => {
            console.error('Error loading recent analyses:', error);
            document.getElementById('recent-analyses-container').innerHTML = 
                '<div class="alert alert-danger">Error loading data</div>';
        });
}

function displayRecentAnalyses(analyses) {
    if (analyses.length === 0) {
        document.getElementById('recent-analyses-container').innerHTML = 
            '<div class="text-center text-muted">No recent analyses found</div>';
        return;
    }
    
    let html = '<table class="table table-hover"><thead><tr>' +
               '<th>Date</th><th>Subject</th><th>Sender</th><th>Risk</th><th>Score</th><th>Actions</th>' +
               '</tr></thead><tbody>';
    
    analyses.forEach(analysis => {
        const threatInfo = formatThreatScore(analysis.threat_score);
        html += `<tr>
            <td>${formatDateTime(analysis.created_at)}</td>
            <td class="text-truncate" style="max-width: 200px;">${escapeHtml(analysis.email_subject)}</td>
            <td>${escapeHtml(analysis.email_sender)}</td>
            <td><span class="badge bg-${threatInfo.class}">${threatInfo.level}</span></td>
            <td>
                <div class="progress" style="height: 20px;">
                    <div class="progress-bar bg-${threatInfo.class}" style="width: ${threatInfo.percentage}%">
                        ${threatInfo.score}%
                    </div>
                </div>
            </td>
            <td>
                <button class="btn btn-sm btn-outline-primary" onclick="viewAnalysis('${analysis.analysis_id}')">
                    <i class="fas fa-eye"></i>
                </button>
            </td>
        </tr>`;
    });
    
    html += '</tbody></table>';
    document.getElementById('recent-analyses-container').innerHTML = html;
}

function handleFormSubmissions() {
    // File upload form
    document.getElementById('file-upload-form').addEventListener('submit', function(e) {
        e.preventDefault();
        showProgress('file-upload-progress');
        this.submit();
    });
    
    // Content analysis form  
    document.getElementById('content-analysis-form').addEventListener('submit', function(e) {
        e.preventDefault();
        showProgress('content-analysis-progress');
        this.submit();
    });
}

function showProgress(progressId) {
    const progressBar = document.getElementById(progressId);
    progressBar.classList.remove('d-none');
    
    let width = 0;
    const interval = setInterval(() => {
        width += 10;
        progressBar.querySelector('.progress-bar').style.width = width + '%';
        
        if (width >= 90) {
            clearInterval(interval);
        }
    }, 200);
}
</script>
