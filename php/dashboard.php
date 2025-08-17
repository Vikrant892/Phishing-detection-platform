<?php
/**
 * Dashboard page for the Phishing Detection Platform
 * Displays real-time statistics and recent analyses
 */

// Get dashboard statistics from API
$dashboardStats = [];
$recentAnalyses = [];

try {
    $response = $apiClient->get('/dashboard-stats');
    if ($response['success']) {
        $dashboardStats = $response['data'];
        $recentAnalyses = $dashboardStats['recent_analyses'] ?? [];
    }
} catch (Exception $e) {
    $error = "Failed to load dashboard data: " . $e->getMessage();
}
?>

<div id="dashboard-content" class="container-fluid">
    <!-- Page Header -->
    <div class="row mb-4">
        <div class="col-12">
            <div class="d-flex justify-content-between align-items-center">
                <h1 class="h3 mb-0 text-gray-800">
                    <i class="fas fa-tachometer-alt me-2"></i>
                    Security Dashboard
                </h1>
                <div class="d-flex gap-2">
                    <button class="btn btn-primary" onclick="refreshDashboard()">
                        <i class="fas fa-sync-alt me-1"></i>
                        Refresh
                    </button>
                    <div class="dropdown">
                        <button class="btn btn-outline-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown">
                            <i class="fas fa-calendar me-1"></i>
                            Time Range
                        </button>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="#" onclick="setTimeRange('24h')">Last 24 Hours</a></li>
                            <li><a class="dropdown-item" href="#" onclick="setTimeRange('7d')">Last 7 Days</a></li>
                            <li><a class="dropdown-item" href="#" onclick="setTimeRange('30d')">Last 30 Days</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <?php if (isset($error)): ?>
    <div class="row mb-4">
        <div class="col-12">
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-triangle me-2"></i>
                <?php echo htmlspecialchars($error); ?>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <!-- Statistics Cards -->
    <div class="row mb-4">
        <div class="col-xl-3 col-md-6 mb-4">
            <div class="card border-left-primary shadow h-100 py-2">
                <div class="card-body">
                    <div class="row no-gutters align-items-center">
                        <div class="col mr-2">
                            <div class="text-xs font-weight-bold text-primary text-uppercase mb-1">
                                Total Analyses
                            </div>
                            <div class="h5 mb-0 font-weight-bold text-gray-800" id="total-analyses">
                                <?php echo number_format($dashboardStats['total_analyses'] ?? 0); ?>
                            </div>
                        </div>
                        <div class="col-auto">
                            <i class="fas fa-envelope fa-2x text-gray-300"></i>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="col-xl-3 col-md-6 mb-4">
            <div class="card border-left-danger shadow h-100 py-2">
                <div class="card-body">
                    <div class="row no-gutters align-items-center">
                        <div class="col mr-2">
                            <div class="text-xs font-weight-bold text-danger text-uppercase mb-1">
                                High Risk Threats
                            </div>
                            <div class="h5 mb-0 font-weight-bold text-gray-800" id="high-risk-count">
                                <?php 
                                $highRisk = $dashboardStats['risk_distribution']['HIGH'] ?? 0;
                                echo number_format($highRisk); 
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

        <div class="col-xl-3 col-md-6 mb-4">
            <div class="card border-left-warning shadow h-100 py-2">
                <div class="card-body">
                    <div class="row no-gutters align-items-center">
                        <div class="col mr-2">
                            <div class="text-xs font-weight-bold text-warning text-uppercase mb-1">
                                Average Threat Score
                            </div>
                            <div class="h5 mb-0 font-weight-bold text-gray-800" id="avg-threat-score">
                                <?php echo number_format($dashboardStats['avg_threat_score'] ?? 0, 1); ?>%
                            </div>
                        </div>
                        <div class="col-auto">
                            <i class="fas fa-chart-line fa-2x text-gray-300"></i>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="col-xl-3 col-md-6 mb-4">
            <div class="card border-left-info shadow h-100 py-2">
                <div class="card-body">
                    <div class="row no-gutters align-items-center">
                        <div class="col mr-2">
                            <div class="text-xs font-weight-bold text-info text-uppercase mb-1">
                                Quarantined Emails
                            </div>
                            <div class="h5 mb-0 font-weight-bold text-gray-800" id="quarantined-count">
                                <?php echo number_format($dashboardStats['quarantined_count'] ?? 0); ?>
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

    <!-- Charts Row -->
    <div class="row mb-4">
        <!-- Risk Distribution Chart -->
        <div class="col-xl-6 col-lg-7">
            <div class="card shadow mb-4">
                <div class="card-header py-3 d-flex justify-content-between align-items-center">
                    <h6 class="m-0 font-weight-bold text-primary">Risk Distribution</h6>
                    <div class="dropdown no-arrow">
                        <a class="dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">
                            <i class="fas fa-ellipsis-v fa-sm fa-fw text-gray-400"></i>
                        </a>
                        <div class="dropdown-menu dropdown-menu-right shadow animated--fade-in">
                            <a class="dropdown-item" href="#">Export Chart</a>
                            <a class="dropdown-item" href="#">View Details</a>
                        </div>
                    </div>
                </div>
                <div class="card-body">
                    <div class="chart-pie pt-4 pb-2">
                        <canvas id="riskDistributionChart"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <!-- Threat Trends Chart -->
        <div class="col-xl-6 col-lg-5">
            <div class="card shadow mb-4">
                <div class="card-header py-3">
                    <h6 class="m-0 font-weight-bold text-primary">Threat Trends (24h)</h6>
                </div>
                <div class="card-body">
                    <div class="chart-area">
                        <canvas id="threatTrendsChart"></canvas>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Recent Analyses and Quick Actions -->
    <div class="row">
        <!-- Recent Analyses -->
        <div class="col-lg-8 mb-4">
            <div class="card shadow mb-4">
                <div class="card-header py-3 d-flex justify-content-between align-items-center">
                    <h6 class="m-0 font-weight-bold text-primary">Recent Analyses</h6>
                    <a href="index.php?page=reports" class="btn btn-sm btn-primary">
                        <i class="fas fa-list me-1"></i>
                        View All
                    </a>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead>
                                <tr>
                                    <th>Time</th>
                                    <th>Subject</th>
                                    <th>Sender</th>
                                    <th>Risk Level</th>
                                    <th>Score</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody id="recent-analyses-table">
                                <?php if (empty($recentAnalyses)): ?>
                                <tr>
                                    <td colspan="6" class="text-center text-muted">
                                        <i class="fas fa-inbox fa-3x mb-3 d-block"></i>
                                        No recent analyses available
                                    </td>
                                </tr>
                                <?php else: ?>
                                <?php foreach ($recentAnalyses as $analysis): ?>
                                <?php $threatScore = formatThreatScore($analysis['threat_score']); ?>
                                <tr>
                                    <td><?php echo formatDateTime($analysis['created_at']); ?></td>
                                    <td>
                                        <div class="text-truncate" style="max-width: 200px;" title="<?php echo htmlspecialchars($analysis['email_subject']); ?>">
                                            <?php echo htmlspecialchars($analysis['email_subject']); ?>
                                        </div>
                                    </td>
                                    <td><?php echo htmlspecialchars($analysis['email_sender']); ?></td>
                                    <td>
                                        <span class="badge bg-<?php echo $threatScore['class']; ?>">
                                            <?php echo $threatScore['level']; ?>
                                        </span>
                                    </td>
                                    <td>
                                        <div class="progress" style="height: 20px;">
                                            <div class="progress-bar bg-<?php echo $threatScore['class']; ?>" 
                                                 style="width: <?php echo $threatScore['percentage']; ?>%">
                                                <?php echo $threatScore['score']; ?>%
                                            </div>
                                        </div>
                                    </td>
                                    <td>
                                        <div class="btn-group btn-group-sm">
                                            <button class="btn btn-outline-primary btn-sm" 
                                                    onclick="viewAnalysis('<?php echo $analysis['analysis_id']; ?>')" 
                                                    title="View Details">
                                                <i class="fas fa-eye"></i>
                                            </button>
                                            <?php if ($analysis['threat_score'] >= 40): ?>
                                            <button class="btn btn-outline-warning btn-sm" 
                                                    onclick="quarantineEmail('<?php echo $analysis['analysis_id']; ?>')" 
                                                    title="Quarantine">
                                                <i class="fas fa-lock"></i>
                                            </button>
                                            <?php endif; ?>
                                        </div>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <!-- Quick Actions -->
        <div class="col-lg-4 mb-4">
            <div class="card shadow mb-4">
                <div class="card-header py-3">
                    <h6 class="m-0 font-weight-bold text-primary">Quick Actions</h6>
                </div>
                <div class="card-body">
                    <div class="d-grid gap-2">
                        <a href="index.php?page=upload" class="btn btn-primary">
                            <i class="fas fa-upload me-2"></i>
                            Analyze Email
                        </a>
                        <button class="btn btn-outline-primary" onclick="showBulkUpload()">
                            <i class="fas fa-file-upload me-2"></i>
                            Bulk Analysis
                        </button>
                        <a href="index.php?page=reports" class="btn btn-outline-secondary">
                            <i class="fas fa-chart-bar me-2"></i>
                            Generate Report
                        </a>
                        <a href="index.php?page=settings" class="btn btn-outline-info">
                            <i class="fas fa-cog me-2"></i>
                            Threat Patterns
                        </a>
                    </div>
                </div>
            </div>

            <!-- System Status -->
            <div class="card shadow mb-4">
                <div class="card-header py-3">
                    <h6 class="m-0 font-weight-bold text-success">System Status</h6>
                </div>
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-center mb-2">
                        <span>API Service</span>
                        <span class="badge bg-success" id="api-status">Online</span>
                    </div>
                    <div class="d-flex justify-content-between align-items-center mb-2">
                        <span>Database</span>
                        <span class="badge bg-success" id="db-status">Connected</span>
                    </div>
                    <div class="d-flex justify-content-between align-items-center mb-2">
                        <span>ML Engine</span>
                        <span class="badge bg-success" id="ml-status">Active</span>
                    </div>
                    <div class="d-flex justify-content-between align-items-center">
                        <span>Last Update</span>
                        <small class="text-muted" id="last-update">
                            <?php echo date('H:i:s'); ?>
                        </small>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Real-time Activity Feed -->
    <div class="row">
        <div class="col-12">
            <div class="card shadow mb-4">
                <div class="card-header py-3 d-flex justify-content-between align-items-center">
                    <h6 class="m-0 font-weight-bold text-primary">
                        <i class="fas fa-stream me-2"></i>
                        Real-time Activity Feed
                    </h6>
                    <button class="btn btn-sm btn-outline-primary" onclick="toggleActivityFeed()">
                        <i class="fas fa-pause" id="activity-toggle-icon"></i>
                        <span id="activity-toggle-text">Pause</span>
                    </button>
                </div>
                <div class="card-body">
                    <div id="activity-feed" class="activity-feed">
                        <!-- Activity items will be populated by JavaScript -->
                        <div class="text-center text-muted">
                            <i class="fas fa-satellite-dish fa-2x mb-2 d-block"></i>
                            Monitoring for threat activity...
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Bulk Upload Modal -->
<div class="modal fade" id="bulkUploadModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">
                    <i class="fas fa-file-upload me-2"></i>
                    Bulk Email Analysis
                </h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <form id="bulk-upload-form" enctype="multipart/form-data">
                    <div class="mb-3">
                        <label for="bulk-files" class="form-label">Select Email Files</label>
                        <input type="file" class="form-control" id="bulk-files" name="files[]" 
                               multiple accept=".eml,.msg,.txt" required>
                        <div class="form-text">
                            Supported formats: EML, MSG, TXT. Maximum 10 files at once.
                        </div>
                    </div>
                    <div class="progress d-none" id="bulk-upload-progress">
                        <div class="progress-bar" role="progressbar" style="width: 0%"></div>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                <button type="button" class="btn btn-primary" onclick="processBulkUpload()">
                    <i class="fas fa-play me-1"></i>
                    Start Analysis
                </button>
            </div>
        </div>
    </div>
</div>

<script>
// Dashboard-specific data
const dashboardData = <?php echo json_encode($dashboardStats); ?>;
</script>
