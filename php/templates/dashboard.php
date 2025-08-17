<?php
// Get dashboard statistics
try {
    $threatStats = $threatManager->getThreatStatistics(30);
    $emailStats = $emailManager->getEmailStatistics(30);
    $alerts = $threatManager->getActiveAlerts();
    $patterns = $threatManager->getThreatPatterns(7);
} catch (Exception $e) {
    error_log("Dashboard data error: " . $e->getMessage());
    $threatStats = [];
    $emailStats = [];
    $alerts = [];
    $patterns = [];
}
?>

<div class="dashboard-container">
    <!-- Page Header -->
    <div class="d-flex justify-content-between align-items-center mb-4">
        <div>
            <h1 class="h3 mb-0">Security Dashboard</h1>
            <p class="text-muted">Real-time phishing detection and threat monitoring</p>
        </div>
        <div class="d-flex gap-2">
            <button class="btn btn-outline-primary" onclick="refreshDashboard()">
                <i class="fas fa-sync-alt me-1"></i>
                Refresh
            </button>
            <button class="btn btn-primary" onclick="generateReport()">
                <i class="fas fa-file-pdf me-1"></i>
                Generate Report
            </button>
        </div>
    </div>

    <!-- Alert Banner -->
    <?php if (!empty($alerts['high_risk_emails']) || !empty($alerts['threat_spikes'])): ?>
    <div class="alert alert-warning alert-dismissible fade show mb-4" role="alert">
        <div class="d-flex align-items-center">
            <i class="fas fa-exclamation-triangle me-2"></i>
            <div>
                <strong>Security Alert:</strong>
                <?php if (!empty($alerts['high_risk_emails'])): ?>
                    <?= count($alerts['high_risk_emails']) ?> high-risk emails detected in the last 24 hours.
                <?php endif; ?>
                <?php if (!empty($alerts['threat_spikes'])): ?>
                    <?= count($alerts['threat_spikes']) ?> threat pattern spikes detected.
                <?php endif; ?>
            </div>
        </div>
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    </div>
    <?php endif; ?>

    <!-- Key Metrics Cards -->
    <div class="row mb-4">
        <div class="col-xl-3 col-md-6 mb-3">
            <div class="card stat-card bg-primary text-white">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <div class="stat-number"><?= number_format($emailStats['total_emails'] ?? 0) ?></div>
                            <div class="stat-label">Emails Analyzed</div>
                        </div>
                        <div class="stat-icon">
                            <i class="fas fa-envelope-open-text"></i>
                        </div>
                    </div>
                    <div class="stat-footer mt-2">
                        <i class="fas fa-calendar me-1"></i>
                        Last 30 days
                    </div>
                </div>
            </div>
        </div>

        <div class="col-xl-3 col-md-6 mb-3">
            <div class="card stat-card bg-danger text-white">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <div class="stat-number"><?= number_format($threatStats['total_threats'] ?? 0) ?></div>
                            <div class="stat-label">Threats Detected</div>
                        </div>
                        <div class="stat-icon">
                            <i class="fas fa-shield-alt"></i>
                        </div>
                    </div>
                    <div class="stat-footer mt-2">
                        <i class="fas fa-exclamation-triangle me-1"></i>
                        Active monitoring
                    </div>
                </div>
            </div>
        </div>

        <div class="col-xl-3 col-md-6 mb-3">
            <div class="card stat-card bg-warning text-white">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <div class="stat-number"><?= count($alerts['high_risk_emails'] ?? []) ?></div>
                            <div class="stat-label">High Risk Emails</div>
                        </div>
                        <div class="stat-icon">
                            <i class="fas fa-exclamation-circle"></i>
                        </div>
                    </div>
                    <div class="stat-footer mt-2">
                        <i class="fas fa-clock me-1"></i>
                        Last 24 hours
                    </div>
                </div>
            </div>
        </div>

        <div class="col-xl-3 col-md-6 mb-3">
            <div class="card stat-card bg-info text-white">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <div class="stat-number"><?= $alerts['quarantine_count'] ?? 0 ?></div>
                            <div class="stat-label">Quarantined</div>
                        </div>
                        <div class="stat-icon">
                            <i class="fas fa-lock"></i>
                        </div>
                    </div>
                    <div class="stat-footer mt-2">
                        <i class="fas fa-history me-1"></i>
                        Today
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Charts Row -->
    <div class="row mb-4">
        <!-- Threat Trend Chart -->
        <div class="col-lg-8 mb-3">
            <div class="card">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <h5 class="mb-0">
                        <i class="fas fa-chart-line me-2"></i>
                        Threat Detection Trend
                    </h5>
                    <div class="btn-group btn-group-sm" role="group">
                        <input type="radio" class="btn-check" name="trendPeriod" id="trend7d" value="7" checked>
                        <label class="btn btn-outline-primary" for="trend7d">7D</label>
                        
                        <input type="radio" class="btn-check" name="trendPeriod" id="trend30d" value="30">
                        <label class="btn btn-outline-primary" for="trend30d">30D</label>
                        
                        <input type="radio" class="btn-check" name="trendPeriod" id="trend90d" value="90">
                        <label class="btn btn-outline-primary" for="trend90d">90D</label>
                    </div>
                </div>
                <div class="card-body">
                    <canvas id="threatTrendChart" height="100"></canvas>
                </div>
            </div>
        </div>

        <!-- Risk Distribution -->
        <div class="col-lg-4 mb-3">
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0">
                        <i class="fas fa-chart-pie me-2"></i>
                        Risk Distribution
                    </h5>
                </div>
                <div class="card-body">
                    <canvas id="riskDistributionChart"></canvas>
                </div>
            </div>
        </div>
    </div>

    <!-- Recent Activity and Alerts -->
    <div class="row mb-4">
        <!-- Recent Critical Threats -->
        <div class="col-lg-8 mb-3">
            <div class="card">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <h5 class="mb-0">
                        <i class="fas fa-exclamation-triangle me-2"></i>
                        Recent Critical Threats
                    </h5>
                    <a href="?page=threat_history&filter=critical" class="btn btn-sm btn-outline-primary">
                        View All <i class="fas fa-arrow-right ms-1"></i>
                    </a>
                </div>
                <div class="card-body">
                    <?php if (!empty($threatStats['recent_critical'])): ?>
                        <div class="threat-list">
                            <?php foreach (array_slice($threatStats['recent_critical'], 0, 5) as $threat): ?>
                            <div class="threat-item d-flex align-items-center justify-content-between py-2 border-bottom">
                                <div class="d-flex align-items-center">
                                    <div class="threat-severity-badge severity-critical me-3"></div>
                                    <div>
                                        <div class="fw-semibold"><?= htmlspecialchars($threat['threat_type']) ?></div>
                                        <small class="text-muted">
                                            From: <?= htmlspecialchars($threat['sender_address'] ?? 'Unknown') ?>
                                        </small>
                                    </div>
                                </div>
                                <div class="text-end">
                                    <small class="text-muted"><?= date('M j, H:i', strtotime($threat['detected_at'])) ?></small>
                                    <br>
                                    <button class="btn btn-sm btn-outline-primary" onclick="viewThreatDetails('<?= $threat['email_id'] ?>')">
                                        Details
                                    </button>
                                </div>
                            </div>
                            <?php endforeach; ?>
                        </div>
                    <?php else: ?>
                        <div class="text-center text-muted py-4">
                            <i class="fas fa-check-circle fa-3x mb-3"></i>
                            <p>No critical threats detected recently</p>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <!-- System Status -->
        <div class="col-lg-4 mb-3">
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0">
                        <i class="fas fa-server me-2"></i>
                        System Status
                    </h5>
                </div>
                <div class="card-body">
                    <div class="status-item d-flex justify-content-between align-items-center mb-3">
                        <div>
                            <div class="fw-semibold">Database</div>
                            <small class="text-muted">Connection & Performance</small>
                        </div>
                        <span class="badge bg-success">
                            <i class="fas fa-check-circle me-1"></i>
                            Healthy
                        </span>
                    </div>

                    <div class="status-item d-flex justify-content-between align-items-center mb-3">
                        <div>
                            <div class="fw-semibold">Python API</div>
                            <small class="text-muted">Analysis Engine</small>
                        </div>
                        <span class="badge bg-success">
                            <i class="fas fa-check-circle me-1"></i>
                            Active
                        </span>
                    </div>

                    <div class="status-item d-flex justify-content-between align-items-center mb-3">
                        <div>
                            <div class="fw-semibold">Real-time Monitoring</div>
                            <small class="text-muted">Threat Detection</small>
                        </div>
                        <span class="badge bg-success">
                            <i class="fas fa-check-circle me-1"></i>
                            Running
                        </span>
                    </div>

                    <div class="status-item d-flex justify-content-between align-items-center">
                        <div>
                            <div class="fw-semibold">Auto-refresh</div>
                            <small class="text-muted">Dashboard Updates</small>
                        </div>
                        <span class="badge bg-info">
                            <i class="fas fa-sync-alt me-1"></i>
                            30s
                        </span>
                    </div>
                </div>
            </div>

            <!-- Quick Actions -->
            <div class="card mt-3">
                <div class="card-header">
                    <h6 class="mb-0">Quick Actions</h6>
                </div>
                <div class="card-body">
                    <div class="d-grid gap-2">
                        <a href="?page=email_analysis" class="btn btn-primary btn-sm">
                            <i class="fas fa-upload me-1"></i>
                            Analyze Email
                        </a>
                        <button class="btn btn-outline-secondary btn-sm" onclick="runContentScan()">
                            <i class="fas fa-search me-1"></i>
                            Content Scan
                        </button>
                        <a href="?page=threat_history" class="btn btn-outline-info btn-sm">
                            <i class="fas fa-history me-1"></i>
                            View History
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Top Categories and Patterns -->
    <div class="row">
        <!-- Top Threat Categories -->
        <div class="col-lg-6 mb-3">
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0">
                        <i class="fas fa-tags me-2"></i>
                        Top Threat Categories
                    </h5>
                </div>
                <div class="card-body">
                    <?php if (!empty($threatStats['category_distribution'])): ?>
                        <div class="category-list">
                            <?php foreach (array_slice($threatStats['category_distribution'], 0, 8) as $category): ?>
                            <div class="category-item d-flex justify-content-between align-items-center py-2">
                                <div>
                                    <span class="fw-semibold"><?= htmlspecialchars($category['category'] ?? 'Unknown') ?></span>
                                </div>
                                <div class="d-flex align-items-center">
                                    <div class="progress me-3" style="width: 100px; height: 6px;">
                                        <div class="progress-bar" style="width: <?= min(100, ($category['count'] / max(1, $threatStats['category_distribution'][0]['count'] ?? 1)) * 100) ?>%"></div>
                                    </div>
                                    <span class="badge bg-secondary"><?= $category['count'] ?></span>
                                </div>
                            </div>
                            <?php endforeach; ?>
                        </div>
                    <?php else: ?>
                        <div class="text-center text-muted py-3">
                            <i class="fas fa-info-circle fa-2x mb-2"></i>
                            <p>No threat categories data available</p>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <!-- Hourly Pattern -->
        <div class="col-lg-6 mb-3">
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0">
                        <i class="fas fa-clock me-2"></i>
                        Hourly Threat Pattern
                    </h5>
                </div>
                <div class="card-body">
                    <canvas id="hourlyPatternChart" height="100"></canvas>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Content Scan Modal -->
<div class="modal fade" id="contentScanModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Quick Content Scan</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <form id="contentScanForm">
                    <div class="mb-3">
                        <label for="scanContent" class="form-label">Content to Scan</label>
                        <textarea class="form-control" id="scanContent" rows="6" placeholder="Paste email content or text to scan for threats..."></textarea>
                    </div>
                    <div class="row">
                        <div class="col-md-6">
                            <label for="contentType" class="form-label">Content Type</label>
                            <select class="form-select" id="contentType">
                                <option value="text">Plain Text</option>
                                <option value="html">HTML</option>
                            </select>
                        </div>
                    </div>
                </form>
                <div id="scanResults" class="mt-3" style="display: none;"></div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                <button type="button" class="btn btn-primary" onclick="performContentScan()">
                    <i class="fas fa-search me-1"></i>
                    Scan Content
                </button>
            </div>
        </div>
    </div>
</div>

<script>
// Dashboard data for charts
const dashboardData = {
    threatTrend: <?= json_encode($threatStats['daily_trend'] ?? []) ?>,
    riskDistribution: <?= json_encode($emailStats['risk_distribution'] ?? []) ?>,
    hourlyPattern: <?= json_encode($patterns['hourly'] ?? []) ?>,
    categories: <?= json_encode($threatStats['category_distribution'] ?? []) ?>
};
</script>
