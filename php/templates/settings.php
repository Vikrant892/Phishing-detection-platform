<!-- Settings Page -->
<div class="row mb-4">
    <div class="col-12">
        <div class="d-flex justify-content-between align-items-center">
            <h1 class="h3 mb-0">
                <i class="fas fa-cog me-2 text-primary"></i>
                System Settings
            </h1>
            <div class="d-flex gap-2">
                <button class="btn btn-outline-danger btn-sm" onclick="Settings.resetToDefaults()">
                    <i class="fas fa-undo me-1"></i>Reset to Defaults
                </button>
                <button class="btn btn-success btn-sm" onclick="Settings.saveAllSettings()">
                    <i class="fas fa-save me-1"></i>Save All Changes
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Settings Navigation Tabs -->
<div class="row mb-4">
    <div class="col-12">
        <ul class="nav nav-tabs" id="settingsTabs" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link active" id="general-tab" data-bs-toggle="tab" 
                        data-bs-target="#general" type="button" role="tab">
                    <i class="fas fa-sliders-h me-2"></i>General
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="security-tab" data-bs-toggle="tab" 
                        data-bs-target="#security" type="button" role="tab">
                    <i class="fas fa-shield-alt me-2"></i>Security
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="patterns-tab" data-bs-toggle="tab" 
                        data-bs-target="#patterns" type="button" role="tab">
                    <i class="fas fa-search me-2"></i>Threat Patterns
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="notifications-tab" data-bs-toggle="tab" 
                        data-bs-target="#notifications" type="button" role="tab">
                    <i class="fas fa-bell me-2"></i>Notifications
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="advanced-tab" data-bs-toggle="tab" 
                        data-bs-target="#advanced" type="button" role="tab">
                    <i class="fas fa-tools me-2"></i>Advanced
                </button>
            </li>
        </ul>
    </div>
</div>

<!-- Settings Content -->
<div class="tab-content" id="settingsTabContent">
    
    <!-- General Settings -->
    <div class="tab-pane fade show active" id="general" role="tabpanel">
        <div class="row">
            <div class="col-lg-8">
                <div class="card shadow">
                    <div class="card-header py-3">
                        <h6 class="m-0 fw-bold text-primary">
                            <i class="fas fa-sliders-h me-2"></i>General Configuration
                        </h6>
                    </div>
                    <div class="card-body">
                        <form id="generalSettingsForm">
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label for="riskThreshold" class="form-label">
                                            Risk Score Threshold
                                            <i class="fas fa-info-circle text-muted" 
                                               title="Emails with risk scores above this value will be flagged as threats"></i>
                                        </label>
                                        <div class="input-group">
                                            <input type="number" class="form-control" id="riskThreshold" 
                                                   name="risk_threshold" min="0" max="100" step="0.1"
                                                   value="<?php echo $page_data['current_settings']['risk_threshold'] ?? 40.0; ?>">
                                            <span class="input-group-text">%</span>
                                        </div>
                                        <div class="form-text">
                                            Current: <?php echo $page_data['current_settings']['risk_threshold'] ?? 40.0; ?>% 
                                            (Recommended: 40-60%)
                                        </div>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label for="maxFileSize" class="form-label">
                                            Maximum File Size
                                        </label>
                                        <div class="input-group">
                                            <input type="number" class="form-control" id="maxFileSize" 
                                                   name="max_file_size" min="1" max="500"
                                                   value="<?php echo ($page_data['current_settings']['max_file_size'] ?? 100); ?>">
                                            <span class="input-group-text">MB</span>
                                        </div>
                                        <div class="form-text">
                                            Maximum size for uploaded email files
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label for="retentionDays" class="form-label">
                                            Data Retention Period
                                        </label>
                                        <div class="input-group">
                                            <input type="number" class="form-control" id="retentionDays" 
                                                   name="retention_days" min="1" max="3650"
                                                   value="<?php echo $page_data['current_settings']['retention_days'] ?? 90; ?>">
                                            <span class="input-group-text">days</span>
                                        </div>
                                        <div class="form-text">
                                            How long to keep analysis data
                                        </div>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label for="notificationEmail" class="form-label">
                                            Notification Email
                                        </label>
                                        <input type="email" class="form-control" id="notificationEmail" 
                                               name="notification_email"
                                               value="<?php echo htmlspecialchars($page_data['current_settings']['notification_email'] ?? ''); ?>">
                                        <div class="form-text">
                                            Email address for system notifications
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="mb-3">
                                <div class="form-check form-switch">
                                    <input class="form-check-input" type="checkbox" id="autoQuarantine" 
                                           name="auto_quarantine"
                                           <?php echo ($page_data['current_settings']['auto_quarantine'] ?? true) ? 'checked' : ''; ?>>
                                    <label class="form-check-label" for="autoQuarantine">
                                        Auto-Quarantine High Risk Emails
                                        <small class="text-muted d-block">
                                            Automatically quarantine emails with risk scores above 80%
                                        </small>
                                    </label>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
            
            <div class="col-lg-4">
                <div class="card shadow">
                    <div class="card-header py-3">
                        <h6 class="m-0 fw-bold text-info">
                            <i class="fas fa-chart-bar me-2"></i>System Statistics
                        </h6>
                    </div>
                    <div class="card-body">
                        <div class="mb-3">
                            <div class="d-flex justify-content-between">
                                <span>Storage Used:</span>
                                <strong id="storageUsed">0 MB</strong>
                            </div>
                            <div class="progress mt-1">
                                <div class="progress-bar" role="progressbar" style="width: 0%" id="storageProgress"></div>
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <div class="d-flex justify-content-between">
                                <span>Database Size:</span>
                                <strong id="databaseSize">0 MB</strong>
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <div class="d-flex justify-content-between">
                                <span>Total Patterns:</span>
                                <strong id="totalPatterns">0</strong>
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <div class="d-flex justify-content-between">
                                <span>Active Patterns:</span>
                                <strong id="activePatterns">0</strong>
                            </div>
                        </div>
                        
                        <hr>
                        
                        <button class="btn btn-outline-warning btn-sm w-100 mb-2" onclick="Settings.cleanupData()">
                            <i class="fas fa-broom me-1"></i>Cleanup Old Data
                        </button>
                        
                        <button class="btn btn-outline-info btn-sm w-100" onclick="Settings.optimizeDatabase()">
                            <i class="fas fa-database me-1"></i>Optimize Database
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Security Settings -->
    <div class="tab-pane fade" id="security" role="tabpanel">
        <div class="row">
            <div class="col-lg-8">
                <div class="card shadow">
                    <div class="card-header py-3">
                        <h6 class="m-0 fw-bold text-primary">
                            <i class="fas fa-shield-alt me-2"></i>Security Configuration
                        </h6>
                    </div>
                    <div class="card-body">
                        <form id="securitySettingsForm">
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label for="sessionTimeout" class="form-label">
                                            Session Timeout
                                        </label>
                                        <div class="input-group">
                                            <input type="number" class="form-control" id="sessionTimeout" 
                                                   name="session_timeout" min="15" max="1440"
                                                   value="60">
                                            <span class="input-group-text">minutes</span>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label for="maxLoginAttempts" class="form-label">
                                            Max Login Attempts
                                        </label>
                                        <input type="number" class="form-control" id="maxLoginAttempts" 
                                               name="max_login_attempts" min="3" max="10"
                                               value="5">
                                    </div>
                                </div>
                            </div>
                            
                            <div class="mb-3">
                                <div class="form-check form-switch">
                                    <input class="form-check-input" type="checkbox" id="enableAuditLog" checked>
                                    <label class="form-check-label" for="enableAuditLog">
                                        Enable Audit Logging
                                    </label>
                                </div>
                            </div>
                            
                            <div class="mb-3">
                                <div class="form-check form-switch">
                                    <input class="form-check-input" type="checkbox" id="requireStrongPasswords" checked>
                                    <label class="form-check-label" for="requireStrongPasswords">
                                        Require Strong Passwords
                                    </label>
                                </div>
                            </div>
                            
                            <div class="mb-3">
                                <div class="form-check form-switch">
                                    <input class="form-check-input" type="checkbox" id="enableTwoFactor">
                                    <label class="form-check-label" for="enableTwoFactor">
                                        Enable Two-Factor Authentication
                                        <small class="text-muted d-block">Coming soon</small>
                                    </label>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
            
            <div class="col-lg-4">
                <div class="card shadow">
                    <div class="card-header py-3">
                        <h6 class="m-0 fw-bold text-warning">
                            <i class="fas fa-exclamation-triangle me-2"></i>Security Alerts
                        </h6>
                    </div>
                    <div class="card-body">
                        <div id="securityAlerts">
                            <div class="alert alert-success alert-sm">
                                <i class="fas fa-check-circle me-2"></i>
                                No security issues detected
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="card shadow mt-3">
                    <div class="card-header py-3">
                        <h6 class="m-0 fw-bold text-info">
                            <i class="fas fa-key me-2"></i>API Access
                        </h6>
                    </div>
                    <div class="card-body">
                        <p class="small text-muted">
                            Generate API keys for external integrations
                        </p>
                        <button class="btn btn-primary btn-sm w-100" onclick="Settings.generateApiKey()">
                            <i class="fas fa-plus me-1"></i>Generate New API Key
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Threat Patterns -->
    <div class="tab-pane fade" id="patterns" role="tabpanel">
        <div class="row">
            <div class="col-12">
                <div class="card shadow">
                    <div class="card-header py-3 d-flex justify-content-between align-items-center">
                        <h6 class="m-0 fw-bold text-primary">
                            <i class="fas fa-search me-2"></i>Threat Detection Patterns
                        </h6>
                        <button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#addPatternModal">
                            <i class="fas fa-plus me-1"></i>Add Pattern
                        </button>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-hover" id="threatPatternsTable">
                                <thead class="table-light">
                                    <tr>
                                        <th>Name</th>
                                        <th>Type</th>
                                        <th>Pattern</th>
                                        <th>Risk Score</th>
                                        <th>Status</th>
                                        <th>Created</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (!empty($page_data['threat_patterns'])): ?>
                                        <?php foreach ($page_data['threat_patterns'] as $pattern): ?>
                                        <tr data-pattern-id="<?php echo $pattern['id']; ?>">
                                            <td>
                                                <strong><?php echo htmlspecialchars($pattern['name']); ?></strong>
                                            </td>
                                            <td>
                                                <span class="badge bg-info">
                                                    <?php echo ucfirst($pattern['pattern_type']); ?>
                                                </span>
                                            </td>
                                            <td>
                                                <code class="text-truncate d-block" style="max-width: 200px;">
                                                    <?php echo htmlspecialchars(truncateText($pattern['pattern_text'], 50)); ?>
                                                </code>
                                            </td>
                                            <td>
                                                <span class="badge bg-<?php echo $pattern['risk_score'] >= 30 ? 'danger' : ($pattern['risk_score'] >= 15 ? 'warning' : 'secondary'); ?>">
                                                    <?php echo $pattern['risk_score']; ?>
                                                </span>
                                            </td>
                                            <td>
                                                <?php if ($pattern['is_active']): ?>
                                                <span class="badge bg-success">Active</span>
                                                <?php else: ?>
                                                <span class="badge bg-secondary">Inactive</span>
                                                <?php endif; ?>
                                            </td>
                                            <td>
                                                <small><?php echo formatTimestamp($pattern['created_at'], 'M j, Y'); ?></small>
                                            </td>
                                            <td>
                                                <div class="btn-group btn-group-sm">
                                                    <button class="btn btn-outline-primary" 
                                                            onclick="Settings.editPattern(<?php echo $pattern['id']; ?>)"
                                                            title="Edit">
                                                        <i class="fas fa-edit"></i>
                                                    </button>
                                                    <button class="btn btn-outline-<?php echo $pattern['is_active'] ? 'warning' : 'success'; ?>" 
                                                            onclick="Settings.togglePattern(<?php echo $pattern['id']; ?>)"
                                                            title="<?php echo $pattern['is_active'] ? 'Deactivate' : 'Activate'; ?>">
                                                        <i class="fas fa-<?php echo $pattern['is_active'] ? 'pause' : 'play'; ?>"></i>
                                                    </button>
                                                    <button class="btn btn-outline-danger" 
                                                            onclick="Settings.deletePattern(<?php echo $pattern['id']; ?>)"
                                                            title="Delete">
                                                        <i class="fas fa-trash"></i>
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>
                                        <?php endforeach; ?>
                                    <?php else: ?>
                                    <tr>
                                        <td colspan="7" class="text-center text-muted py-4">
                                            <i class="fas fa-search fa-2x mb-2"></i><br>
                                            No threat patterns configured. Add your first pattern to get started.
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
    </div>
    
    <!-- Notifications -->
    <div class="tab-pane fade" id="notifications" role="tabpanel">
        <div class="row">
            <div class="col-lg-8">
                <div class="card shadow">
                    <div class="card-header py-3">
                        <h6 class="m-0 fw-bold text-primary">
                            <i class="fas fa-bell me-2"></i>Notification Settings
                        </h6>
                    </div>
                    <div class="card-body">
                        <form id="notificationSettingsForm">
                            <h6 class="text-muted mb-3">Email Notifications</h6>
                            
                            <div class="mb-3">
                                <div class="form-check form-switch">
                                    <input class="form-check-input" type="checkbox" id="notifyHighRisk" checked>
                                    <label class="form-check-label" for="notifyHighRisk">
                                        High Risk Threat Detection
                                    </label>
                                </div>
                            </div>
                            
                            <div class="mb-3">
                                <div class="form-check form-switch">
                                    <input class="form-check-input" type="checkbox" id="notifyQuarantine" checked>
                                    <label class="form-check-label" for="notifyQuarantine">
                                        Email Quarantine Actions
                                    </label>
                                </div>
                            </div>
                            
                            <div class="mb-3">
                                <div class="form-check form-switch">
                                    <input class="form-check-input" type="checkbox" id="notifySystemHealth">
                                    <label class="form-check-label" for="notifySystemHealth">
                                        System Health Issues
                                    </label>
                                </div>
                            </div>
                            
                            <hr>
                            
                            <h6 class="text-muted mb-3">Dashboard Alerts</h6>
                            
                            <div class="mb-3">
                                <div class="form-check form-switch">
                                    <input class="form-check-input" type="checkbox" id="realTimeAlerts" checked>
                                    <label class="form-check-label" for="realTimeAlerts">
                                        Real-time Threat Alerts
                                    </label>
                                </div>
                            </div>
                            
                            <div class="mb-3">
                                <div class="form-check form-switch">
                                    <input class="form-check-input" type="checkbox" id="soundAlerts">
                                    <label class="form-check-label" for="soundAlerts">
                                        Audio Notifications
                                    </label>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
            
            <div class="col-lg-4">
                <div class="card shadow">
                    <div class="card-header py-3">
                        <h6 class="m-0 fw-bold text-success">
                            <i class="fas fa-test-tube me-2"></i>Test Notifications
                        </h6>
                    </div>
                    <div class="card-body">
                        <p class="small text-muted mb-3">
                            Test your notification settings
                        </p>
                        
                        <button class="btn btn-outline-primary btn-sm w-100 mb-2" 
                                onclick="Settings.testEmailNotification()">
                            <i class="fas fa-envelope me-1"></i>Test Email
                        </button>
                        
                        <button class="btn btn-outline-success btn-sm w-100 mb-2" 
                                onclick="Settings.testDashboardAlert()">
                            <i class="fas fa-bell me-1"></i>Test Dashboard Alert
                        </button>
                        
                        <button class="btn btn-outline-warning btn-sm w-100" 
                                onclick="Settings.testSoundAlert()">
                            <i class="fas fa-volume-up me-1"></i>Test Sound Alert
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Advanced Settings -->
    <div class="tab-pane fade" id="advanced" role="tabpanel">
        <div class="row">
            <div class="col-12">
                <div class="card shadow mb-4">
                    <div class="card-header py-3">
                        <h6 class="m-0 fw-bold text-warning">
                            <i class="fas fa-exclamation-triangle me-2"></i>
                            Advanced Settings - Use with Caution
                        </h6>
                    </div>
                    <div class="card-body">
                        <div class="alert alert-warning">
                            <i class="fas fa-exclamation-triangle me-2"></i>
                            <strong>Warning:</strong> These settings can affect system performance and security. 
                            Only modify these settings if you understand their impact.
                        </div>
                        
                        <form id="advancedSettingsForm">
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label for="debugMode" class="form-label">Debug Mode</label>
                                        <div class="form-check form-switch">
                                            <input class="form-check-input" type="checkbox" id="debugMode">
                                            <label class="form-check-label" for="debugMode">
                                                Enable debug logging
                                            </label>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label for="maintenanceMode" class="form-label">Maintenance Mode</label>
                                        <div class="form-check form-switch">
                                            <input class="form-check-input" type="checkbox" id="maintenanceMode">
                                            <label class="form-check-label" for="maintenanceMode">
                                                Enable maintenance mode
                                            </label>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <hr>
                            
                            <h6 class="text-danger mb-3">Dangerous Actions</h6>
                            
                            <div class="row">
                                <div class="col-md-4">
                                    <button type="button" class="btn btn-outline-warning w-100" 
                                            onclick="Settings.resetAllPatterns()">
                                        <i class="fas fa-undo me-1"></i>Reset All Patterns
                                    </button>
                                </div>
                                <div class="col-md-4">
                                    <button type="button" class="btn btn-outline-danger w-100" 
                                            onclick="Settings.clearAllData()">
                                        <i class="fas fa-trash me-1"></i>Clear All Data
                                    </button>
                                </div>
                                <div class="col-md-4">
                                    <button type="button" class="btn btn-outline-dark w-100" 
                                            onclick="Settings.exportConfiguration()">
                                        <i class="fas fa-download me-1"></i>Export Config
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Add Pattern Modal -->
<div class="modal fade" id="addPatternModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">
                    <i class="fas fa-plus me-2"></i>Add Threat Pattern
                </h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <form id="addPatternForm">
                    <div class="row">
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label for="patternName" class="form-label">Pattern Name</label>
                                <input type="text" class="form-control" id="patternName" 
                                       name="name" required>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label for="patternType" class="form-label">Pattern Type</label>
                                <select class="form-select" id="patternType" name="pattern_type" required>
                                    <option value="literal">Literal Match</option>
                                    <option value="regex">Regular Expression</option>
                                    <option value="fuzzy">Fuzzy Match</option>
                                </select>
                            </div>
                        </div>
                    </div>
                    
                    <div class="row">
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label for="segmentStart" class="form-label">Segment Start</label>
                                <input type="text" class="form-control" id="segmentStart" 
                                       name="segment_start" placeholder="e.g., <body">
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label for="segmentEnd" class="form-label">Segment End</label>
                                <input type="text" class="form-control" id="segmentEnd" 
                                       name="segment_end" placeholder="e.g., </body>">
                            </div>
                        </div>
                    </div>
                    
                    <div class="mb-3">
                        <label for="patternText" class="form-label">Pattern Text</label>
                        <textarea class="form-control" id="patternText" name="pattern_text" 
                                  rows="3" required placeholder="Enter the pattern to match..."></textarea>
                    </div>
                    
                    <div class="row">
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label for="riskScore" class="form-label">Risk Score</label>
                                <input type="number" class="form-control" id="riskScore" 
                                       name="risk_score" min="1" max="100" value="10">
                                <div class="form-text">
                                    Points added to total risk score when matched (1-100)
                                </div>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label class="form-label">Status</label>
                                <div class="form-check form-switch">
                                    <input class="form-check-input" type="checkbox" id="patternActive" checked>
                                    <label class="form-check-label" for="patternActive">
                                        Active
                                    </label>
                                </div>
                            </div>
                        </div>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                <button type="button" class="btn btn-primary" onclick="Settings.savePattern()">
                    <i class="fas fa-save me-1"></i>Save Pattern
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Settings-specific styles -->
<style>
.nav-tabs .nav-link {
    border: none;
    color: #6c757d;
}

.nav-tabs .nav-link.active {
    background-color: #007bff;
    color: white;
    border-radius: 5px 5px 0 0;
}

.form-check-input:checked {
    background-color: #007bff;
    border-color: #007bff;
}

.alert-sm {
    padding: 0.375rem 0.75rem;
    margin-bottom: 0.5rem;
    font-size: 0.875rem;
}

.table code {
    font-size: 0.8rem;
    padding: 0.2rem 0.4rem;
    background-color: #f8f9fa;
    border-radius: 3px;
}

.card-header h6 {
    color: #495057;
}

@media (max-width: 768px) {
    .nav-tabs {
        flex-wrap: nowrap;
        overflow-x: auto;
    }
    
    .nav-tabs .nav-item {
        white-space: nowrap;
    }
    
    .btn-group .btn {
        padding: 0.25rem 0.5rem;
        font-size: 0.75rem;
    }
}
</style>
