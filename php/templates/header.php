<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Advanced Cybersecurity Phishing Detection Platform">
    <meta name="author" content="Phishing Detection Team">
    
    <title><?php echo $page_title; ?> | <?php echo APP_NAME; ?></title>
    
    <!-- Bootstrap 5 CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    
    <!-- Font Awesome Icons -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    
    <!-- Custom CSS -->
    <link href="assets/css/main.css" rel="stylesheet">
    
    <!-- Favicon -->
    <link rel="icon" type="image/x-icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡️</text></svg>">
    
    <!-- PWA Manifest -->
    <link rel="manifest" href="manifest.json">
    <meta name="theme-color" content="#007bff">
    
    <!-- Meta tags for mobile -->
    <meta name="mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="default">
    
    <!-- CSRF Token -->
    <meta name="csrf-token" content="<?php echo generateCSRFToken(); ?>">
</head>
<body class="<?php echo $current_page; ?>-page">
    
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary fixed-top">
        <div class="container-fluid">
            <!-- Brand -->
            <a class="navbar-brand d-flex align-items-center" href="/php/">
                <i class="fas fa-shield-alt me-2"></i>
                <span class="d-none d-md-inline"><?php echo APP_NAME; ?></span>
                <span class="d-md-none">PDP</span>
            </a>
            
            <!-- Mobile toggle button -->
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            
            <!-- Navigation items -->
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item">
                        <a class="nav-link <?php echo $current_page === 'dashboard' ? 'active' : ''; ?>" 
                           href="/php/dashboard">
                            <i class="fas fa-tachometer-alt me-1"></i>
                            <span class="d-lg-inline d-none">Dashboard</span>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link <?php echo $current_page === 'analysis' ? 'active' : ''; ?>" 
                           href="/php/analysis">
                            <i class="fas fa-search me-1"></i>
                            <span class="d-lg-inline d-none">Analysis</span>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link <?php echo $current_page === 'reports' ? 'active' : ''; ?>" 
                           href="/php/reports">
                            <i class="fas fa-chart-line me-1"></i>
                            <span class="d-lg-inline d-none">Reports</span>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link <?php echo $current_page === 'settings' ? 'active' : ''; ?>" 
                           href="/php/settings">
                            <i class="fas fa-cog me-1"></i>
                            <span class="d-lg-inline d-none">Settings</span>
                        </a>
                    </li>
                </ul>
                
                <!-- Right side navigation -->
                <ul class="navbar-nav">
                    <!-- Real-time threat indicator -->
                    <li class="nav-item">
                        <span class="nav-link" id="threatIndicator">
                            <i class="fas fa-circle text-success me-1" id="threatIcon"></i>
                            <span class="d-none d-lg-inline" id="threatStatus">All Clear</span>
                        </span>
                    </li>
                    
                    <!-- Notifications -->
                    <li class="nav-item dropdown">
                        <a class="nav-link position-relative" href="#" id="notificationsDropdown" 
                           data-bs-toggle="dropdown">
                            <i class="fas fa-bell"></i>
                            <span class="position-absolute top-0 start-100 translate-middle badge rounded-pill bg-danger d-none" 
                                  id="notificationBadge">0</span>
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end notification-dropdown" style="width: 300px;">
                            <li class="dropdown-header">
                                <i class="fas fa-bell me-2"></i>Recent Alerts
                            </li>
                            <li><hr class="dropdown-divider"></li>
                            <li id="notificationsList">
                                <div class="text-center p-3 text-muted">
                                    <i class="fas fa-check-circle fa-2x mb-2"></i><br>
                                    No new alerts
                                </div>
                            </li>
                            <li><hr class="dropdown-divider"></li>
                            <li>
                                <a class="dropdown-item text-center" href="/php/reports">
                                    <small>View All Reports</small>
                                </a>
                            </li>
                        </ul>
                    </li>
                    
                    <!-- User menu -->
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" id="userDropdown" 
                           data-bs-toggle="dropdown">
                            <i class="fas fa-user-circle me-1"></i>
                            <span class="d-none d-lg-inline">
                                <?php echo $_SESSION['username'] ?? 'User'; ?>
                            </span>
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end">
                            <li class="dropdown-header">
                                <i class="fas fa-user me-2"></i>
                                <?php echo $_SESSION['username'] ?? 'User'; ?>
                                <small class="d-block text-muted">
                                    <?php echo ucfirst($_SESSION['user_role'] ?? 'user'); ?>
                                </small>
                            </li>
                            <li><hr class="dropdown-divider"></li>
                            <li>
                                <a class="dropdown-item" href="/php/settings">
                                    <i class="fas fa-cog me-2"></i>Settings
                                </a>
                            </li>
                            <li>
                                <a class="dropdown-item" href="#" onclick="toggleTheme()">
                                    <i class="fas fa-moon me-2" id="themeIcon"></i>
                                    <span id="themeText">Dark Mode</span>
                                </a>
                            </li>
                            <li><hr class="dropdown-divider"></li>
                            <li>
                                <a class="dropdown-item text-danger" href="/php/logout">
                                    <i class="fas fa-sign-out-alt me-2"></i>Logout
                                </a>
                            </li>
                        </ul>
                    </li>
                </ul>
            </div>
        </div>
    </nav>
    
    <!-- Main content area -->
    <main class="main-content">
        <div class="container-fluid">
            <!-- Page breadcrumb -->
            <?php if ($current_page !== 'dashboard'): ?>
            <nav aria-label="breadcrumb" class="mb-3">
                <ol class="breadcrumb">
                    <li class="breadcrumb-item">
                        <a href="/php/dashboard"><i class="fas fa-home"></i></a>
                    </li>
                    <li class="breadcrumb-item active">
                        <?php echo ucfirst($current_page); ?>
                    </li>
                </ol>
            </nav>
            <?php endif; ?>
            
            <!-- Flash messages -->
            <div id="flashMessages"></div>
            
            <!-- Page alerts -->
            <?php if (isset($page_data['error'])): ?>
            <div class="alert alert-danger alert-dismissible fade show" role="alert">
                <i class="fas fa-exclamation-triangle me-2"></i>
                <strong>Error:</strong> <?php echo htmlspecialchars($page_data['error']); ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
            <?php endif; ?>
            
            <!-- Backend status check -->
            <div class="alert alert-warning alert-dismissible fade show d-none" id="backendOfflineAlert" role="alert">
                <i class="fas fa-exclamation-triangle me-2"></i>
                <strong>Warning:</strong> Backend analysis service is offline. Some features may be limited.
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
