<?php
/**
 * Header Template for Phishing Detection Platform
 * Contains HTML head, navigation, and page setup
 */

// Ensure configuration is loaded
if (!defined('APP_NAME')) {
    require_once dirname(__DIR__) . '/config.php';
}

// Set default page title if not provided
$pageTitle = $pageTitle ?? 'Dashboard';

// Initialize additional assets arrays if not set
$additionalCSS = $additionalCSS ?? [];
$additionalJS = $additionalJS ?? [];

// Generate CSRF token for forms
$csrfToken = generateCsrfToken();

// Get current page for navigation highlighting
$currentPage = $_GET['page'] ?? 'dashboard';

// Check if user has notification preferences
$notificationsEnabled = $_SESSION['notifications_enabled'] ?? true;
$theme = $_SESSION['theme'] ?? 'light';
?>
<!DOCTYPE html>
<html lang="en" data-theme="<?php echo htmlspecialchars($theme); ?>">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="Advanced cybersecurity phishing detection platform with real-time analysis and comprehensive threat management across all devices">
    <meta name="keywords" content="phishing detection, cybersecurity, email security, threat analysis, malware detection">
    <meta name="author" content="Phishing Detection Platform">
    <meta name="robots" content="noindex, nofollow">
    <meta name="theme-color" content="#4e73df">
    
    <title><?php echo htmlspecialchars($pageTitle); ?> - <?php echo htmlspecialchars(APP_NAME); ?></title>
    
    <!-- Favicon and App Icons -->
    <link rel="icon" type="image/x-icon" href="/static/images/favicon.ico">
    <link rel="apple-touch-icon" sizes="180x180" href="/static/images/apple-touch-icon.png">
    <link rel="icon" type="image/png" sizes="32x32" href="/static/images/favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="/static/images/favicon-16x16.png">
    <link rel="manifest" href="/static/manifest.json">
    
    <!-- Open Graph Meta Tags -->
    <meta property="og:title" content="<?php echo htmlspecialchars($pageTitle . ' - ' . APP_NAME); ?>">
    <meta property="og:description" content="Advanced cybersecurity phishing detection platform">
    <meta property="og:type" content="website">
    <meta property="og:url" content="<?php echo htmlspecialchars($_SERVER['REQUEST_URI']); ?>">
    <meta property="og:image" content="/static/images/og-image.png">
    
    <!-- Font Awesome Icons -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" 
          rel="stylesheet" 
          integrity="sha512-iecdLmaskl7CVkqkXNQ/ZH/XLlvWZOJyj7Yy7tcenmpD1ypASozpmT/E0iPtmFIB46ZmdtAc9eNBvH0H/ZpiBw==" 
          crossorigin="anonymous" 
          referrerpolicy="no-referrer">
    
    <!-- Google Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Nunito:ital,wght@0,200;0,300;0,400;0,600;0,700;0,800;0,900;1,200;1,300;1,400;1,600;1,700;1,800;1,900&display=swap" 
          rel="stylesheet">
    
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" 
          rel="stylesheet" 
          integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN" 
          crossorigin="anonymous">
    
    <!-- AOS (Animate On Scroll) -->
    <link href="https://unpkg.com/aos@2.3.1/dist/aos.css" rel="stylesheet">
    
    <!-- Custom CSS -->
    <link href="/static/css/style.css?v=<?php echo filemtime(__DIR__ . '/../static/css/style.css'); ?>" rel="stylesheet">
    
    <?php foreach ($additionalCSS as $css): ?>
    <link href="<?php echo htmlspecialchars($css); ?>" rel="stylesheet">
    <?php endforeach; ?>
    
    <!-- CSRF Token and Configuration -->
    <meta name="csrf-token" content="<?php echo htmlspecialchars($csrfToken); ?>">
    <meta name="api-base-url" content="/api.php">
    <meta name="app-version" content="<?php echo htmlspecialchars(APP_VERSION); ?>">
    <meta name="notifications-enabled" content="<?php echo $notificationsEnabled ? 'true' : 'false'; ?>">
    
    <!-- Preload Critical Resources -->
    <link rel="preload" href="/static/js/app.js" as="script">
    <link rel="preload" href="https://code.jquery.com/jquery-3.7.1.min.js" as="script" crossorigin>
    
    <!-- PWA Configuration -->
    <meta name="mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="default">
    <meta name="apple-mobile-web-app-title" content="<?php echo htmlspecialchars(APP_NAME); ?>">
    
    <!-- Security Headers -->
    <meta http-equiv="Content-Security-Policy" content="default-src 'self' 'unsafe-inline' 'unsafe-eval' https: data:; img-src 'self' data: https:;">
    <meta http-equiv="X-Content-Type-Options" content="nosniff">
    <meta http-equiv="X-Frame-Options" content="SAMEORIGIN">
    <meta http-equiv="X-XSS-Protection" content="1; mode=block">
    
    <!-- Dark Mode Detection Script -->
    <script>
        // Apply saved theme or detect system preference
        (function() {
            const savedTheme = localStorage.getItem('theme');
            const systemTheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
            const theme = savedTheme || systemTheme;
            document.documentElement.setAttribute('data-theme', theme);
        })();
    </script>
    
    <!-- Application Configuration -->
    <script>
        window.AppConfig = {
            apiBaseUrl: '/api.php',
            csrfToken: '<?php echo htmlspecialchars($csrfToken); ?>',
            currentPage: '<?php echo htmlspecialchars($currentPage); ?>',
            notificationsEnabled: <?php echo $notificationsEnabled ? 'true' : 'false'; ?>,
            theme: '<?php echo htmlspecialchars($theme); ?>',
            version: '<?php echo htmlspecialchars(APP_VERSION); ?>',
            uploadMaxSize: <?php echo MAX_FILE_SIZE; ?>,
            allowedExtensions: <?php echo json_encode(ALLOWED_EXTENSIONS); ?>,
            itemsPerPage: <?php echo ITEMS_PER_PAGE; ?>
        };
    </script>
</head>

<body id="page-top" class="<?php echo $theme === 'dark' ? 'dark-theme' : ''; ?>">
    <!-- Skip Navigation Link for Accessibility -->
    <a class="skip-link visually-hidden-focusable" href="#main-content">Skip to main content</a>
    
    <!-- Loading Indicator -->
    <div id="initial-loading" class="initial-loading">
        <div class="loading-content">
            <div class="loading-logo">
                <i class="fas fa-shield-alt fa-3x text-primary mb-3"></i>
            </div>
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Loading application...</span>
            </div>
            <p class="mt-3 text-muted">Initializing security platform...</p>
        </div>
    </div>
    
    <!-- Page Wrapper -->
    <div id="wrapper" class="wrapper">
        
        <!-- Sidebar -->
        <ul class="navbar-nav bg-gradient-primary sidebar sidebar-dark accordion" id="accordionSidebar">
            
            <!-- Sidebar Brand -->
            <a class="sidebar-brand d-flex align-items-center justify-content-center" href="index.php">
                <div class="sidebar-brand-icon rotate-n-15">
                    <i class="fas fa-shield-alt"></i>
                </div>
                <div class="sidebar-brand-text mx-3">
                    <span class="d-none d-lg-inline">Phishing Detection</span>
                    <span class="d-lg-none">PDP</span>
                </div>
            </a>
            
            <!-- Divider -->
            <hr class="sidebar-divider my-0">
            
            <!-- Dashboard Navigation -->
            <li class="nav-item <?php echo $currentPage === 'dashboard' ? 'active' : ''; ?>">
                <a class="nav-link" href="index.php">
                    <i class="fas fa-fw fa-tachometer-alt"></i>
                    <span>Dashboard</span>
                </a>
            </li>
            
            <!-- Divider -->
            <hr class="sidebar-divider">
            
            <!-- Analysis Section Heading -->
            <div class="sidebar-heading">
                Analysis & Detection
            </div>
            
            <!-- Email Analysis -->
            <li class="nav-item <?php echo $currentPage === 'upload' ? 'active' : ''; ?>">
                <a class="nav-link" href="index.php?page=upload">
                    <i class="fas fa-fw fa-upload"></i>
                    <span>Email Analysis</span>
                </a>
            </li>
            
            <!-- Reports & History -->
            <li class="nav-item <?php echo $currentPage === 'reports' ? 'active' : ''; ?>">
                <a class="nav-link" href="index.php?page=reports">
                    <i class="fas fa-fw fa-chart-bar"></i>
                    <span>Reports & History</span>
                </a>
            </li>
            
            <!-- Bulk Analysis -->
            <li class="nav-item">
                <a class="nav-link" href="#" onclick="Dashboard.showBulkUpload ? Dashboard.showBulkUpload() : PhishingApp.showBulkUpload()">
                    <i class="fas fa-fw fa-file-upload"></i>
                    <span>Bulk Analysis</span>
                </a>
            </li>
            
            <!-- Divider -->
            <hr class="sidebar-divider">
            
            <!-- Configuration Section Heading -->
            <div class="sidebar-heading">
                Configuration
            </div>
            
            <!-- Threat Patterns -->
            <li class="nav-item <?php echo $currentPage === 'settings' ? 'active' : ''; ?>">
                <a class="nav-link" href="index.php?page=settings">
                    <i class="fas fa-fw fa-cog"></i>
                    <span>Threat Patterns</span>
                </a>
            </li>
            
            <!-- System Health -->
            <li class="nav-item">
                <a class="nav-link" href="#" onclick="PhishingApp.checkSystemHealth()">
                    <i class="fas fa-fw fa-heartbeat"></i>
                    <span>System Health</span>
                </a>
            </li>
            
            <!-- Divider -->
            <hr class="sidebar-divider d-none d-md-block">
            
            <!-- System Status Card -->
            <div class="sidebar-card d-none d-lg-flex">
                <div class="card-body text-center">
                    <h6 class="text-white-50 mb-3">
                        <i class="fas fa-server me-1"></i>
                        System Status
                    </h6>
                    <div class="d-flex justify-content-between text-white-50 small mb-2">
                        <span>API Service:</span>
                        <span class="text-success" id="sidebar-api-status">
                            <i class="fas fa-circle fa-xs"></i> Online
                        </span>
                    </div>
                    <div class="d-flex justify-content-between text-white-50 small mb-2">
                        <span>ML Engine:</span>
                        <span class="text-success" id="sidebar-ml-status">
                            <i class="fas fa-circle fa-xs"></i> Active
                        </span>
                    </div>
                    <div class="d-flex justify-content-between text-white-50 small mb-3">
                        <span>Database:</span>
                        <span class="text-success" id="sidebar-db-status">
                            <i class="fas fa-circle fa-xs"></i> Connected
                        </span>
                    </div>
                    <div class="text-white-50 small">
                        Last Update: <br>
                        <span id="sidebar-last-update"><?php echo date('H:i:s'); ?></span>
                    </div>
                </div>
            </div>
            
            <!-- Sidebar Toggler -->
            <div class="text-center d-none d-md-inline">
                <button class="rounded-circle border-0 sidebar-toggle" id="sidebarToggle" 
                        aria-label="Toggle Sidebar"></button>
            </div>
            
        </ul>
        <!-- End of Sidebar -->
        
        <!-- Content Wrapper -->
        <div id="content-wrapper" class="content-wrapper d-flex flex-column">
            
            <!-- Main Content -->
            <div id="content">
                
                <!-- Topbar -->
                <nav class="navbar navbar-expand navbar-light bg-white topbar mb-4 static-top shadow">
                    
                    <!-- Sidebar Toggle (Topbar) -->
                    <button id="sidebarToggleTop" class="btn btn-link d-md-none rounded-circle me-3 sidebar-toggle mobile-menu-toggle" 
                            aria-label="Toggle Navigation">
                        <i class="fa fa-bars"></i>
                    </button>
                    
                    <!-- Topbar Search -->
                    <form class="d-none d-sm-inline-block form-inline me-auto ms-md-3 my-2 my-md-0 mw-100 navbar-search">
                        <div class="input-group">
                            <input type="text" class="form-control bg-light border-0 small" 
                                   placeholder="Search emails, senders, threats..." 
                                   aria-label="Global Search" 
                                   aria-describedby="search-addon" 
                                   id="global-search-input"
                                   autocomplete="off">
                            <button class="btn btn-primary" type="button" onclick="PhishingApp.openGlobalSearch()" 
                                    id="search-addon" aria-label="Open Search">
                                <i class="fas fa-search fa-sm"></i>
                            </button>
                        </div>
                    </form>
                    
                    <!-- Topbar Navbar -->
                    <ul class="navbar-nav ms-auto">
                        
                        <!-- Search Dropdown (Mobile) -->
                        <li class="nav-item dropdown no-arrow d-sm-none">
                            <a class="nav-link dropdown-toggle" href="#" id="searchDropdown" role="button" 
                               data-bs-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                                <i class="fas fa-search fa-fw"></i>
                            </a>
                            <div class="dropdown-menu dropdown-menu-end p-3 shadow animated--grow-in" 
                                 aria-labelledby="searchDropdown">
                                <form class="navbar-search">
                                    <div class="input-group">
                                        <input type="text" class="form-control bg-light border-0 small" 
                                               placeholder="Search..." aria-label="Mobile Search">
                                        <button class="btn btn-primary" type="button" onclick="PhishingApp.openGlobalSearch()">
                                            <i class="fas fa-search fa-sm"></i>
                                        </button>
                                    </div>
                                </form>
                            </div>
                        </li>
                        
                        <!-- Alerts Dropdown -->
                        <li class="nav-item dropdown no-arrow mx-1">
                            <a class="nav-link dropdown-toggle" href="#" id="alertsDropdown" role="button" 
                               data-bs-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                                <i class="fas fa-bell fa-fw"></i>
                                <span class="badge bg-danger badge-counter" id="alerts-counter">0</span>
                            </a>
                            <div class="dropdown-list dropdown-menu dropdown-menu-end shadow animated--grow-in" 
                                 aria-labelledby="alertsDropdown" style="min-width: 350px;">
                                <h6 class="dropdown-header bg-primary text-white">
                                    <i class="fas fa-shield-alt me-2"></i>
                                    Security Alerts
                                </h6>
                                <div id="alerts-list">
                                    <!-- Alerts will be populated by JavaScript -->
                                    <div class="dropdown-item text-center text-muted py-3">
                                        <i class="fas fa-check-circle fa-2x mb-2 d-block text-success"></i>
                                        No active alerts
                                    </div>
                                </div>
                                <a class="dropdown-item text-center small text-primary border-top" 
                                   href="index.php?page=reports&filter=alerts">
                                    <i class="fas fa-eye me-1"></i>
                                    View All Alerts
                                </a>
                            </div>
                        </li>
                        
                        <!-- Quick Actions Dropdown -->
                        <li class="nav-item dropdown no-arrow mx-1">
                            <a class="nav-link dropdown-toggle" href="#" id="actionsDropdown" role="button" 
                               data-bs-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                                <i class="fas fa-bolt fa-fw"></i>
                            </a>
                            <div class="dropdown-menu dropdown-menu-end shadow animated--grow-in" 
                                 aria-labelledby="actionsDropdown">
                                <h6 class="dropdown-header">Quick Actions</h6>
                                <a class="dropdown-item" href="index.php?page=upload">
                                    <i class="fas fa-upload fa-sm fa-fw me-2 text-primary"></i>
                                    Analyze Email
                                </a>
                                <a class="dropdown-item" href="#" onclick="PhishingApp.showBulkUpload()">
                                    <i class="fas fa-file-upload fa-sm fa-fw me-2 text-info"></i>
                                    Bulk Analysis
                                </a>
                                <div class="dropdown-divider"></div>
                                <a class="dropdown-item" href="#" onclick="PhishingApp.exportReport('pdf')">
                                    <i class="fas fa-file-pdf fa-sm fa-fw me-2 text-danger"></i>
                                    Export Report
                                </a>
                                <a class="dropdown-item" href="index.php?page=settings">
                                    <i class="fas fa-cog fa-sm fa-fw me-2 text-secondary"></i>
                                    Threat Patterns
                                </a>
                            </div>
                        </li>
                        
                        <!-- Theme Toggle -->
                        <li class="nav-item no-arrow mx-1">
                            <div class="nav-link">
                                <label class="theme-toggle" title="Toggle Theme" data-bs-toggle="tooltip">
                                    <input type="checkbox" <?php echo $theme === 'dark' ? 'checked' : ''; ?>>
                                    <span class="theme-slider"></span>
                                </label>
                            </div>
                        </li>
                        
                        <div class="topbar-divider d-none d-sm-block"></div>
                        
                        <!-- User Information -->
                        <li class="nav-item dropdown no-arrow">
                            <a class="nav-link dropdown-toggle" href="#" id="userDropdown" role="button" 
                               data-bs-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                                <span class="me-2 d-none d-lg-inline text-gray-600 small">Security Admin</span>
                                <div class="topbar-avatar">
                                    <i class="fas fa-user-shield fa-lg text-primary"></i>
                                </div>
                            </a>
                            <div class="dropdown-menu dropdown-menu-end shadow animated--grow-in" 
                                 aria-labelledby="userDropdown">
                                <div class="dropdown-header text-center">
                                    <div class="avatar-lg mb-2">
                                        <i class="fas fa-user-shield fa-2x text-primary"></i>
                                    </div>
                                    <strong>Security Administrator</strong><br>
                                    <small class="text-muted">admin@system.local</small>
                                </div>
                                <div class="dropdown-divider"></div>
                                <a class="dropdown-item" href="#" onclick="PhishingApp.showUserProfile()">
                                    <i class="fas fa-user fa-sm fa-fw me-2 text-gray-400"></i>
                                    Profile Settings
                                </a>
                                <a class="dropdown-item" href="index.php?page=settings">
                                    <i class="fas fa-cogs fa-sm fa-fw me-2 text-gray-400"></i>
                                    System Settings
                                </a>
                                <a class="dropdown-item" href="#" onclick="PhishingApp.showActivityLog()">
                                    <i class="fas fa-list fa-sm fa-fw me-2 text-gray-400"></i>
                                    Activity Log
                                </a>
                                <a class="dropdown-item" href="#" onclick="PhishingApp.showSystemInfo()">
                                    <i class="fas fa-info-circle fa-sm fa-fw me-2 text-gray-400"></i>
                                    System Information
                                </a>
                                <div class="dropdown-divider"></div>
                                <a class="dropdown-item" href="#" onclick="PhishingApp.logout()">
                                    <i class="fas fa-sign-out-alt fa-sm fa-fw me-2 text-gray-400"></i>
                                    Logout
                                </a>
                            </div>
                        </li>
                        
                    </ul>
                    
                </nav>
                <!-- End of Topbar -->
                
                <!-- Begin Page Content -->
                <main id="main-content" class="main-content" role="main">
