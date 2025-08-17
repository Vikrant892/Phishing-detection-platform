<?php
/**
 * Main Layout Template for Phishing Detection Platform
 * Provides the base HTML structure with sidebar navigation
 */

if (!defined('APP_NAME')) {
    require_once '../config.php';
}
?>
<!DOCTYPE html>
<html lang="en" data-theme="<?php echo $_SESSION['theme'] ?? 'light'; ?>">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="Advanced cybersecurity phishing detection platform with real-time analysis and comprehensive threat management">
    <meta name="author" content="Phishing Detection Platform">
    <meta name="robots" content="noindex, nofollow">
    
    <title><?php echo $pageTitle ?? 'Dashboard'; ?> - <?php echo APP_NAME; ?></title>
    
    <!-- Favicon -->
    <link rel="icon" type="image/x-icon" href="/static/images/favicon.ico">
    <link rel="apple-touch-icon" href="/static/images/apple-touch-icon.png">
    
    <!-- Font Awesome -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet" integrity="sha512-iecdLmaskl7CVkqkXNQ/ZH/XLlvWZOJyj7Yy7tcenmpD1ypASozpmT/E0iPtmFIB46ZmdtAc9eNBvH0H/ZpiBw==" crossorigin="anonymous">
    
    <!-- Google Fonts -->
    <link href="https://fonts.googleapis.com/css2?family=Nunito:ital,wght@0,200;0,300;0,400;0,600;0,700;0,800;0,900;1,200;1,300;1,400;1,600;1,700;1,800;1,900&display=swap" rel="stylesheet">
    
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN" crossorigin="anonymous">
    
    <!-- AOS (Animate On Scroll) -->
    <link href="https://unpkg.com/aos@2.3.1/dist/aos.css" rel="stylesheet">
    
    <!-- Custom CSS -->
    <link href="/static/css/style.css" rel="stylesheet">
    
    <!-- CSRF Token -->
    <meta name="csrf-token" content="<?php echo generateCsrfToken(); ?>">
    
    <?php if (isset($additionalCSS)): ?>
    <!-- Page-specific CSS -->
    <?php foreach ($additionalCSS as $css): ?>
    <link href="<?php echo $css; ?>" rel="stylesheet">
    <?php endforeach; ?>
    <?php endif; ?>
</head>

<body id="page-top">
    <!-- Page Wrapper -->
    <div id="wrapper" class="wrapper">
        
        <!-- Sidebar -->
        <ul class="navbar-nav bg-gradient-primary sidebar sidebar-dark accordion" id="accordionSidebar">
            
            <!-- Sidebar - Brand -->
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
            
            <!-- Navigation Items -->
            <li class="nav-item <?php echo (!isset($_GET['page']) || $_GET['page'] === 'dashboard') ? 'active' : ''; ?>">
                <a class="nav-link" href="index.php">
                    <i class="fas fa-fw fa-tachometer-alt"></i>
                    <span>Dashboard</span>
                </a>
            </li>
            
            <!-- Divider -->
            <hr class="sidebar-divider">
            
            <!-- Heading -->
            <div class="sidebar-heading">
                Analysis
            </div>
            
            <li class="nav-item <?php echo (isset($_GET['page']) && $_GET['page'] === 'upload') ? 'active' : ''; ?>">
                <a class="nav-link" href="index.php?page=upload">
                    <i class="fas fa-fw fa-upload"></i>
                    <span>Email Analysis</span>
                </a>
            </li>
            
            <li class="nav-item <?php echo (isset($_GET['page']) && $_GET['page'] === 'reports') ? 'active' : ''; ?>">
                <a class="nav-link" href="index.php?page=reports">
                    <i class="fas fa-fw fa-chart-bar"></i>
                    <span>Reports & History</span>
                </a>
            </li>
            
            <!-- Divider -->
            <hr class="sidebar-divider">
            
            <!-- Heading -->
            <div class="sidebar-heading">
                Configuration
            </div>
            
            <li class="nav-item <?php echo (isset($_GET['page']) && $_GET['page'] === 'settings') ? 'active' : ''; ?>">
                <a class="nav-link" href="index.php?page=settings">
                    <i class="fas fa-fw fa-cog"></i>
                    <span>Settings</span>
                </a>
            </li>
            
            <!-- Divider -->
            <hr class="sidebar-divider d-none d-md-block">
            
            <!-- System Status -->
            <div class="sidebar-card d-none d-lg-flex">
                <div class="card-body text-center">
                    <h6 class="text-white-50">System Status</h6>
                    <div class="d-flex justify-content-between text-white-50 small mb-2">
                        <span>API:</span>
                        <span class="text-success">Online</span>
                    </div>
                    <div class="d-flex justify-content-between text-white-50 small mb-2">
                        <span>ML Engine:</span>
                        <span class="text-success">Active</span>
                    </div>
                    <div class="text-white-50 small">
                        Last Update: <span id="sidebar-last-update"><?php echo date('H:i'); ?></span>
                    </div>
                </div>
            </div>
            
            <!-- Sidebar Toggler (Sidebar) -->
            <div class="text-center d-none d-md-inline">
                <button class="rounded-circle border-0 sidebar-toggle" id="sidebarToggle"></button>
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
                    <button id="sidebarToggleTop" class="btn btn-link d-md-none rounded-circle mr-3 sidebar-toggle">
                        <i class="fa fa-bars"></i>
                    </button>
                    
                    <!-- Topbar Search -->
                    <form class="d-none d-sm-inline-block form-inline mr-auto ml-md-3 my-2 my-md-0 mw-100 navbar-search">
                        <div class="input-group">
                            <input type="text" class="form-control bg-light border-0 small" 
                                   placeholder="Search emails, senders..." aria-label="Search" 
                                   aria-describedby="basic-addon2" id="global-search-input">
                            <div class="input-group-append">
                                <button class="btn btn-primary" type="button" onclick="PhishingApp.openGlobalSearch()">
                                    <i class="fas fa-search fa-sm"></i>
                                </button>
                            </div>
                        </div>
                    </form>
                    
                    <!-- Topbar Navbar -->
                    <ul class="navbar-nav ml-auto">
                        
                        <!-- Search Dropdown (Visible Only XS) -->
                        <li class="nav-item dropdown no-arrow d-sm-none">
                            <a class="nav-link dropdown-toggle" href="#" id="searchDropdown" role="button" 
                               data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                                <i class="fas fa-search fa-fw"></i>
                            </a>
                            <div class="dropdown-menu dropdown-menu-right p-3 shadow animated--grow-in" 
                                 aria-labelledby="searchDropdown">
                                <form class="form-inline mr-auto w-100 navbar-search">
                                    <div class="input-group">
                                        <input type="text" class="form-control bg-light border-0 small" 
                                               placeholder="Search for..." aria-label="Search" 
                                               aria-describedby="basic-addon2">
                                        <div class="input-group-append">
                                            <button class="btn btn-primary" type="button">
                                                <i class="fas fa-search fa-sm"></i>
                                            </button>
                                        </div>
                                    </div>
                                </form>
                            </div>
                        </li>
                        
                        <!-- Alerts Dropdown -->
                        <li class="nav-item dropdown no-arrow mx-1">
                            <a class="nav-link dropdown-toggle" href="#" id="alertsDropdown" role="button" 
                               data-bs-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                                <i class="fas fa-bell fa-fw"></i>
                                <span class="badge badge-danger badge-counter" id="alerts-counter">3+</span>
                            </a>
                            <div class="dropdown-list dropdown-menu dropdown-menu-right shadow animated--grow-in" 
                                 aria-labelledby="alertsDropdown">
                                <h6 class="dropdown-header">
                                    Security Alerts
                                </h6>
                                <a class="dropdown-item d-flex align-items-center" href="#">
                                    <div class="mr-3">
                                        <div class="icon-circle bg-danger">
                                            <i class="fas fa-exclamation-triangle text-white"></i>
                                        </div>
                                    </div>
                                    <div>
                                        <div class="small text-gray-500">December 12, 2019</div>
                                        <span class="font-weight-bold">High-risk email detected from suspicious domain</span>
                                    </div>
                                </a>
                                <a class="dropdown-item d-flex align-items-center" href="#">
                                    <div class="mr-3">
                                        <div class="icon-circle bg-warning">
                                            <i class="fas fa-shield-alt text-white"></i>
                                        </div>
                                    </div>
                                    <div>
                                        <div class="small text-gray-500">December 7, 2019</div>
                                        Multiple phishing attempts blocked
                                    </div>
                                </a>
                                <a class="dropdown-item d-flex align-items-center" href="#">
                                    <div class="mr-3">
                                        <div class="icon-circle bg-primary">
                                            <i class="fas fa-lock text-white"></i>
                                        </div>
                                    </div>
                                    <div>
                                        <div class="small text-gray-500">December 2, 2019</div>
                                        Email quarantined successfully
                                    </div>
                                </a>
                                <a class="dropdown-item text-center small text-gray-500" href="#">Show All Alerts</a>
                            </div>
                        </li>
                        
                        <!-- Theme Toggle -->
                        <li class="nav-item no-arrow mx-1">
                            <div class="nav-link">
                                <label class="theme-toggle">
                                    <input type="checkbox" <?php echo ($_SESSION['theme'] ?? 'light') === 'dark' ? 'checked' : ''; ?>>
                                    <span class="theme-slider"></span>
                                </label>
                            </div>
                        </li>
                        
                        <div class="topbar-divider d-none d-sm-block"></div>
                        
                        <!-- User Information -->
                        <li class="nav-item dropdown no-arrow">
                            <a class="nav-link dropdown-toggle" href="#" id="userDropdown" role="button" 
                               data-bs-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                                <span class="mr-2 d-none d-lg-inline text-gray-600 small">Security Admin</span>
                                <div class="topbar-avatar">
                                    <i class="fas fa-user-shield fa-lg"></i>
                                </div>
                            </a>
                            <div class="dropdown-menu dropdown-menu-right shadow animated--grow-in" 
                                 aria-labelledby="userDropdown">
                                <a class="dropdown-item" href="#" onclick="PhishingApp.showUserProfile()">
                                    <i class="fas fa-user fa-sm fa-fw mr-2 text-gray-400"></i>
                                    Profile
                                </a>
                                <a class="dropdown-item" href="index.php?page=settings">
                                    <i class="fas fa-cogs fa-sm fa-fw mr-2 text-gray-400"></i>
                                    Settings
                                </a>
                                <a class="dropdown-item" href="#" onclick="PhishingApp.showActivityLog()">
                                    <i class="fas fa-list fa-sm fa-fw mr-2 text-gray-400"></i>
                                    Activity Log
                                </a>
                                <div class="dropdown-divider"></div>
                                <a class="dropdown-item" href="#" onclick="PhishingApp.logout()">
                                    <i class="fas fa-sign-out-alt fa-sm fa-fw mr-2 text-gray-400"></i>
                                    Logout
                                </a>
                            </div>
                        </li>
                    </ul>
                </nav>
                <!-- End of Topbar -->
                
                <!-- Begin Page Content -->
                <div class="container-fluid">
                    <?php echo $content ?? ''; ?>
                </div>
                <!-- /.container-fluid -->
                
            </div>
            <!-- End of Main Content -->
            
            <!-- Footer -->
            <footer class="sticky-footer bg-white">
                <div class="container my-auto">
                    <div class="copyright text-center my-auto">
                        <span>&copy; <?php echo date('Y'); ?> <?php echo APP_NAME; ?>. Advanced cybersecurity threat detection platform.</span>
                    </div>
                </div>
            </footer>
            <!-- End of Footer -->
            
        </div>
        <!-- End of Content Wrapper -->
        
    </div>
    <!-- End of Page Wrapper -->
    
    <!-- Scroll to Top Button-->
    <a class="scroll-to-top rounded" href="#page-top">
        <i class="fas fa-angle-up"></i>
    </a>
    
    <!-- Floating Action Button for Quick Upload -->
    <button class="fab" onclick="document.getElementById('quick-upload-input').click()" 
            title="Quick Email Upload" data-bs-toggle="tooltip">
        <i class="fas fa-plus"></i>
    </button>
    
    <!-- Hidden quick upload input -->
    <input type="file" id="quick-upload-input" accept=".eml,.msg,.txt" 
           style="display: none;" onchange="PhishingApp.handleQuickUpload(this.files[0])">
    
    <!-- Notification Container -->
    <div class="notification-container"></div>
    
    <!-- Loading Overlay -->
    <div id="loading-overlay" class="loading-overlay d-none">
        <div class="spinner-border text-primary" role="status">
            <span class="visually-hidden">Loading...</span>
        </div>
    </div>
    
    <?php if (isset($additionalHTML)): ?>
    <!-- Page-specific HTML -->
    <?php echo $additionalHTML; ?>
    <?php endif; ?>
    
    <!-- JavaScript Libraries -->
    <script src="https://code.jquery.com/jquery-3.7.1.min.js" integrity="sha256-/JqT3SQfawRcv/BIHPThkBvs0OEvtFFmqPF/lYI/Cxo=" crossorigin="anonymous"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-C6RzsynM9kWDrMNeT87bh95OGNyZPhcTNXj1NW7RuBCsyN/o0jlpcV8Qyq46cDfL" crossorigin="anonymous"></script>
    
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.min.js" integrity="sha256-qElp0K9E3r98BaW9s4+hNNi7c31jkVOqUx5oQFp/kD8=" crossorigin="anonymous"></script>
    
    <!-- AOS (Animate On Scroll) -->
    <script src="https://unpkg.com/aos@2.3.1/dist/aos.js"></script>
    
    <!-- Custom JavaScript -->
    <script src="/static/js/app.js"></script>
    <script src="/static/js/dashboard.js"></script>
    
    <?php if (isset($additionalJS)): ?>
    <!-- Page-specific JavaScript -->
    <?php foreach ($additionalJS as $js): ?>
    <script src="<?php echo $js; ?>"></script>
    <?php endforeach; ?>
    <?php endif; ?>
    
    <!-- Initialize AOS -->
    <script>
        AOS.init({
            duration: 800,
            easing: 'ease-in-out',
            once: true,
            mirror: false
        });
    </script>
    
    <!-- Page-specific JavaScript -->
    <?php if (isset($inlineJS)): ?>
    <script>
        <?php echo $inlineJS; ?>
    </script>
    <?php endif; ?>
    
</body>
</html>
