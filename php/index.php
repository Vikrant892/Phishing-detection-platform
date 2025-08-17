<?php
/**
 * Phishing Detection Platform - Main Entry Point
 * Advanced cybersecurity dashboard with responsive design
 */

require_once 'config.php';
require_once 'templates/header.php';

// Check if user is accessing a specific page
$page = $_GET['page'] ?? 'dashboard';

// Route to appropriate page
switch ($page) {
    case 'dashboard':
        require_once 'dashboard.php';
        break;
    case 'upload':
        require_once 'upload.php';
        break;
    case 'reports':
        require_once 'reports.php';
        break;
    case 'settings':
        require_once 'settings.php';
        break;
    default:
        require_once 'dashboard.php';
        break;
}

require_once 'templates/footer.php';
?>
