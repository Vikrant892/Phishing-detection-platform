<?php
/**
 * Authentication and Authorization Functions
 */

/**
 * Check if user is authenticated
 */
function isAuthenticated() {
    // Check if session exists and is valid
    if (!isset($_SESSION['authenticated']) || !$_SESSION['authenticated']) {
        return false;
    }
    
    // Check session timeout
    if (isset($_SESSION['login_time'])) {
        $sessionAge = time() - $_SESSION['login_time'];
        if ($sessionAge > SESSION_TIMEOUT) {
            logout();
            return false;
        }
    }
    
    // Update last activity time
    $_SESSION['last_activity'] = time();
    
    return true;
}

/**
 * Authenticate user (simplified for demo)
 */
function authenticate($username, $password) {
    // Authentication handled by AuthManager class - see php/classes/AuthManager.php
    if (AuthManager::verify($username, $password)) {
        $_SESSION['authenticated'] = true;
        $_SESSION['user_id'] = $username;
        $_SESSION['username'] = $username;
        $_SESSION['login_time'] = time();
        $_SESSION['last_activity'] = time();
        $_SESSION['user_role'] = getUserRole($username);
        
        // Log successful login
        logMessage("User authenticated: $username from " . getClientIP(), 'INFO');
        
        return [
            'success' => true,
            'message' => 'Authentication successful',
            'user' => [
                'id' => $username,
                'username' => $username,
                'role' => $_SESSION['user_role']
            ]
        ];
    }
    
    // Log failed login attempt
    logMessage("Failed login attempt: $username from " . getClientIP(), 'WARNING');
    
    return [
        'success' => false,
        'message' => 'Invalid username or password'
    ];
}

/**
 * Logout user
 */
function logout() {
    $username = $_SESSION['username'] ?? 'unknown';
    
    // Clear session
    session_unset();
    session_destroy();
    
    // Start new session
    session_start();
    session_regenerate_id(true);
    
    // Log logout
    logMessage("User logged out: $username", 'INFO');
    
    return true;
}

/**
 * Get user role
 */
function getUserRole($username) {
    $roles = [
        'admin' => 'administrator',
        'analyst' => 'security_analyst',
        'operator' => 'operator'
    ];
    
    return $roles[$username] ?? 'user';
}

/**
 * Check if user has permission
 */
function hasPermission($permission) {
    if (!isAuthenticated()) {
        return false;
    }
    
    $userRole = $_SESSION['user_role'] ?? 'user';
    
    $permissions = [
        'administrator' => [
            'view_dashboard',
            'analyze_emails',
            'generate_reports',
            'manage_settings',
            'manage_quarantine',
            'manage_patterns',
            'manage_users',
            'export_data',
            'view_logs'
        ],
        'security_analyst' => [
            'view_dashboard',
            'analyze_emails',
            'generate_reports',
            'manage_quarantine',
            'manage_patterns',
            'export_data'
        ],
        'operator' => [
            'view_dashboard',
            'analyze_emails',
            'generate_reports'
        ],
        'user' => [
            'view_dashboard'
        ]
    ];
    
    $userPermissions = $permissions[$userRole] ?? [];
    
    return in_array($permission, $userPermissions);
}

/**
 * Require authentication
 */
function requireAuth($redirectUrl = '/php/login.php') {
    if (!isAuthenticated()) {
        if (isAjaxRequest()) {
            sendJSONResponse([
                'success' => false,
                'message' => 'Authentication required',
                'redirect' => $redirectUrl
            ], 401);
        } else {
            header("Location: $redirectUrl");
            exit;
        }
    }
}

/**
 * Require specific permission
 */
function requirePermission($permission, $errorMessage = 'Access denied') {
    requireAuth();
    
    if (!hasPermission($permission)) {
        if (isAjaxRequest()) {
            sendJSONResponse([
                'success' => false,
                'message' => $errorMessage
            ], 403);
        } else {
            die($errorMessage);
        }
    }
}

/**
 * Get current user info
 */
function getCurrentUser() {
    if (!isAuthenticated()) {
        return null;
    }
    
    return [
        'id' => $_SESSION['user_id'] ?? null,
        'username' => $_SESSION['username'] ?? null,
        'role' => $_SESSION['user_role'] ?? null,
        'login_time' => $_SESSION['login_time'] ?? null,
        'last_activity' => $_SESSION['last_activity'] ?? null
    ];
}

/**
 * Generate secure session token
 */
function generateSessionToken() {
    return bin2hex(random_bytes(32));
}

/**
 * Validate session token
 */
function validateSessionToken($token) {
    return isset($_SESSION['session_token']) && 
           hash_equals($_SESSION['session_token'], $token);
}

/**
 * Refresh session
 */
function refreshSession() {
    if (!isAuthenticated()) {
        return false;
    }
    
    // Regenerate session ID
    session_regenerate_id(true);
    
    // Update last activity
    $_SESSION['last_activity'] = time();
    
    // Generate new session token
    $_SESSION['session_token'] = generateSessionToken();
    
    return true;
}

/**
 * Check for session hijacking
 */
function checkSessionSecurity() {
    if (!isAuthenticated()) {
        return true;
    }
    
    // Check user agent consistency
    if (isset($_SESSION['user_agent'])) {
        $currentUserAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        if ($_SESSION['user_agent'] !== $currentUserAgent) {
            logMessage("Session hijacking attempt detected for user: " . 
                      ($_SESSION['username'] ?? 'unknown'), 'WARNING');
            logout();
            return false;
        }
    } else {
        $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? '';
    }
    
    // Check IP address consistency (optional, can cause issues with proxy users)
    if (isset($_SESSION['ip_address'])) {
        $currentIP = getClientIP();
        if ($_SESSION['ip_address'] !== $currentIP) {
            logMessage("IP address change detected for user: " . 
                      ($_SESSION['username'] ?? 'unknown') . 
                      " (Old: {$_SESSION['ip_address']}, New: $currentIP)", 'INFO');
            // Note: Not logging out on IP change as it can be legitimate
        }
    } else {
        $_SESSION['ip_address'] = getClientIP();
    }
    
    return true;
}

/**
 * Login rate limiting
 */
function checkLoginRateLimit($username) {
    $rateLimitFile = TEMP_DIR . '/login_attempts.json';
    $attempts = [];
    
    // Load existing attempts
    if (file_exists($rateLimitFile)) {
        $data = file_get_contents($rateLimitFile);
        $attempts = json_decode($data, true) ?: [];
    }
    
    $clientIP = getClientIP();
    $currentTime = time();
    $lockoutDuration = 900; // 15 minutes
    $maxAttempts = 5;
    
    // Clean old attempts
    foreach ($attempts as $key => $attempt) {
        if ($currentTime - $attempt['time'] > $lockoutDuration) {
            unset($attempts[$key]);
        }
    }
    
    // Count recent attempts for this IP/username combination
    $recentAttempts = 0;
    foreach ($attempts as $attempt) {
        if ($attempt['ip'] === $clientIP && $attempt['username'] === $username) {
            $recentAttempts++;
        }
    }
    
    // Check if locked out
    if ($recentAttempts >= $maxAttempts) {
        return [
            'allowed' => false,
            'message' => 'Too many login attempts. Please try again later.',
            'lockout_remaining' => $lockoutDuration - ($currentTime - $attempts[0]['time'])
        ];
    }
    
    return ['allowed' => true];
}

/**
 * Record failed login attempt
 */
function recordFailedLogin($username) {
    $rateLimitFile = TEMP_DIR . '/login_attempts.json';
    $attempts = [];
    
    // Load existing attempts
    if (file_exists($rateLimitFile)) {
        $data = file_get_contents($rateLimitFile);
        $attempts = json_decode($data, true) ?: [];
    }
    
    // Add new attempt
    $attempts[] = [
        'username' => $username,
        'ip' => getClientIP(),
        'time' => time()
    ];
    
    // Save attempts
    file_put_contents($rateLimitFile, json_encode($attempts), LOCK_EX);
}

/**
 * Generate password hash (for future use)
 */
function hashPassword($password) {
    return password_hash($password, PASSWORD_DEFAULT);
}

/**
 * Verify password hash (for future use)
 */
function verifyPassword($password, $hash) {
    return password_verify($password, $hash);
}

/**
 * Generate secure random password
 */
function generateSecurePassword($length = 12) {
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
    $password = '';
    
    for ($i = 0; $i < $length; $i++) {
        $password .= $chars[random_int(0, strlen($chars) - 1)];
    }
    
    return $password;
}

/**
 * Check password strength
 */
function checkPasswordStrength($password) {
    $strength = 0;
    $feedback = [];
    
    // Length check
    if (strlen($password) >= 8) {
        $strength += 1;
    } else {
        $feedback[] = 'Password should be at least 8 characters long';
    }
    
    // Uppercase check
    if (preg_match('/[A-Z]/', $password)) {
        $strength += 1;
    } else {
        $feedback[] = 'Include at least one uppercase letter';
    }
    
    // Lowercase check
    if (preg_match('/[a-z]/', $password)) {
        $strength += 1;
    } else {
        $feedback[] = 'Include at least one lowercase letter';
    }
    
    // Number check
    if (preg_match('/[0-9]/', $password)) {
        $strength += 1;
    } else {
        $feedback[] = 'Include at least one number';
    }
    
    // Special character check
    if (preg_match('/[^A-Za-z0-9]/', $password)) {
        $strength += 1;
    } else {
        $feedback[] = 'Include at least one special character';
    }
    
    $levels = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'];
    
    return [
        'score' => $strength,
        'level' => $levels[$strength] ?? 'Very Weak',
        'feedback' => $feedback
    ];
}

// Initialize session security check on every request
if (session_status() === PHP_SESSION_ACTIVE) {
    checkSessionSecurity();
}
?>
