<?php

/**
 * Authentication Manager Class
 * Handles user authentication, session management, and access control
 */
class AuthManager
{
    private $database;
    private $sessionTimeout;
    private $maxLoginAttempts;
    private $lockoutDuration;
    
    public function __construct(Database $database)
    {
        $this->database = $database;
        $this->sessionTimeout = 3600; // 1 hour
        $this->maxLoginAttempts = 5;
        $this->lockoutDuration = 900; // 15 minutes
        
        // Configure session
        $this->configureSession();
    }
    
    /**
     * Configure PHP session settings
     */
    private function configureSession()
    {
        // Set secure session parameters
        ini_set('session.cookie_httponly', 1);
        ini_set('session.use_only_cookies', 1);
        ini_set('session.cookie_secure', isset($_SERVER['HTTPS']));
        ini_set('session.gc_maxlifetime', $this->sessionTimeout);
        
        // Set session name
        session_name('phishing_detector_session');
    }
    
    /**
     * Authenticate user with username and password
     */
    public function authenticate($username, $password, $rememberMe = false)
    {
        try {
            // Check for account lockout
            if ($this->isAccountLocked($username)) {
                return [
                    'success' => false,
                    'error' => 'Account temporarily locked due to multiple failed attempts'
                ];
            }
            
            // Get user from database
            $user = $this->getUserByUsername($username);
            
            if (!$user || !$this->verifyPassword($password, $user['password_hash'])) {
                $this->recordFailedAttempt($username);
                return [
                    'success' => false,
                    'error' => 'Invalid username or password'
                ];
            }
            
            // Check if user is active
            if (!$user['is_active']) {
                return [
                    'success' => false,
                    'error' => 'Account is disabled'
                ];
            }
            
            // Clear failed attempts
            $this->clearFailedAttempts($username);
            
            // Create session
            $sessionId = $this->createSession($user, $rememberMe);
            
            // Update last login
            $this->updateLastLogin($user['id']);
            
            // Log successful login
            $this->logSecurityEvent('login_success', $user['id'], [
                'ip' => $this->getClientIP(),
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? ''
            ]);
            
            return [
                'success' => true,
                'user' => [
                    'id' => $user['id'],
                    'username' => $user['username'],
                    'email' => $user['email'],
                    'role' => $user['role'],
                    'permissions' => json_decode($user['permissions'] ?? '[]', true)
                ],
                'session_id' => $sessionId
            ];
            
        } catch (Exception $e) {
            error_log("Authentication error: " . $e->getMessage());
            return [
                'success' => false,
                'error' => 'Authentication failed'
            ];
        }
    }
    
    /**
     * Logout user and destroy session
     */
    public function logout($userId = null)
    {
        try {
            $sessionId = session_id();
            $userId = $userId ?? $_SESSION['user_id'] ?? null;
            
            // Remove session from database
            if ($sessionId) {
                $sql = "DELETE FROM user_sessions WHERE id = ?";
                $this->database->execute($sql, [$sessionId]);
            }
            
            // Log logout
            if ($userId) {
                $this->logSecurityEvent('logout', $userId, [
                    'ip' => $this->getClientIP()
                ]);
            }
            
            // Destroy PHP session
            session_unset();
            session_destroy();
            
            // Clear session cookie
            if (isset($_COOKIE[session_name()])) {
                setcookie(session_name(), '', time() - 3600, '/');
            }
            
            return true;
            
        } catch (Exception $e) {
            error_log("Logout error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Check if user is authenticated
     */
    public function isAuthenticated()
    {
        try {
            if (!isset($_SESSION['user_id']) || !isset($_SESSION['session_id'])) {
                return false;
            }
            
            // Check session in database
            $sql = "SELECT * FROM user_sessions WHERE id = ? AND expires_at > NOW()";
            $session = $this->database->fetchRow($sql, [$_SESSION['session_id']]);
            
            if (!$session) {
                $this->logout();
                return false;
            }
            
            // Update session activity
            $sql = "UPDATE user_sessions SET updated_at = NOW() WHERE id = ?";
            $this->database->execute($sql, [$_SESSION['session_id']]);
            
            return true;
            
        } catch (Exception $e) {
            error_log("Authentication check error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Get current authenticated user
     */
    public function getCurrentUser()
    {
        try {
            if (!$this->isAuthenticated()) {
                return null;
            }
            
            $sql = "SELECT u.*, s.created_at as session_created, s.updated_at as last_activity
                    FROM users u
                    JOIN user_sessions s ON u.id = s.user_id
                    WHERE s.id = ?";
            
            $user = $this->database->fetchRow($sql, [$_SESSION['session_id']]);
            
            if ($user) {
                $user['permissions'] = json_decode($user['permissions'] ?? '[]', true);
                unset($user['password_hash']); // Never return password hash
            }
            
            return $user;
            
        } catch (Exception $e) {
            error_log("Get current user error: " . $e->getMessage());
            return null;
        }
    }
    
    /**
     * Check if user has specific permission
     */
    public function hasPermission($permission)
    {
        $user = $this->getCurrentUser();
        
        if (!$user) {
            return false;
        }
        
        // Admin role has all permissions
        if ($user['role'] === 'admin') {
            return true;
        }
        
        return in_array($permission, $user['permissions']);
    }
    
    /**
     * Create user account
     */
    public function createUser($userData)
    {
        try {
            // Validate required fields
            $requiredFields = ['username', 'email', 'password'];
            foreach ($requiredFields as $field) {
                if (empty($userData[$field])) {
                    return [
                        'success' => false,
                        'error' => "Missing required field: $field"
                    ];
                }
            }
            
            // Check if username exists
            if ($this->getUserByUsername($userData['username'])) {
                return [
                    'success' => false,
                    'error' => 'Username already exists'
                ];
            }
            
            // Check if email exists
            if ($this->getUserByEmail($userData['email'])) {
                return [
                    'success' => false,
                    'error' => 'Email already exists'
                ];
            }
            
            // Validate password strength
            if (!$this->validatePassword($userData['password'])) {
                return [
                    'success' => false,
                    'error' => 'Password does not meet security requirements'
                ];
            }
            
            // Hash password
            $passwordHash = $this->hashPassword($userData['password']);
            
            // Insert user
            $sql = "INSERT INTO users (username, email, password_hash, role, permissions, is_active, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, NOW())";
            
            $permissions = json_encode($userData['permissions'] ?? []);
            $role = $userData['role'] ?? 'user';
            $isActive = $userData['is_active'] ?? true;
            
            $this->database->execute($sql, [
                $userData['username'],
                $userData['email'],
                $passwordHash,
                $role,
                $permissions,
                $isActive
            ]);
            
            $userId = $this->database->lastInsertId();
            
            // Log user creation
            $this->logSecurityEvent('user_created', $userId, [
                'created_by' => $_SESSION['user_id'] ?? 'system'
            ]);
            
            return [
                'success' => true,
                'user_id' => $userId
            ];
            
        } catch (Exception $e) {
            error_log("Create user error: " . $e->getMessage());
            return [
                'success' => false,
                'error' => 'Failed to create user'
            ];
        }
    }
    
    /**
     * Update user account
     */
    public function updateUser($userId, $userData)
    {
        try {
            $user = $this->getUserById($userId);
            if (!$user) {
                return [
                    'success' => false,
                    'error' => 'User not found'
                ];
            }
            
            $updateFields = [];
            $params = [];
            
            // Update allowed fields
            $allowedFields = ['email', 'role', 'permissions', 'is_active'];
            
            foreach ($allowedFields as $field) {
                if (array_key_exists($field, $userData)) {
                    if ($field === 'permissions') {
                        $updateFields[] = "$field = ?";
                        $params[] = json_encode($userData[$field]);
                    } else {
                        $updateFields[] = "$field = ?";
                        $params[] = $userData[$field];
                    }
                }
            }
            
            // Update password if provided
            if (!empty($userData['password'])) {
                if (!$this->validatePassword($userData['password'])) {
                    return [
                        'success' => false,
                        'error' => 'Password does not meet security requirements'
                    ];
                }
                
                $updateFields[] = "password_hash = ?";
                $params[] = $this->hashPassword($userData['password']);
            }
            
            if (empty($updateFields)) {
                return [
                    'success' => false,
                    'error' => 'No fields to update'
                ];
            }
            
            $updateFields[] = "updated_at = NOW()";
            $params[] = $userId;
            
            $sql = "UPDATE users SET " . implode(', ', $updateFields) . " WHERE id = ?";
            $this->database->execute($sql, $params);
            
            // Log user update
            $this->logSecurityEvent('user_updated', $userId, [
                'updated_by' => $_SESSION['user_id'] ?? 'system',
                'fields' => array_keys($userData)
            ]);
            
            return ['success' => true];
            
        } catch (Exception $e) {
            error_log("Update user error: " . $e->getMessage());
            return [
                'success' => false,
                'error' => 'Failed to update user'
            ];
        }
    }
    
    /**
     * Change password
     */
    public function changePassword($userId, $currentPassword, $newPassword)
    {
        try {
            $user = $this->getUserById($userId);
            if (!$user) {
                return [
                    'success' => false,
                    'error' => 'User not found'
                ];
            }
            
            // Verify current password
            if (!$this->verifyPassword($currentPassword, $user['password_hash'])) {
                return [
                    'success' => false,
                    'error' => 'Current password is incorrect'
                ];
            }
            
            // Validate new password
            if (!$this->validatePassword($newPassword)) {
                return [
                    'success' => false,
                    'error' => 'New password does not meet security requirements'
                ];
            }
            
            // Update password
            $sql = "UPDATE users SET password_hash = ?, updated_at = NOW() WHERE id = ?";
            $this->database->execute($sql, [$this->hashPassword($newPassword), $userId]);
            
            // Log password change
            $this->logSecurityEvent('password_changed', $userId, [
                'ip' => $this->getClientIP()
            ]);
            
            return ['success' => true];
            
        } catch (Exception $e) {
            error_log("Change password error: " . $e->getMessage());
            return [
                'success' => false,
                'error' => 'Failed to change password'
            ];
        }
    }
    
    /**
     * Create user session
     */
    private function createSession($user, $rememberMe = false)
    {
        $sessionId = bin2hex(random_bytes(32));
        $expiresAt = date('Y-m-d H:i:s', time() + ($rememberMe ? 30 * 24 * 3600 : $this->sessionTimeout));
        
        $sessionData = [
            'user_id' => $user['id'],
            'username' => $user['username'],
            'role' => $user['role'],
            'ip_address' => $this->getClientIP(),
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? ''
        ];
        
        $sql = "INSERT INTO user_sessions (id, user_id, session_data, expires_at, created_at, updated_at)
                VALUES (?, ?, ?, ?, NOW(), NOW())";
        
        $this->database->execute($sql, [
            $sessionId,
            $user['id'],
            json_encode($sessionData),
            $expiresAt
        ]);
        
        // Set session variables
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role'] = $user['role'];
        $_SESSION['session_id'] = $sessionId;
        
        return $sessionId;
    }
    
    /**
     * Get user by username
     */
    private function getUserByUsername($username)
    {
        $sql = "SELECT * FROM users WHERE username = ? AND is_active = 1";
        return $this->database->fetchRow($sql, [$username]);
    }
    
    /**
     * Get user by email
     */
    private function getUserByEmail($email)
    {
        $sql = "SELECT * FROM users WHERE email = ? AND is_active = 1";
        return $this->database->fetchRow($sql, [$email]);
    }
    
    /**
     * Get user by ID
     */
    private function getUserById($userId)
    {
        $sql = "SELECT * FROM users WHERE id = ?";
        return $this->database->fetchRow($sql, [$userId]);
    }
    
    /**
     * Hash password
     */
    private function hashPassword($password)
    {
        return password_hash($password, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536,
            'time_cost' => 4,
            'threads' => 3
        ]);
    }
    
    /**
     * Verify password
     */
    private function verifyPassword($password, $hash)
    {
        return password_verify($password, $hash);
    }
    
    /**
     * Validate password strength
     */
    private function validatePassword($password)
    {
        // Minimum requirements: 8 characters, uppercase, lowercase, number, special char
        return strlen($password) >= 8 &&
               preg_match('/[A-Z]/', $password) &&
               preg_match('/[a-z]/', $password) &&
               preg_match('/\d/', $password) &&
               preg_match('/[^A-Za-z\d]/', $password);
    }
    
    /**
     * Check if account is locked
     */
    private function isAccountLocked($username)
    {
        $sql = "SELECT COUNT(*) as attempts FROM failed_login_attempts 
                WHERE username = ? AND attempt_time > DATE_SUB(NOW(), INTERVAL ? SECOND)";
        
        $result = $this->database->fetchRow($sql, [$username, $this->lockoutDuration]);
        
        return ($result['attempts'] ?? 0) >= $this->maxLoginAttempts;
    }
    
    /**
     * Record failed login attempt
     */
    private function recordFailedAttempt($username)
    {
        $sql = "INSERT INTO failed_login_attempts (username, ip_address, attempt_time)
                VALUES (?, ?, NOW())";
        
        $this->database->execute($sql, [$username, $this->getClientIP()]);
    }
    
    /**
     * Clear failed login attempts
     */
    private function clearFailedAttempts($username)
    {
        $sql = "DELETE FROM failed_login_attempts WHERE username = ?";
        $this->database->execute($sql, [$username]);
    }
    
    /**
     * Update last login time
     */
    private function updateLastLogin($userId)
    {
        $sql = "UPDATE users SET last_login = NOW() WHERE id = ?";
        $this->database->execute($sql, [$userId]);
    }
    
    /**
     * Log security event
     */
    private function logSecurityEvent($event, $userId, $details = [])
    {
        $sql = "INSERT INTO security_logs (user_id, event_type, ip_address, user_agent, details, created_at)
                VALUES (?, ?, ?, ?, ?, NOW())";
        
        $this->database->execute($sql, [
            $userId,
            $event,
            $this->getClientIP(),
            $_SERVER['HTTP_USER_AGENT'] ?? '',
            json_encode($details)
        ]);
    }
    
    /**
     * Get client IP address
     */
    private function getClientIP()
    {
        $headers = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_FORWARDED', 'REMOTE_ADDR'];
        
        foreach ($headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ip = $_SERVER[$header];
                if (strpos($ip, ',') !== false) {
                    $ip = explode(',', $ip)[0];
                }
                return trim($ip);
            }
        }
        
        return '0.0.0.0';
    }
    
    /**
     * Clean up expired sessions
     */
    public function cleanupExpiredSessions()
    {
        try {
            $sql = "DELETE FROM user_sessions WHERE expires_at < NOW()";
            $stmt = $this->database->execute($sql);
            
            return $stmt->rowCount();
            
        } catch (Exception $e) {
            error_log("Session cleanup error: " . $e->getMessage());
            return 0;
        }
    }
    
    /**
     * Get active sessions count
     */
    public function getActiveSessionsCount()
    {
        try {
            $sql = "SELECT COUNT(*) as count FROM user_sessions WHERE expires_at > NOW()";
            $result = $this->database->fetchRow($sql);
            
            return $result['count'] ?? 0;
            
        } catch (Exception $e) {
            error_log("Get active sessions error: " . $e->getMessage());
            return 0;
        }
    }
}

