<?php

/**
 * Database Connection and Management Class
 * Handles all database operations with security best practices
 */
class Database
{
    private $connection;
    private $host;
    private $username;
    private $password;
    private $database;
    private $charset;
    
    public function __construct()
    {
        $this->host = $_ENV['PGHOST'] ?? 'localhost';
        $this->username = $_ENV['PGUSER'] ?? 'root';
        $this->password = $_ENV['PGPASSWORD'] ?? '';
        $this->database = $_ENV['PGDATABASE'] ?? 'phishing_detector';
        $this->charset = 'utf8mb4';
        
        $this->connect();
    }
    
    /**
     * Establish database connection
     */
    private function connect()
    {
        try {
            $dsn = "mysql:host={$this->host};dbname={$this->database};charset={$this->charset}";
            
            $options = [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::ATTR_PERSISTENT => false,
                PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES {$this->charset} COLLATE utf8mb4_unicode_ci"
            ];
            
            $this->connection = new PDO($dsn, $this->username, $this->password, $options);
            
        } catch (PDOException $e) {
            error_log("Database connection failed: " . $e->getMessage());
            throw new Exception("Database connection failed");
        }
    }
    
    /**
     * Get database connection
     */
    public function getConnection()
    {
        // Check if connection is still alive
        try {
            $this->connection->query('SELECT 1');
        } catch (PDOException $e) {
            $this->connect();
        }
        
        return $this->connection;
    }
    
    /**
     * Execute prepared statement with parameters
     */
    public function execute($sql, $params = [])
    {
        try {
            $stmt = $this->connection->prepare($sql);
            $stmt->execute($params);
            return $stmt;
        } catch (PDOException $e) {
            error_log("Database execute error: " . $e->getMessage());
            throw new Exception("Database operation failed: " . $e->getMessage());
        }
    }
    
    /**
     * Fetch single row
     */
    public function fetchRow($sql, $params = [])
    {
        $stmt = $this->execute($sql, $params);
        return $stmt->fetch();
    }
    
    /**
     * Fetch all rows
     */
    public function fetchAll($sql, $params = [])
    {
        $stmt = $this->execute($sql, $params);
        return $stmt->fetchAll();
    }
    
    /**
     * Get last insert ID
     */
    public function lastInsertId()
    {
        return $this->connection->lastInsertId();
    }
    
    /**
     * Begin transaction
     */
    public function beginTransaction()
    {
        return $this->connection->beginTransaction();
    }
    
    /**
     * Commit transaction
     */
    public function commit()
    {
        return $this->connection->commit();
    }
    
    /**
     * Rollback transaction
     */
    public function rollback()
    {
        return $this->connection->rollback();
    }
    
    /**
     * Get row count for last statement
     */
    public function rowCount()
    {
        return $this->connection->query("SELECT FOUND_ROWS()")->fetchColumn();
    }
    
    /**
     * Escape string for LIKE queries
     */
    public function escapeLike($string)
    {
        return str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $string);
    }
    
    /**
     * Build WHERE clause from array of conditions
     */
    public function buildWhereClause($conditions, &$params = [])
    {
        if (empty($conditions)) {
            return '';
        }
        
        $clauses = [];
        foreach ($conditions as $field => $value) {
            if ($value === null) {
                $clauses[] = "$field IS NULL";
            } elseif (is_array($value)) {
                $placeholders = str_repeat('?,', count($value) - 1) . '?';
                $clauses[] = "$field IN ($placeholders)";
                $params = array_merge($params, $value);
            } else {
                $clauses[] = "$field = ?";
                $params[] = $value;
            }
        }
        
        return 'WHERE ' . implode(' AND ', $clauses);
    }
    
    /**
     * Build ORDER BY clause
     */
    public function buildOrderClause($orderBy, $orderDir = 'ASC')
    {
        if (empty($orderBy)) {
            return '';
        }
        
        $allowedColumns = [
            'id', 'created_at', 'updated_at', 'analysis_date', 'threat_score', 
            'risk_level', 'filename', 'sender_address', 'subject'
        ];
        
        if (!in_array($orderBy, $allowedColumns)) {
            $orderBy = 'created_at';
        }
        
        $orderDir = strtoupper($orderDir) === 'DESC' ? 'DESC' : 'ASC';
        
        return "ORDER BY $orderBy $orderDir";
    }
    
    /**
     * Build LIMIT clause
     */
    public function buildLimitClause($limit, $offset = 0)
    {
        $limit = max(1, min(1000, (int)$limit)); // Between 1 and 1000
        $offset = max(0, (int)$offset);
        
        return "LIMIT $limit OFFSET $offset";
    }
    
    /**
     * Get table schema information
     */
    public function getTableSchema($tableName)
    {
        $sql = "DESCRIBE " . $this->escapeIdentifier($tableName);
        return $this->fetchAll($sql);
    }
    
    /**
     * Escape identifier (table/column names)
     */
    public function escapeIdentifier($identifier)
    {
        return '`' . str_replace('`', '``', $identifier) . '`';
    }
    
    /**
     * Check if table exists
     */
    public function tableExists($tableName)
    {
        $sql = "SHOW TABLES LIKE ?";
        $result = $this->fetchRow($sql, [$tableName]);
        return !empty($result);
    }
    
    /**
     * Get database statistics
     */
    public function getDatabaseStats()
    {
        $stats = [];
        
        try {
            // Get table sizes
            $sql = "SELECT 
                        table_name,
                        table_rows,
                        ROUND(((data_length + index_length) / 1024 / 1024), 2) AS size_mb
                    FROM information_schema.tables 
                    WHERE table_schema = ? 
                    ORDER BY (data_length + index_length) DESC";
            
            $stats['tables'] = $this->fetchAll($sql, [$this->database]);
            
            // Get total database size
            $sql = "SELECT 
                        ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS total_size_mb
                    FROM information_schema.tables 
                    WHERE table_schema = ?";
            
            $result = $this->fetchRow($sql, [$this->database]);
            $stats['total_size_mb'] = $result['total_size_mb'] ?? 0;
            
        } catch (Exception $e) {
            error_log("Database stats error: " . $e->getMessage());
            $stats = ['error' => 'Unable to fetch database statistics'];
        }
        
        return $stats;
    }
    
    /**
     * Optimize database tables
     */
    public function optimizeTables()
    {
        try {
            $tables = ['email_analysis', 'detected_threats', 'setup_rules', 'threat_statistics', 'quarantine'];
            
            foreach ($tables as $table) {
                if ($this->tableExists($table)) {
                    $this->execute("OPTIMIZE TABLE " . $this->escapeIdentifier($table));
                }
            }
            
            return true;
        } catch (Exception $e) {
            error_log("Table optimization error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Backup database structure
     */
    public function backupSchema()
    {
        try {
            $sql = "SHOW CREATE DATABASE " . $this->escapeIdentifier($this->database);
            $dbCreate = $this->fetchRow($sql);
            
            $backup = "-- Database Schema Backup\n";
            $backup .= "-- Generated: " . date('Y-m-d H:i:s') . "\n\n";
            $backup .= $dbCreate['Create Database'] . ";\n\n";
            
            // Get all tables
            $tables = $this->fetchAll("SHOW TABLES");
            
            foreach ($tables as $table) {
                $tableName = array_values($table)[0];
                $createTable = $this->fetchRow("SHOW CREATE TABLE " . $this->escapeIdentifier($tableName));
                $backup .= $createTable['Create Table'] . ";\n\n";
            }
            
            return $backup;
        } catch (Exception $e) {
            error_log("Schema backup error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Clean up old records based on retention policy
     */
    public function cleanup($retentionDays = 90)
    {
        try {
            $cutoffDate = date('Y-m-d', strtotime("-$retentionDays days"));
            
            $this->beginTransaction();
            
            // Clean old email analysis records
            $sql = "DELETE FROM email_analysis WHERE analysis_date < ?";
            $this->execute($sql, [$cutoffDate]);
            
            // Clean old threat statistics
            $sql = "DELETE FROM threat_statistics WHERE stat_date < ?";
            $this->execute($sql, [$cutoffDate]);
            
            // Clean expired sessions
            $sql = "DELETE FROM user_sessions WHERE expires_at < NOW()";
            $this->execute($sql);
            
            $this->commit();
            
            return true;
        } catch (Exception $e) {
            $this->rollback();
            error_log("Database cleanup error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Health check
     */
    public function healthCheck()
    {
        try {
            $this->execute("SELECT 1");
            return [
                'status' => 'healthy',
                'timestamp' => date('Y-m-d H:i:s'),
                'connection' => 'active'
            ];
        } catch (Exception $e) {
            return [
                'status' => 'unhealthy',
                'timestamp' => date('Y-m-d H:i:s'),
                'error' => $e->getMessage()
            ];
        }
    }
    
    /**
     * Close connection
     */
    public function close()
    {
        $this->connection = null;
    }
    
    /**
     * Destructor
     */
    public function __destruct()
    {
        $this->close();
    }
}

