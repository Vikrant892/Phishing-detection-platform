/**
 * Phishing Detection Platform - Main JavaScript Application
 * Core functionality and shared components
 */

// Global application object
const PhishingApp = {
    config: {
        apiBaseUrl: '/api.php',
        refreshInterval: 30000, // 30 seconds
        theme: localStorage.getItem('theme') || 'light',
        notifications: true,
        autoRefresh: true
    },
    
    // Initialize the application
    init() {
        this.setupEventListeners();
        this.initializeTheme();
        this.setupNotifications();
        this.startPeriodicUpdates();
        this.initializeTooltips();
        this.setupFormValidation();
        this.initializeCharts();
        
        console.log('Phishing Detection Platform initialized');
    },

    // Set up global event listeners
    setupEventListeners() {
        // Sidebar toggle
        document.addEventListener('click', (e) => {
            if (e.target.matches('.sidebar-toggle, .sidebar-toggle *')) {
                this.toggleSidebar();
            }
            
            // Mobile menu toggle
            if (e.target.matches('.mobile-menu-toggle, .mobile-menu-toggle *')) {
                this.toggleMobileMenu();
            }
            
            // Theme toggle
            if (e.target.matches('.theme-toggle input')) {
                this.toggleTheme();
            }
        });

        // Global keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            // Ctrl/Cmd + K for global search
            if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                e.preventDefault();
                this.openGlobalSearch();
            }
            
            // ESC to close modals
            if (e.key === 'Escape') {
                this.closeActiveModals();
            }
        });

        // Handle file drops on the entire page
        document.addEventListener('dragover', (e) => {
            e.preventDefault();
            e.dataTransfer.dropEffect = 'copy';
        });

        document.addEventListener('drop', (e) => {
            e.preventDefault();
            if (e.target.matches('.file-upload-area, .file-upload-area *')) {
                this.handleFileDrop(e);
            }
        });

        // Form submission handling
        document.addEventListener('submit', (e) => {
            if (e.target.matches('form[data-ajax="true"]')) {
                e.preventDefault();
                this.handleAjaxFormSubmission(e.target);
            }
        });
    },

    // Theme management
    initializeTheme() {
        document.documentElement.setAttribute('data-theme', this.config.theme);
        const themeToggle = document.querySelector('.theme-toggle input');
        if (themeToggle) {
            themeToggle.checked = this.config.theme === 'dark';
        }
    },

    toggleTheme() {
        this.config.theme = this.config.theme === 'light' ? 'dark' : 'light';
        document.documentElement.setAttribute('data-theme', this.config.theme);
        localStorage.setItem('theme', this.config.theme);
        
        this.showNotification(`Switched to ${this.config.theme} theme`, 'info');
    },

    // Sidebar functionality
    toggleSidebar() {
        const sidebar = document.querySelector('.sidebar');
        const contentWrapper = document.querySelector('.content-wrapper');
        
        if (sidebar) {
            sidebar.classList.toggle('toggled');
            localStorage.setItem('sidebar-toggled', sidebar.classList.contains('toggled'));
        }
    },

    toggleMobileMenu() {
        const sidebar = document.querySelector('.sidebar');
        if (sidebar) {
            sidebar.classList.toggle('show');
        }
    },

    // Notification system
    setupNotifications() {
        if ('Notification' in window && this.config.notifications) {
            if (Notification.permission === 'default') {
                Notification.requestPermission();
            }
        }
        
        // Create notification container if it doesn't exist
        if (!document.querySelector('.notification-container')) {
            const container = document.createElement('div');
            container.className = 'notification-container';
            container.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 9999;
                pointer-events: none;
            `;
            document.body.appendChild(container);
        }
    },

    showNotification(message, type = 'info', duration = 5000) {
        const container = document.querySelector('.notification-container');
        const notification = document.createElement('div');
        
        const typeClasses = {
            success: 'alert-success',
            danger: 'alert-danger',
            warning: 'alert-warning',
            info: 'alert-info'
        };
        
        notification.className = `alert ${typeClasses[type] || typeClasses.info} alert-dismissible fade show`;
        notification.style.cssText = `
            pointer-events: auto;
            margin-bottom: 10px;
            min-width: 300px;
        `;
        
        notification.innerHTML = `
            <div class="d-flex align-items-center">
                <i class="fas fa-${this.getNotificationIcon(type)} me-2"></i>
                <span>${this.escapeHtml(message)}</span>
                <button type="button" class="btn-close ms-auto" data-bs-dismiss="alert"></button>
            </div>
        `;
        
        container.appendChild(notification);
        
        // Auto dismiss
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, duration);
        
        // Browser notification for important messages
        if (type === 'danger' || type === 'warning') {
            this.showBrowserNotification(message, type);
        }
    },

    showBrowserNotification(message, type) {
        if ('Notification' in window && Notification.permission === 'granted') {
            const notification = new Notification('Phishing Detection Alert', {
                body: message,
                icon: '/static/images/logo.png',
                badge: '/static/images/badge.png'
            });
            
            setTimeout(() => notification.close(), 5000);
        }
    },

    getNotificationIcon(type) {
        const icons = {
            success: 'check-circle',
            danger: 'exclamation-triangle',
            warning: 'exclamation-circle',
            info: 'info-circle'
        };
        return icons[type] || icons.info;
    },

    // API Communication
    async makeApiRequest(endpoint, options = {}) {
        const defaultOptions = {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            credentials: 'same-origin'
        };
        
        const config = { ...defaultOptions, ...options };
        
        try {
            this.showLoadingIndicator(true);
            
            const response = await fetch(`${this.config.apiBaseUrl}?action=${endpoint}`, config);
            const data = await response.json();
            
            if (!data.success) {
                throw new Error(data.error || 'API request failed');
            }
            
            return data;
        } catch (error) {
            console.error('API Request Error:', error);
            this.showNotification(`Error: ${error.message}`, 'danger');
            throw error;
        } finally {
            this.showLoadingIndicator(false);
        }
    },

    // File handling
    handleFileDrop(event) {
        const files = Array.from(event.dataTransfer.files);
        const fileInput = event.target.closest('.file-upload-area').querySelector('input[type="file"]');
        
        if (fileInput) {
            // Update file input
            const dt = new DataTransfer();
            files.forEach(file => dt.items.add(file));
            fileInput.files = dt.files;
            
            // Show file names
            this.displaySelectedFiles(files, event.target.closest('.file-upload-area'));
        }
    },

    displaySelectedFiles(files, container) {
        const fileList = container.querySelector('.file-list') || this.createFileList(container);
        fileList.innerHTML = '';
        
        files.forEach((file, index) => {
            const fileItem = document.createElement('div');
            fileItem.className = 'file-item d-flex justify-content-between align-items-center p-2 border rounded mb-1';
            fileItem.innerHTML = `
                <div>
                    <i class="fas fa-file me-2"></i>
                    <span>${this.escapeHtml(file.name)}</span>
                    <small class="text-muted ms-2">(${this.formatFileSize(file.size)})</small>
                </div>
                <button type="button" class="btn btn-sm btn-outline-danger" onclick="PhishingApp.removeFile(${index})">
                    <i class="fas fa-times"></i>
                </button>
            `;
            fileList.appendChild(fileItem);
        });
    },

    createFileList(container) {
        const fileList = document.createElement('div');
        fileList.className = 'file-list mt-3';
        container.appendChild(fileList);
        return fileList;
    },

    // Form handling
    async handleAjaxFormSubmission(form) {
        const formData = new FormData(form);
        const submitButton = form.querySelector('button[type="submit"]');
        const originalText = submitButton.innerHTML;
        
        try {
            // Disable submit button and show loading
            submitButton.disabled = true;
            submitButton.innerHTML = '<i class="spinner-border spinner-border-sm me-2"></i>Processing...';
            
            const response = await fetch(form.action || this.config.apiBaseUrl, {
                method: 'POST',
                body: formData,
                credentials: 'same-origin'
            });
            
            const data = await response.json();
            
            if (data.success) {
                this.showNotification('Operation completed successfully', 'success');
                
                // Trigger custom success event
                form.dispatchEvent(new CustomEvent('ajaxSuccess', { detail: data }));
                
                // Reset form if specified
                if (form.dataset.resetOnSuccess === 'true') {
                    form.reset();
                }
            } else {
                throw new Error(data.error || 'Operation failed');
            }
        } catch (error) {
            this.showNotification(error.message, 'danger');
            form.dispatchEvent(new CustomEvent('ajaxError', { detail: error }));
        } finally {
            // Re-enable submit button
            submitButton.disabled = false;
            submitButton.innerHTML = originalText;
        }
    },

    // Form validation
    setupFormValidation() {
        document.querySelectorAll('form[data-validate="true"]').forEach(form => {
            form.addEventListener('submit', (e) => {
                if (!this.validateForm(form)) {
                    e.preventDefault();
                    e.stopPropagation();
                }
                form.classList.add('was-validated');
            });
        });
    },

    validateForm(form) {
        const inputs = form.querySelectorAll('input[required], textarea[required], select[required]');
        let isValid = true;
        
        inputs.forEach(input => {
            if (!input.checkValidity()) {
                isValid = false;
                this.showFieldError(input, input.validationMessage);
            } else {
                this.clearFieldError(input);
            }
        });
        
        return isValid;
    },

    showFieldError(field, message) {
        field.classList.add('is-invalid');
        
        let feedback = field.parentNode.querySelector('.invalid-feedback');
        if (!feedback) {
            feedback = document.createElement('div');
            feedback.className = 'invalid-feedback';
            field.parentNode.appendChild(feedback);
        }
        feedback.textContent = message;
    },

    clearFieldError(field) {
        field.classList.remove('is-invalid');
        const feedback = field.parentNode.querySelector('.invalid-feedback');
        if (feedback) {
            feedback.remove();
        }
    },

    // UI Components
    initializeTooltips() {
        // Initialize Bootstrap tooltips if available
        if (typeof bootstrap !== 'undefined' && bootstrap.Tooltip) {
            document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(element => {
                new bootstrap.Tooltip(element);
            });
        }
    },

    showLoadingIndicator(show = true) {
        let indicator = document.querySelector('.global-loading-indicator');
        
        if (!indicator) {
            indicator = document.createElement('div');
            indicator.className = 'global-loading-indicator';
            indicator.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 4px;
                background: linear-gradient(90deg, var(--primary-color) 0%, var(--primary-dark) 100%);
                z-index: 9999;
                opacity: 0;
                transition: opacity 0.3s ease;
            `;
            document.body.appendChild(indicator);
        }
        
        if (show) {
            indicator.style.opacity = '1';
            indicator.classList.add('pulse');
        } else {
            indicator.style.opacity = '0';
            indicator.classList.remove('pulse');
        }
    },

    // Search functionality
    openGlobalSearch() {
        let searchModal = document.querySelector('#globalSearchModal');
        
        if (!searchModal) {
            searchModal = this.createGlobalSearchModal();
        }
        
        const modal = new bootstrap.Modal(searchModal);
        modal.show();
        
        // Focus search input when modal is shown
        searchModal.addEventListener('shown.bs.modal', () => {
            searchModal.querySelector('input[type="search"]').focus();
        });
    },

    createGlobalSearchModal() {
        const modal = document.createElement('div');
        modal.className = 'modal fade';
        modal.id = 'globalSearchModal';
        modal.innerHTML = `
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Global Search</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <form onsubmit="PhishingApp.performGlobalSearch(event)">
                            <div class="mb-3">
                                <input type="search" class="form-control form-control-lg" 
                                       placeholder="Search emails, senders, or threats..." 
                                       name="search" required>
                            </div>
                            <div class="d-flex gap-2">
                                <select class="form-select" name="type">
                                    <option value="all">All Fields</option>
                                    <option value="subject">Subject</option>
                                    <option value="sender">Sender</option>
                                    <option value="content">Content</option>
                                </select>
                                <button type="submit" class="btn btn-primary">
                                    <i class="fas fa-search me-1"></i>Search
                                </button>
                            </div>
                        </form>
                        <div id="searchResults" class="mt-3"></div>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
        return modal;
    },

    async performGlobalSearch(event) {
        event.preventDefault();
        const form = event.target;
        const formData = new FormData(form);
        const searchTerm = formData.get('search');
        const searchType = formData.get('type');
        
        try {
            const response = await this.makeApiRequest('search', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            this.displaySearchResults(response.data.results);
        } catch (error) {
            document.getElementById('searchResults').innerHTML = 
                '<div class="alert alert-danger">Search failed. Please try again.</div>';
        }
    },

    displaySearchResults(results) {
        const container = document.getElementById('searchResults');
        
        if (results.length === 0) {
            container.innerHTML = '<div class="text-center text-muted">No results found</div>';
            return;
        }
        
        const resultsList = results.map(result => `
            <div class="search-result-item p-3 border rounded mb-2">
                <div class="d-flex justify-content-between align-items-start">
                    <div>
                        <h6 class="mb-1">${this.escapeHtml(result.email_subject)}</h6>
                        <p class="text-muted mb-1">From: ${this.escapeHtml(result.email_sender)}</p>
                        <small class="text-muted">${this.formatDateTime(result.created_at)}</small>
                    </div>
                    <div class="text-end">
                        <span class="badge bg-${this.getThreatBadgeClass(result.risk_level)}">${result.risk_level}</span>
                        <div class="mt-1">
                            <small class="text-muted">Score: ${result.threat_score}%</small>
                        </div>
                    </div>
                </div>
                <div class="mt-2">
                    <button class="btn btn-sm btn-primary" onclick="PhishingApp.viewAnalysis('${result.analysis_id}')">
                        View Details
                    </button>
                </div>
            </div>
        `).join('');
        
        container.innerHTML = resultsList;
    },

    // Charts initialization
    initializeCharts() {
        // This will be extended by dashboard.js for specific chart implementations
        this.chartColors = {
            primary: getComputedStyle(document.documentElement).getPropertyValue('--primary-color'),
            success: getComputedStyle(document.documentElement).getPropertyValue('--success-color'),
            warning: getComputedStyle(document.documentElement).getPropertyValue('--warning-color'),
            danger: getComputedStyle(document.documentElement).getPropertyValue('--danger-color'),
            info: getComputedStyle(document.documentElement).getPropertyValue('--info-color')
        };
    },

    // Periodic updates
    startPeriodicUpdates() {
        if (this.config.autoRefresh) {
            setInterval(() => {
                this.refreshDashboardData();
            }, this.config.refreshInterval);
        }
    },

    async refreshDashboardData() {
        if (document.querySelector('#dashboard-content')) {
            try {
                const response = await this.makeApiRequest('dashboard-stats');
                this.updateDashboardStats(response.data);
            } catch (error) {
                console.error('Dashboard refresh failed:', error);
            }
        }
    },

    updateDashboardStats(stats) {
        // Update statistics cards
        const statsElements = {
            'total-analyses': stats.total_analyses,
            'high-risk-count': stats.risk_distribution?.HIGH || 0,
            'avg-threat-score': (stats.avg_threat_score || 0).toFixed(1) + '%',
            'quarantined-count': stats.quarantined_count
        };
        
        Object.entries(statsElements).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) {
                this.animateNumberChange(element, value);
            }
        });
        
        // Update last update time
        const lastUpdate = document.getElementById('last-update');
        if (lastUpdate) {
            lastUpdate.textContent = new Date().toLocaleTimeString();
        }
    },

    animateNumberChange(element, newValue) {
        const currentValue = element.textContent.replace(/[^\d.-]/g, '');
        if (currentValue !== newValue.toString()) {
            element.style.transform = 'scale(1.1)';
            setTimeout(() => {
                element.textContent = newValue;
                element.style.transform = 'scale(1)';
            }, 150);
        }
    },

    // Utility functions
    escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, m => map[m]);
    },

    formatFileSize(bytes) {
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        if (bytes === 0) return '0 Bytes';
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
    },

    formatDateTime(dateString) {
        return new Date(dateString).toLocaleString();
    },

    getThreatBadgeClass(riskLevel) {
        const classes = {
            'LOW': 'success',
            'MEDIUM': 'warning',
            'HIGH': 'danger',
            'CRITICAL': 'dark'
        };
        return classes[riskLevel] || 'secondary';
    },

    closeActiveModals() {
        document.querySelectorAll('.modal.show').forEach(modal => {
            const bsModal = bootstrap.Modal.getInstance(modal);
            if (bsModal) {
                bsModal.hide();
            }
        });
    },

    // Analysis functions
    async viewAnalysis(analysisId) {
        try {
            const response = await this.makeApiRequest(`analysis-details&id=${analysisId}`);
            this.showAnalysisModal(response.data);
        } catch (error) {
            this.showNotification('Failed to load analysis details', 'danger');
        }
    },

    async quarantineEmail(analysisId) {
        if (!confirm('Are you sure you want to quarantine this email?')) {
            return;
        }
        
        try {
            await this.makeApiRequest('quarantine', {
                method: 'POST',
                body: JSON.stringify({
                    analysis_id: analysisId,
                    reason: 'Quarantined via web interface'
                })
            });
            
            this.showNotification('Email quarantined successfully', 'success');
            
            // Refresh current page data
            if (typeof refreshCurrentView === 'function') {
                refreshCurrentView();
            }
        } catch (error) {
            this.showNotification('Failed to quarantine email', 'danger');
        }
    }
};

// Utility functions available globally
window.formatThreatScore = function(score) {
    const level = score >= 70 ? 'HIGH' : score >= 40 ? 'MEDIUM' : 'LOW';
    const className = score >= 70 ? 'danger' : score >= 40 ? 'warning' : 'success';
    
    return {
        score: parseFloat(score),
        level: level,
        class: className,
        percentage: Math.min(score, 100)
    };
};

window.showAlert = function(type, message, duration = 5000) {
    PhishingApp.showNotification(message, type, duration);
};

window.escapeHtml = function(text) {
    return PhishingApp.escapeHtml(text);
};

window.formatDateTime = function(dateString) {
    return PhishingApp.formatDateTime(dateString);
};

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    PhishingApp.init();
});

// Make PhishingApp available globally
window.PhishingApp = PhishingApp;
