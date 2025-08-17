<?php
/**
 * Footer Template for Phishing Detection Platform
 * Contains closing HTML, JavaScript libraries, and initialization scripts
 */
?>
                </main>
                <!-- End of Page Content -->
                
            </div>
            <!-- End of Main Content -->
            
            <!-- Footer -->
            <footer class="sticky-footer bg-white">
                <div class="container my-auto">
                    <div class="copyright text-center my-auto">
                        <div class="row align-items-center">
                            <div class="col-md-6 text-md-start">
                                <span>&copy; <?php echo date('Y'); ?> <?php echo htmlspecialchars(APP_NAME); ?>. 
                                Advanced cybersecurity threat detection platform.</span>
                            </div>
                            <div class="col-md-6 text-md-end">
                                <small class="text-muted">
                                    Version <?php echo htmlspecialchars(APP_VERSION); ?> | 
                                    <a href="#" onclick="PhishingApp.showSystemInfo()" class="text-decoration-none">
                                        System Status
                                    </a> | 
                                    <a href="#" onclick="PhishingApp.showPrivacyPolicy()" class="text-decoration-none">
                                        Privacy Policy
                                    </a>
                                </small>
                            </div>
                        </div>
                    </div>
                </div>
            </footer>
            <!-- End of Footer -->
            
        </div>
        <!-- End of Content Wrapper -->
        
    </div>
    <!-- End of Page Wrapper -->
    
    <!-- Scroll to Top Button -->
    <a class="scroll-to-top rounded" href="#page-top" title="Scroll to Top" data-bs-toggle="tooltip">
        <i class="fas fa-angle-up"></i>
    </a>
    
    <!-- Floating Action Button for Quick Upload -->
    <button class="fab" onclick="document.getElementById('quick-upload-input').click()" 
            title="Quick Email Upload" data-bs-toggle="tooltip" data-bs-placement="left"
            aria-label="Quick Upload Email">
        <i class="fas fa-plus"></i>
    </button>
    
    <!-- Hidden Quick Upload Input -->
    <input type="file" id="quick-upload-input" accept=".eml,.msg,.txt" 
           style="display: none;" onchange="PhishingApp.handleQuickUpload(this.files[0])"
           aria-hidden="true">
    
    <!-- Global Modals -->
    
    <!-- Global Search Modal -->
    <div class="modal fade" id="globalSearchModal" tabindex="-1" aria-labelledby="globalSearchLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="globalSearchLabel">
                        <i class="fas fa-search me-2"></i>Global Search
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <form onsubmit="PhishingApp.performGlobalSearch(event)">
                        <div class="row g-3">
                            <div class="col-md-8">
                                <input type="search" class="form-control form-control-lg" 
                                       placeholder="Search emails, senders, or threats..." 
                                       name="search" required autocomplete="off">
                            </div>
                            <div class="col-md-4">
                                <select class="form-select form-select-lg" name="type">
                                    <option value="all">All Fields</option>
                                    <option value="subject">Subject Only</option>
                                    <option value="sender">Sender Only</option>
                                    <option value="content">Content Only</option>
                                </select>
                            </div>
                            <div class="col-12">
                                <button type="submit" class="btn btn-primary btn-lg w-100">
                                    <i class="fas fa-search me-2"></i>Search
                                </button>
                            </div>
                        </div>
                    </form>
                    <div id="searchResults" class="mt-4"></div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- System Information Modal -->
    <div class="modal fade" id="systemInfoModal" tabindex="-1" aria-labelledby="systemInfoLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="systemInfoLabel">
                        <i class="fas fa-info-circle me-2"></i>System Information
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <div class="row">
                        <div class="col-md-6">
                            <h6 class="text-primary">Application</h6>
                            <table class="table table-sm table-borderless">
                                <tr><td class="fw-bold">Version:</td><td><?php echo htmlspecialchars(APP_VERSION); ?></td></tr>
                                <tr><td class="fw-bold">PHP Version:</td><td><?php echo PHP_VERSION; ?></td></tr>
                                <tr><td class="fw-bold">Server:</td><td><?php echo htmlspecialchars($_SERVER['SERVER_SOFTWARE'] ?? 'Unknown'); ?></td></tr>
                                <tr><td class="fw-bold">OS:</td><td><?php echo PHP_OS; ?></td></tr>
                            </table>
                        </div>
                        <div class="col-md-6">
                            <h6 class="text-primary">Configuration</h6>
                            <table class="table table-sm table-borderless">
                                <tr><td class="fw-bold">Max File Size:</td><td><?php echo formatFileSize(MAX_FILE_SIZE); ?></td></tr>
                                <tr><td class="fw-bold">Upload Directory:</td><td><?php echo htmlspecialchars(UPLOAD_DIR); ?></td></tr>
                                <tr><td class="fw-bold">Items Per Page:</td><td><?php echo ITEMS_PER_PAGE; ?></td></tr>
                                <tr><td class="fw-bold">Session Timeout:</td><td><?php echo SESSION_TIMEOUT; ?>s</td></tr>
                            </table>
                        </div>
                    </div>
                    <div class="row mt-3">
                        <div class="col-12">
                            <h6 class="text-primary">Service Status</h6>
                            <div id="system-health-status" class="d-flex justify-content-around text-center">
                                <div class="service-status">
                                    <div class="status-indicator bg-success rounded-circle mx-auto mb-2" style="width: 20px; height: 20px;"></div>
                                    <small>API Service</small>
                                </div>
                                <div class="service-status">
                                    <div class="status-indicator bg-success rounded-circle mx-auto mb-2" style="width: 20px; height: 20px;"></div>
                                    <small>Database</small>
                                </div>
                                <div class="service-status">
                                    <div class="status-indicator bg-success rounded-circle mx-auto mb-2" style="width: 20px; height: 20px;"></div>
                                    <small>ML Engine</small>
                                </div>
                                <div class="service-status">
                                    <div class="status-indicator bg-warning rounded-circle mx-auto mb-2" style="width: 20px; height: 20px;"></div>
                                    <small>Cache System</small>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-outline-primary" onclick="PhishingApp.checkSystemHealth()">
                        <i class="fas fa-sync-alt me-1"></i>Refresh Status
                    </button>
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Loading Overlay -->
    <div id="loading-overlay" class="loading-overlay d-none">
        <div class="loading-content">
            <div class="spinner-border text-primary mb-3" role="status">
                <span class="visually-hidden">Processing...</span>
            </div>
            <p class="text-muted">Processing your request...</p>
        </div>
    </div>
    
    <!-- Notification Container -->
    <div class="notification-container" aria-live="polite" aria-atomic="true"></div>
    
    <!-- Service Worker Registration -->
    <script>
        if ('serviceWorker' in navigator) {
            window.addEventListener('load', function() {
                navigator.serviceWorker.register('/static/js/sw.js')
                    .then(function(registration) {
                        console.log('ServiceWorker registration successful');
                    })
                    .catch(function(err) {
                        console.log('ServiceWorker registration failed: ', err);
                    });
            });
        }
    </script>
    
    <!-- Core JavaScript Libraries -->
    <script src="https://code.jquery.com/jquery-3.7.1.min.js" 
            integrity="sha256-/JqT3SQfawRcv/BIHPThkBvs0OEvtFFmqPF/lYI/Cxo=" 
            crossorigin="anonymous"></script>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js" 
            integrity="sha384-C6RzsynM9kWDrMNeT87bh95OGNyZPhcTNXj1NW7RuBCsyN/o0jlpcV8Qyq46cDfL" 
            crossorigin="anonymous"></script>
    
    <!-- Chart.js for Data Visualization -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.min.js" 
            integrity="sha256-qElp0K9E3r98BaW9s4+hNNi7c31jkVOqUx5oQFp/kD8=" 
            crossorigin="anonymous"></script>
    
    <!-- AOS (Animate On Scroll) Library -->
    <script src="https://unpkg.com/aos@2.3.1/dist/aos.js"></script>
    
    <!-- Custom Application JavaScript -->
    <script src="/static/js/app.js?v=<?php echo filemtime(__DIR__ . '/../static/js/app.js'); ?>"></script>
    
    <?php if (file_exists(__DIR__ . '/../static/js/dashboard.js')): ?>
    <script src="/static/js/dashboard.js?v=<?php echo filemtime(__DIR__ . '/../static/js/dashboard.js'); ?>"></script>
    <?php endif; ?>
    
    <!-- Page-specific JavaScript Files -->
    <?php if (isset($additionalJS) && is_array($additionalJS)): ?>
    <?php foreach ($additionalJS as $jsFile): ?>
    <script src="<?php echo htmlspecialchars($jsFile); ?>"></script>
    <?php endforeach; ?>
    <?php endif; ?>
    
    <!-- Initialize Libraries -->
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Hide initial loading screen
            const initialLoading = document.getElementById('initial-loading');
            if (initialLoading) {
                setTimeout(() => {
                    initialLoading.style.opacity = '0';
                    setTimeout(() => {
                        initialLoading.style.display = 'none';
                    }, 300);
                }, 500);
            }
            
            // Initialize AOS animations
            AOS.init({
                duration: 800,
                easing: 'ease-in-out',
                once: true,
                mirror: false,
                offset: 50
            });
            
            // Initialize Bootstrap tooltips
            const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
            const tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
                return new bootstrap.Tooltip(tooltipTriggerEl);
            });
            
            // Initialize Bootstrap popovers
            const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
            const popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
                return new bootstrap.Popover(popoverTriggerEl);
            });
            
            // Set up keyboard shortcuts
            document.addEventListener('keydown', function(e) {
                // Ctrl/Cmd + K for global search
                if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                    e.preventDefault();
                    PhishingApp.openGlobalSearch();
                }
                
                // ESC to close modals
                if (e.key === 'Escape') {
                    const openModals = document.querySelectorAll('.modal.show');
                    openModals.forEach(modal => {
                        const bsModal = bootstrap.Modal.getInstance(modal);
                        if (bsModal) {
                            bsModal.hide();
                        }
                    });
                }
            });
            
            // Update last activity time
            setInterval(function() {
                const lastUpdateElements = document.querySelectorAll('#sidebar-last-update');
                const currentTime = new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit', second:'2-digit'});
                lastUpdateElements.forEach(element => {
                    element.textContent = currentTime;
                });
            }, 1000);
            
            // Auto-save user preferences
            const themeToggle = document.querySelector('.theme-toggle input');
            if (themeToggle) {
                themeToggle.addEventListener('change', function() {
                    const theme = this.checked ? 'dark' : 'light';
                    localStorage.setItem('theme', theme);
                    localStorage.setItem('theme_updated', Date.now());
                });
            }
            
            // Check for updates to threat patterns
            if (typeof PhishingApp !== 'undefined') {
                PhishingApp.checkForUpdates();
            }
        });
        
        // Global error handler
        window.addEventListener('error', function(e) {
            console.error('Global error:', e.error);
            if (typeof PhishingApp !== 'undefined') {
                PhishingApp.showNotification('An unexpected error occurred. Please refresh the page.', 'danger');
            }
        });
        
        // Handle unhandled promise rejections
        window.addEventListener('unhandledrejection', function(e) {
            console.error('Unhandled promise rejection:', e.reason);
            if (typeof PhishingApp !== 'undefined') {
                PhishingApp.showNotification('A network error occurred. Please check your connection.', 'warning');
            }
        });
        
        // Page visibility change handler
        document.addEventListener('visibilitychange', function() {
            if (document.hidden) {
                // Page is hidden - pause real-time updates
                if (typeof Dashboard !== 'undefined' && Dashboard.pauseUpdates) {
                    Dashboard.pauseUpdates();
                }
            } else {
                // Page is visible - resume updates
                if (typeof Dashboard !== 'undefined' && Dashboard.resumeUpdates) {
                    Dashboard.resumeUpdates();
                }
            }
        });
    </script>
    
    <!-- Page-specific Inline JavaScript -->
    <?php if (isset($inlineJS)): ?>
    <script>
        <?php echo $inlineJS; ?>
    </script>
    <?php endif; ?>
    
    <!-- Analytics and Monitoring -->
    <script>
        // Performance monitoring
        window.addEventListener('load', function() {
            if ('performance' in window) {
                const loadTime = performance.timing.loadEventEnd - performance.timing.navigationStart;
                console.log('Page load time:', loadTime + 'ms');
                
                // Report performance metrics if needed
                if (loadTime > 5000) {
                    console.warn('Slow page load detected:', loadTime + 'ms');
                }
            }
        });
        
        // Memory usage monitoring (if available)
        if ('memory' in performance) {
            setInterval(function() {
                const memInfo = performance.memory;
                if (memInfo.usedJSHeapSize / memInfo.jsHeapSizeLimit > 0.9) {
                    console.warn('High memory usage detected');
                }
            }, 30000); // Check every 30 seconds
        }
    </script>
    
    <!-- Accessibility Enhancements -->
    <script>
        // Skip link functionality
        document.querySelector('.skip-link')?.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector('#main-content');
            if (target) {
                target.focus();
                target.scrollIntoView();
            }
        });
        
        // Enhanced keyboard navigation
        document.addEventListener('keydown', function(e) {
            // Tab navigation enhancement
            if (e.key === 'Tab') {
                document.body.classList.add('keyboard-navigation');
            }
        });
        
        document.addEventListener('mousedown', function() {
            document.body.classList.remove('keyboard-navigation');
        });
        
        // Announce dynamic content changes to screen readers
        function announceToScreenReader(message) {
            const announcement = document.createElement('div');
            announcement.setAttribute('aria-live', 'polite');
            announcement.setAttribute('aria-atomic', 'true');
            announcement.className = 'sr-only';
            announcement.textContent = message;
            document.body.appendChild(announcement);
            
            setTimeout(() => {
                document.body.removeChild(announcement);
            }, 1000);
        }
        
        // Make announcement function globally available
        window.announceToScreenReader = announceToScreenReader;
    </script>
    
</body>
</html>
