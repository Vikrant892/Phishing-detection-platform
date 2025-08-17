        </div>
    </main>
    
    <!-- Footer -->
    <footer class="footer mt-auto py-3 bg-light border-top">
        <div class="container-fluid">
            <div class="row align-items-center">
                <div class="col-md-6">
                    <span class="text-muted">
                        &copy; <?php echo date('Y'); ?> <?php echo APP_NAME; ?> v<?php echo APP_VERSION; ?>
                    </span>
                </div>
                <div class="col-md-6 text-md-end">
                    <span class="text-muted">
                        <i class="fas fa-server me-1"></i>
                        <span id="systemStatus">System Healthy</span>
                        <span class="mx-2">|</span>
                        <i class="fas fa-clock me-1"></i>
                        Last Updated: <span id="lastUpdate"><?php echo date('H:i:s'); ?></span>
                    </span>
                </div>
            </div>
        </div>
    </footer>
    
    <!-- Loading overlay -->
    <div class="loading-overlay d-none" id="loadingOverlay">
        <div class="loading-spinner">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
            <div class="mt-3">
                <span id="loadingText">Processing...</span>
            </div>
        </div>
    </div>
    
    <!-- Toast container -->
    <div class="toast-container position-fixed bottom-0 end-0 p-3">
        <div id="liveToast" class="toast" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="toast-header">
                <i class="fas fa-info-circle text-primary me-2"></i>
                <strong class="me-auto" id="toastTitle">Notification</strong>
                <small id="toastTime">now</small>
                <button type="button" class="btn-close" data-bs-dismiss="toast"></button>
            </div>
            <div class="toast-body" id="toastBody">
                Message content
            </div>
        </div>
    </div>
    
    <!-- Modals -->
    
    <!-- Confirmation Modal -->
    <div class="modal fade" id="confirmModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="confirmModalTitle">Confirm Action</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body" id="confirmModalBody">
                    Are you sure you want to perform this action?
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" id="confirmModalConfirm">Confirm</button>
                </div>
            </div>
        </div>
    </div>
    
    <!-- File Upload Progress Modal -->
    <div class="modal fade" id="uploadProgressModal" tabindex="-1" data-bs-backdrop="static">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="fas fa-upload me-2"></i>Uploading Files
                    </h5>
                </div>
                <div class="modal-body">
                    <div class="mb-3">
                        <div class="progress">
                            <div class="progress-bar" role="progressbar" style="width: 0%" id="uploadProgress">0%</div>
                        </div>
                    </div>
                    <div id="uploadStatus">Preparing upload...</div>
                    <div id="uploadDetails" class="small text-muted mt-2"></div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" id="cancelUpload">Cancel</button>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Analysis Results Modal -->
    <div class="modal fade" id="analysisModal" tabindex="-1">
        <div class="modal-dialog modal-xl">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="fas fa-search me-2"></i>Analysis Results
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body" id="analysisModalBody">
                    <!-- Analysis content will be loaded here -->
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    <button type="button" class="btn btn-warning" id="quarantineBtn">
                        <i class="fas fa-ban me-1"></i>Quarantine
                    </button>
                    <button type="button" class="btn btn-primary" id="exportAnalysisBtn">
                        <i class="fas fa-download me-1"></i>Export
                    </button>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Scripts -->
    
    <!-- Bootstrap 5 JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    
    <!-- jQuery -->
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    
    <!-- Custom JavaScript -->
    <script src="assets/js/app.js"></script>
    
    <!-- Page-specific JavaScript -->
    <?php if ($current_page === 'dashboard'): ?>
    <script src="assets/js/dashboard.js"></script>
    <?php elseif ($current_page === 'analysis'): ?>
    <script src="assets/js/analysis.js"></script>
    <?php elseif ($current_page === 'reports'): ?>
    <script src="assets/js/reports.js"></script>
    <?php elseif ($current_page === 'settings'): ?>
    <script src="assets/js/settings.js"></script>
    <?php endif; ?>
    
    <!-- Progressive Web App Service Worker -->
    <script>
        if ('serviceWorker' in navigator) {
            window.addEventListener('load', function() {
                navigator.serviceWorker.register('/php/sw.js')
                    .then(function(registration) {
                        console.log('SW registered: ', registration);
                    }).catch(function(registrationError) {
                        console.log('SW registration failed: ', registrationError);
                    });
            });
        }
    </script>
    
    <!-- Initialize app -->
    <script>
        $(document).ready(function() {
            // Initialize the application
            App.init();
            
            // Check backend status
            App.checkBackendStatus();
            
            // Setup real-time updates
            App.startRealTimeUpdates();
            
            // Load notifications
            App.loadNotifications();
        });
    </script>
    
    <!-- Analytics (if needed) -->
    <?php if (!APP_DEBUG): ?>
    <script>
        // Add analytics code here for production
    </script>
    <?php endif; ?>
    
</body>
</html>
