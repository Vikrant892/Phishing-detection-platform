/**
 * Phishing Detection Platform - Dashboard Specific JavaScript
 * Charts, real-time updates, and dashboard interactions
 */

const Dashboard = {
    charts: {},
    refreshInterval: 30000,
    activityFeedPaused: false,
    
    init() {
        this.initializeCharts();
        this.setupRealTimeUpdates();
        this.initializeActivityFeed();
        this.setupDashboardInteractions();
        console.log('Dashboard initialized');
    },

    // Chart initialization and management
    initializeCharts() {
        this.initRiskDistributionChart();
        this.initThreatTrendsChart();
        this.initThreatScoreHistogram();
        this.setupChartResponsiveness();
    },

    initRiskDistributionChart() {
        const ctx = document.getElementById('riskDistributionChart');
        if (!ctx) return;

        const data = this.getRiskDistributionData();
        
        this.charts.riskDistribution = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['High Risk', 'Medium Risk', 'Low Risk'],
                datasets: [{
                    data: [
                        data.HIGH || 0,
                        data.MEDIUM || 0,
                        data.LOW || 0
                    ],
                    backgroundColor: [
                        '#e74a3b',  // High Risk - Red
                        '#f6c23e',  // Medium Risk - Yellow
                        '#1cc88a'   // Low Risk - Green
                    ],
                    borderWidth: 2,
                    borderColor: '#ffffff',
                    hoverBorderWidth: 4,
                    hoverOffset: 10
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 20,
                            usePointStyle: true,
                            font: {
                                size: 14,
                                family: 'Nunito'
                            }
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(0, 0, 0, 0.8)',
                        titleColor: 'white',
                        bodyColor: 'white',
                        cornerRadius: 8,
                        callbacks: {
                            label: function(context) {
                                const total = context.dataset.data.reduce((sum, value) => sum + value, 0);
                                const percentage = total > 0 ? ((context.parsed * 100) / total).toFixed(1) : 0;
                                return `${context.label}: ${context.parsed} (${percentage}%)`;
                            }
                        }
                    }
                },
                animation: {
                    animateScale: true,
                    animateRotate: true,
                    duration: 1000
                },
                cutout: '60%',
                elements: {
                    arc: {
                        borderRadius: 8
                    }
                }
            }
        });
    },

    initThreatTrendsChart() {
        const ctx = document.getElementById('threatTrendsChart');
        if (!ctx) return;

        const data = this.getThreatTrendsData();
        
        this.charts.threatTrends = new Chart(ctx, {
            type: 'line',
            data: {
                labels: data.labels,
                datasets: [{
                    label: 'High Risk Threats',
                    data: data.highRisk,
                    borderColor: '#e74a3b',
                    backgroundColor: 'rgba(231, 74, 59, 0.1)',
                    tension: 0.4,
                    fill: true,
                    pointBackgroundColor: '#e74a3b',
                    pointBorderColor: '#ffffff',
                    pointBorderWidth: 2,
                    pointRadius: 4,
                    pointHoverRadius: 6
                }, {
                    label: 'Medium Risk Threats',
                    data: data.mediumRisk,
                    borderColor: '#f6c23e',
                    backgroundColor: 'rgba(246, 194, 62, 0.1)',
                    tension: 0.4,
                    fill: true,
                    pointBackgroundColor: '#f6c23e',
                    pointBorderColor: '#ffffff',
                    pointBorderWidth: 2,
                    pointRadius: 4,
                    pointHoverRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: true,
                        position: 'top',
                        labels: {
                            usePointStyle: true,
                            padding: 20,
                            font: {
                                size: 12,
                                family: 'Nunito'
                            }
                        }
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false,
                        backgroundColor: 'rgba(0, 0, 0, 0.8)',
                        titleColor: 'white',
                        bodyColor: 'white',
                        cornerRadius: 8
                    }
                },
                scales: {
                    x: {
                        display: true,
                        grid: {
                            display: false
                        },
                        ticks: {
                            font: {
                                size: 11
                            },
                            color: '#858796'
                        }
                    },
                    y: {
                        display: true,
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(133, 135, 150, 0.1)'
                        },
                        ticks: {
                            font: {
                                size: 11
                            },
                            color: '#858796'
                        }
                    }
                },
                interaction: {
                    mode: 'nearest',
                    axis: 'x',
                    intersect: false
                },
                animation: {
                    duration: 1000,
                    easing: 'easeInOutQuart'
                }
            }
        });
    },

    initThreatScoreHistogram() {
        const ctx = document.getElementById('threatScoreHistogram');
        if (!ctx) return;

        const data = this.getThreatScoreHistogramData();
        
        this.charts.threatScoreHistogram = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['0-10', '11-20', '21-30', '31-40', '41-50', '51-60', '61-70', '71-80', '81-90', '91-100'],
                datasets: [{
                    label: 'Number of Emails',
                    data: data,
                    backgroundColor: [
                        '#1cc88a', '#1cc88a', '#1cc88a', '#1cc88a',  // Low (0-40)
                        '#f6c23e', '#f6c23e', '#f6c23e',             // Medium (41-70)
                        '#e74a3b', '#e74a3b', '#e74a3b'              // High (71-100)
                    ],
                    borderColor: 'rgba(255, 255, 255, 0.8)',
                    borderWidth: 1,
                    borderRadius: 4,
                    borderSkipped: false
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        backgroundColor: 'rgba(0, 0, 0, 0.8)',
                        titleColor: 'white',
                        bodyColor: 'white',
                        cornerRadius: 8,
                        callbacks: {
                            title: function(context) {
                                return `Threat Score Range: ${context[0].label}%`;
                            },
                            label: function(context) {
                                return `Emails: ${context.parsed.y}`;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        grid: {
                            display: false
                        },
                        ticks: {
                            font: {
                                size: 11
                            },
                            color: '#858796'
                        }
                    },
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(133, 135, 150, 0.1)'
                        },
                        ticks: {
                            stepSize: 1,
                            font: {
                                size: 11
                            },
                            color: '#858796'
                        }
                    }
                },
                animation: {
                    duration: 800,
                    easing: 'easeInOutQuart'
                }
            }
        });
    },

    setupChartResponsiveness() {
        // Handle window resize for charts
        window.addEventListener('resize', () => {
            Object.values(this.charts).forEach(chart => {
                chart.resize();
            });
        });
        
        // Theme change handler for charts
        document.addEventListener('themeChanged', () => {
            this.updateChartsForTheme();
        });
    },

    updateChartsForTheme() {
        const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
        const textColor = isDark ? '#ffffff' : '#858796';
        const gridColor = isDark ? 'rgba(255, 255, 255, 0.1)' : 'rgba(133, 135, 150, 0.1)';
        
        Object.values(this.charts).forEach(chart => {
            if (chart.options.scales) {
                if (chart.options.scales.x) {
                    chart.options.scales.x.ticks.color = textColor;
                    if (chart.options.scales.x.grid) {
                        chart.options.scales.x.grid.color = gridColor;
                    }
                }
                if (chart.options.scales.y) {
                    chart.options.scales.y.ticks.color = textColor;
                    if (chart.options.scales.y.grid) {
                        chart.options.scales.y.grid.color = gridColor;
                    }
                }
            }
            chart.update();
        });
    },

    // Real-time updates
    setupRealTimeUpdates() {
        this.updateDashboardData();
        
        setInterval(() => {
            this.updateDashboardData();
        }, this.refreshInterval);
        
        // Setup WebSocket connection if available
        this.initializeWebSocket();
    },

    async updateDashboardData() {
        try {
            const response = await PhishingApp.makeApiRequest('dashboard-stats');
            const data = response.data;
            
            // Update statistics cards
            this.updateStatisticsCards(data);
            
            // Update charts
            this.updateCharts(data);
            
            // Update recent analyses
            this.updateRecentAnalyses(data.recent_analyses || []);
            
        } catch (error) {
            console.error('Dashboard update failed:', error);
        }
    },

    updateStatisticsCards(data) {
        const updates = {
            'total-analyses': data.total_analyses || 0,
            'high-risk-count': data.risk_distribution?.HIGH || 0,
            'avg-threat-score': parseFloat(data.avg_threat_score || 0).toFixed(1),
            'quarantined-count': data.quarantined_count || 0
        };
        
        Object.entries(updates).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) {
                this.animateCounterUpdate(element, value);
            }
        });
    },

    animateCounterUpdate(element, newValue) {
        const currentValue = parseFloat(element.textContent.replace(/[^\d.-]/g, '')) || 0;
        const targetValue = parseFloat(String(newValue).replace(/[^\d.-]/g, '')) || 0;
        
        if (currentValue !== targetValue) {
            element.style.transform = 'scale(1.05)';
            element.style.color = 'var(--primary-color)';
            
            // Animate the number change
            const duration = 1000;
            const steps = 30;
            const stepValue = (targetValue - currentValue) / steps;
            let currentStep = 0;
            
            const interval = setInterval(() => {
                currentStep++;
                const newVal = currentValue + (stepValue * currentStep);
                
                if (element.id === 'avg-threat-score') {
                    element.textContent = newVal.toFixed(1);
                } else {
                    element.textContent = Math.round(newVal).toLocaleString();
                }
                
                if (currentStep >= steps) {
                    clearInterval(interval);
                    element.style.transform = 'scale(1)';
                    element.style.color = '';
                }
            }, duration / steps);
        }
    },

    updateCharts(data) {
        // Update risk distribution chart
        if (this.charts.riskDistribution && data.risk_distribution) {
            this.charts.riskDistribution.data.datasets[0].data = [
                data.risk_distribution.HIGH || 0,
                data.risk_distribution.MEDIUM || 0,
                data.risk_distribution.LOW || 0
            ];
            this.charts.riskDistribution.update('none');
        }
        
        // Update threat trends chart with new hourly data
        if (this.charts.threatTrends && data.hourly_threats) {
            const newData = this.processThreatTrendsData(data.hourly_threats);
            this.charts.threatTrends.data.labels = newData.labels;
            this.charts.threatTrends.data.datasets[0].data = newData.highRisk;
            this.charts.threatTrends.data.datasets[1].data = newData.mediumRisk;
            this.charts.threatTrends.update('none');
        }
    },

    updateRecentAnalyses(analyses) {
        const tableBody = document.querySelector('#recent-analyses-table');
        if (!tableBody) return;
        
        if (analyses.length === 0) {
            tableBody.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center text-muted py-4">
                        <i class="fas fa-inbox fa-2x mb-2 d-block"></i>
                        No recent analyses available
                    </td>
                </tr>
            `;
            return;
        }
        
        const rows = analyses.map(analysis => {
            const threatInfo = formatThreatScore(analysis.threat_score);
            return `
                <tr class="analysis-row" data-id="${analysis.analysis_id}">
                    <td><small>${formatDateTime(analysis.created_at)}</small></td>
                    <td>
                        <div class="text-truncate" style="max-width: 200px;" title="${escapeHtml(analysis.email_subject)}">
                            ${escapeHtml(analysis.email_subject)}
                        </div>
                    </td>
                    <td>${escapeHtml(analysis.email_sender)}</td>
                    <td>
                        <span class="badge bg-${threatInfo.class}">
                            ${threatInfo.level}
                        </span>
                    </td>
                    <td>
                        <div class="progress" style="height: 20px;">
                            <div class="progress-bar bg-${threatInfo.class}" 
                                 style="width: ${threatInfo.percentage}%"
                                 title="${threatInfo.score}%">
                                ${threatInfo.score}%
                            </div>
                        </div>
                    </td>
                    <td>
                        <div class="btn-group btn-group-sm">
                            <button class="btn btn-outline-primary btn-sm" 
                                    onclick="PhishingApp.viewAnalysis('${analysis.analysis_id}')" 
                                    title="View Details">
                                <i class="fas fa-eye"></i>
                            </button>
                            ${analysis.threat_score >= 40 ? `
                                <button class="btn btn-outline-warning btn-sm" 
                                        onclick="PhishingApp.quarantineEmail('${analysis.analysis_id}')" 
                                        title="Quarantine">
                                    <i class="fas fa-lock"></i>
                                </button>
                            ` : ''}
                        </div>
                    </td>
                </tr>
            `;
        }).join('');
        
        tableBody.innerHTML = rows;
    },

    // Activity Feed
    initializeActivityFeed() {
        this.setupActivityFeedWebSocket();
        this.loadInitialActivityFeed();
    },

    setupActivityFeedWebSocket() {
        // WebSocket setup for real-time activity feed
        // This would connect to a WebSocket server for real-time updates
        if ('WebSocket' in window) {
            try {
                const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
                const wsUrl = `${protocol}//${location.host}/ws/activity`;
                
                this.activityWebSocket = new WebSocket(wsUrl);
                
                this.activityWebSocket.onmessage = (event) => {
                    if (!this.activityFeedPaused) {
                        const activity = JSON.parse(event.data);
                        this.addActivityItem(activity);
                    }
                };
                
                this.activityWebSocket.onclose = () => {
                    console.log('Activity WebSocket disconnected');
                    // Attempt to reconnect after 5 seconds
                    setTimeout(() => this.setupActivityFeedWebSocket(), 5000);
                };
            } catch (error) {
                console.warn('WebSocket not available, falling back to polling');
                this.setupActivityFeedPolling();
            }
        } else {
            this.setupActivityFeedPolling();
        }
    },

    setupActivityFeedPolling() {
        setInterval(() => {
            if (!this.activityFeedPaused) {
                this.pollActivityFeed();
            }
        }, 5000); // Poll every 5 seconds
    },

    async pollActivityFeed() {
        try {
            const response = await PhishingApp.makeApiRequest('recent-activity');
            const activities = response.data.activities || [];
            
            activities.forEach(activity => {
                this.addActivityItem(activity, false);
            });
        } catch (error) {
            console.error('Activity feed polling failed:', error);
        }
    },

    loadInitialActivityFeed() {
        const feedContainer = document.getElementById('activity-feed');
        if (!feedContainer) return;
        
        // Add some initial activity items
        const initialActivities = [
            {
                type: 'threat_detected',
                message: 'High-risk email detected from suspicious domain',
                timestamp: new Date().toISOString(),
                severity: 'high'
            },
            {
                type: 'analysis_complete',
                message: 'Bulk analysis completed: 15 emails processed',
                timestamp: new Date(Date.now() - 300000).toISOString(),
                severity: 'info'
            },
            {
                type: 'quarantine',
                message: 'Email quarantined: Phishing attempt blocked',
                timestamp: new Date(Date.now() - 600000).toISOString(),
                severity: 'warning'
            }
        ];
        
        feedContainer.innerHTML = initialActivities.map(activity => 
            this.createActivityItemHTML(activity)
        ).join('');
    },

    addActivityItem(activity, animate = true) {
        const feedContainer = document.getElementById('activity-feed');
        if (!feedContainer) return;
        
        const activityHTML = this.createActivityItemHTML(activity);
        const tempDiv = document.createElement('div');
        tempDiv.innerHTML = activityHTML;
        const activityElement = tempDiv.firstElementChild;
        
        if (animate) {
            activityElement.style.opacity = '0';
            activityElement.style.transform = 'translateX(-20px)';
        }
        
        feedContainer.insertBefore(activityElement, feedContainer.firstChild);
        
        if (animate) {
            setTimeout(() => {
                activityElement.style.transition = 'all 0.3s ease';
                activityElement.style.opacity = '1';
                activityElement.style.transform = 'translateX(0)';
            }, 50);
        }
        
        // Keep only the latest 10 items
        while (feedContainer.children.length > 10) {
            feedContainer.removeChild(feedContainer.lastChild);
        }
    },

    createActivityItemHTML(activity) {
        const iconMap = {
            threat_detected: 'fas fa-shield-alt',
            analysis_complete: 'fas fa-check-circle',
            quarantine: 'fas fa-lock',
            upload: 'fas fa-upload',
            export: 'fas fa-download'
        };
        
        const colorMap = {
            high: 'bg-danger',
            warning: 'bg-warning',
            info: 'bg-info',
            success: 'bg-success'
        };
        
        const icon = iconMap[activity.type] || 'fas fa-info-circle';
        const color = colorMap[activity.severity] || 'bg-info';
        
        return `
            <div class="activity-item">
                <div class="activity-icon ${color}">
                    <i class="${icon}"></i>
                </div>
                <div class="activity-content">
                    <p class="mb-1">${escapeHtml(activity.message)}</p>
                    <small class="text-muted">${this.getRelativeTime(activity.timestamp)}</small>
                </div>
            </div>
        `;
    },

    getRelativeTime(timestamp) {
        const now = new Date();
        const time = new Date(timestamp);
        const diff = Math.floor((now - time) / 1000);
        
        if (diff < 60) return 'Just now';
        if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
        return `${Math.floor(diff / 86400)}d ago`;
    },

    // Dashboard interactions
    setupDashboardInteractions() {
        this.setupActivityFeedControls();
        this.setupStatCardAnimations();
        this.setupQuickActions();
    },

    setupActivityFeedControls() {
        const toggleButton = document.querySelector('[onclick="toggleActivityFeed()"]');
        if (toggleButton) {
            toggleButton.addEventListener('click', (e) => {
                e.preventDefault();
                this.toggleActivityFeed();
            });
        }
    },

    toggleActivityFeed() {
        this.activityFeedPaused = !this.activityFeedPaused;
        
        const toggleIcon = document.getElementById('activity-toggle-icon');
        const toggleText = document.getElementById('activity-toggle-text');
        
        if (this.activityFeedPaused) {
            toggleIcon.className = 'fas fa-play';
            toggleText.textContent = 'Resume';
            PhishingApp.showNotification('Activity feed paused', 'info');
        } else {
            toggleIcon.className = 'fas fa-pause';
            toggleText.textContent = 'Pause';
            PhishingApp.showNotification('Activity feed resumed', 'info');
        }
    },

    setupStatCardAnimations() {
        // Add hover effects to statistics cards
        document.querySelectorAll('.card.border-left-primary, .card.border-left-danger, .card.border-left-warning, .card.border-left-info').forEach(card => {
            card.addEventListener('mouseenter', function() {
                this.style.transform = 'translateY(-5px)';
                this.style.transition = 'transform 0.2s ease';
            });
            
            card.addEventListener('mouseleave', function() {
                this.style.transform = 'translateY(0)';
            });
        });
    },

    setupQuickActions() {
        // Setup bulk upload modal functionality
        const showBulkUpload = window.showBulkUpload || function() {
            const modal = new bootstrap.Modal(document.getElementById('bulkUploadModal'));
            modal.show();
        };
        
        window.showBulkUpload = showBulkUpload;
        
        // Setup bulk upload processing
        window.processBulkUpload = () => {
            const form = document.getElementById('bulk-upload-form');
            const files = form.querySelector('#bulk-files').files;
            
            if (files.length === 0) {
                PhishingApp.showNotification('Please select files to upload', 'warning');
                return;
            }
            
            this.processBulkUpload(files);
        };
    },

    async processBulkUpload(files) {
        const progressBar = document.getElementById('bulk-upload-progress');
        const progressBarInner = progressBar.querySelector('.progress-bar');
        
        progressBar.classList.remove('d-none');
        
        const formData = new FormData();
        Array.from(files).forEach((file, index) => {
            formData.append('files[]', file);
        });
        
        try {
            // Simulate progress for user feedback
            let progress = 0;
            const progressInterval = setInterval(() => {
                progress += Math.random() * 15;
                if (progress > 90) progress = 90;
                progressBarInner.style.width = progress + '%';
            }, 500);
            
            const response = await fetch('api.php?action=bulk-analyze', {
                method: 'POST',
                body: formData
            });
            
            clearInterval(progressInterval);
            progressBarInner.style.width = '100%';
            
            const data = await response.json();
            
            if (data.success) {
                PhishingApp.showNotification(
                    `Bulk analysis completed: ${data.data.processed} files processed, ${data.data.failed} failed`, 
                    'success'
                );
                
                // Close modal and refresh dashboard
                bootstrap.Modal.getInstance(document.getElementById('bulkUploadModal')).hide();
                this.updateDashboardData();
            } else {
                throw new Error(data.error || 'Bulk upload failed');
            }
        } catch (error) {
            PhishingApp.showNotification('Bulk upload failed: ' + error.message, 'danger');
        } finally {
            progressBar.classList.add('d-none');
            progressBarInner.style.width = '0%';
        }
    },

    // Data processing methods
    getRiskDistributionData() {
        if (window.dashboardData && window.dashboardData.risk_distribution) {
            return window.dashboardData.risk_distribution;
        }
        
        // Fallback to DOM data
        const highRisk = parseInt(document.getElementById('high-risk-count')?.textContent?.replace(/,/g, '') || '0');
        const mediumRisk = parseInt(document.getElementById('medium-risk-count')?.textContent?.replace(/,/g, '') || '0');
        const lowRisk = parseInt(document.getElementById('low-risk-count')?.textContent?.replace(/,/g, '') || '0');
        
        return { HIGH: highRisk, MEDIUM: mediumRisk, LOW: lowRisk };
    },

    getThreatTrendsData() {
        if (window.dashboardData && window.dashboardData.hourly_threats) {
            return this.processThreatTrendsData(window.dashboardData.hourly_threats);
        }
        
        // Generate sample data for the last 24 hours
        const now = new Date();
        const labels = [];
        const highRisk = [];
        const mediumRisk = [];
        
        for (let i = 23; i >= 0; i--) {
            const hour = new Date(now.getTime() - (i * 60 * 60 * 1000));
            labels.push(hour.getHours() + ':00');
            highRisk.push(Math.floor(Math.random() * 10));
            mediumRisk.push(Math.floor(Math.random() * 20));
        }
        
        return { labels, highRisk, mediumRisk };
    },

    processThreatTrendsData(hourlyData) {
        const labels = [];
        const highRisk = [];
        const mediumRisk = [];
        
        // Process the hourly data from the API
        hourlyData.forEach(item => {
            const hour = item.hour < 10 ? `0${item.hour}:00` : `${item.hour}:00`;
            labels.push(hour);
            
            // This would need to be adjusted based on actual API data structure
            highRisk.push(item.high_risk_count || 0);
            mediumRisk.push(item.medium_risk_count || 0);
        });
        
        return { labels, highRisk, mediumRisk };
    },

    getThreatScoreHistogramData() {
        // This would typically come from the API
        // For now, return sample data
        return [45, 35, 25, 15, 20, 18, 12, 8, 5, 2];
    },

    // WebSocket connection for real-time updates
    initializeWebSocket() {
        if ('WebSocket' in window) {
            try {
                const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
                const wsUrl = `${protocol}//${location.host}/ws/dashboard`;
                
                this.dashboardWebSocket = new WebSocket(wsUrl);
                
                this.dashboardWebSocket.onmessage = (event) => {
                    const data = JSON.parse(event.data);
                    this.handleRealTimeUpdate(data);
                };
                
                this.dashboardWebSocket.onopen = () => {
                    console.log('Dashboard WebSocket connected');
                };
                
                this.dashboardWebSocket.onclose = () => {
                    console.log('Dashboard WebSocket disconnected, attempting reconnection...');
                    setTimeout(() => this.initializeWebSocket(), 5000);
                };
            } catch (error) {
                console.warn('WebSocket connection failed:', error);
            }
        }
    },

    handleRealTimeUpdate(data) {
        switch (data.type) {
            case 'new_analysis':
                this.handleNewAnalysis(data.payload);
                break;
            case 'stats_update':
                this.updateStatisticsCards(data.payload);
                break;
            case 'threat_alert':
                this.handleThreatAlert(data.payload);
                break;
        }
    },

    handleNewAnalysis(analysis) {
        // Update recent analyses table
        const recentAnalyses = [analysis];
        this.updateRecentAnalyses(recentAnalyses);
        
        // Show notification for high-risk analyses
        if (analysis.threat_score >= 70) {
            PhishingApp.showNotification(
                `High-risk email detected: ${analysis.email_subject}`, 
                'danger',
                10000
            );
        }
    },

    handleThreatAlert(alert) {
        PhishingApp.showNotification(alert.message, alert.level, 15000);
        
        // Add to activity feed
        this.addActivityItem({
            type: 'threat_detected',
            message: alert.message,
            timestamp: new Date().toISOString(),
            severity: alert.level
        });
    }
};

// Global functions for dashboard interactions
window.refreshDashboard = function() {
    Dashboard.updateDashboardData();
    PhishingApp.showNotification('Dashboard refreshed', 'info');
};

window.setTimeRange = function(range) {
    // This would update the dashboard to show data for the specified time range
    console.log('Setting time range to:', range);
    PhishingApp.showNotification(`Time range set to ${range}`, 'info');
};

window.viewAnalysis = function(analysisId) {
    PhishingApp.viewAnalysis(analysisId);
};

window.quarantineEmail = function(analysisId) {
    PhishingApp.quarantineEmail(analysisId);
};

window.toggleActivityFeed = function() {
    Dashboard.toggleActivityFeed();
};

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    // Wait a bit for other scripts to load
    setTimeout(() => {
        if (document.getElementById('dashboard-content')) {
            Dashboard.init();
        }
    }, 100);
});

// Make Dashboard available globally
window.Dashboard = Dashboard;
