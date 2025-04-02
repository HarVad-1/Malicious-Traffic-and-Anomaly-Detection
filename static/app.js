// Initialize variables
let monitoring = false;
let startTime = null;
let uptimeInterval = null;
let alertCount = 0;
let attackCount = 0;
let packetCount = 0;
let sourceIPs = {};
let alertTypes = {
    'ICMP': 0,
    'TCP': 0,
    'UDP': 0,
    'Ping of Death': 0,
    'Ping Flood': 0,
    'SSH Attack': 0,
    'Nmap Scan': 0,
    'SQL Injection': 0,
    'XSS Attack': 0,
    'Other': 0
};

// Time-series data for the trend chart
const timeLabels = [];
const alertData = [];

// Initialize charts
let alertDistributionChart;
let alertTrendChart;

// DOM elements
const startBtn = document.getElementById('startBtn');
const stopBtn = document.getElementById('stopBtn');
const generateReportBtn = document.getElementById('generateReportBtn');
const alertTableBody = document.getElementById('alertTableBody');
const statusBar = document.getElementById('statusBar');
const totalAlertsEl = document.getElementById('totalAlerts');
const attackAlertsEl = document.getElementById('attackAlerts');
const packetCountEl = document.getElementById('packetCount');
const uptimeEl = document.getElementById('uptime');
const sourceIPsEl = document.getElementById('sourceIPs');
const reportModal = new bootstrap.Modal(document.getElementById('reportModal'));

// Initialize charts
function initCharts() {
    // Alert Distribution Chart (Pie)
    const distributionCtx = document.getElementById('alertDistribution').getContext('2d');
    alertDistributionChart = new Chart(distributionCtx, {
        type: 'doughnut',
        data: {
            labels: Object.keys(alertTypes),
            datasets: [{
                data: Object.values(alertTypes),
                backgroundColor: [
                    '#ffc107', // ICMP - yellow
                    '#17a2b8', // TCP - cyan
                    '#28a745', // UDP - green
                    '#ff6b6b', // Ping of Death - light red
                    '#fd7e14', // Ping Flood - orange
                    '#6f42c1', // SSH Attack - purple
                    '#20c997', // Nmap Scan - teal
                    '#e83e8c', // SQL Injection - pink
                    '#dc3545', // XSS Attack - red
                    '#6c757d'  // Other - gray
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        boxWidth: 12,
                        padding: 15
                    }
                }
            }
        }
    });

    // Alert Trend Chart (Line)
    const trendCtx = document.getElementById('alertTrend').getContext('2d');
    alertTrendChart = new Chart(trendCtx, {
        type: 'line',
        data: {
            labels: timeLabels,
            datasets: [{
                label: 'Alerts',
                data: alertData,
                borderColor: '#007bff',
                backgroundColor: 'rgba(0, 123, 255, 0.1)',
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    grid: {
                        display: false
                    }
                },
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0
                    }
                }
            }
        }
    });
}

// Initialize the application
function init() {
    initCharts();
    setupEventListeners();
    
    // Get available interfaces
    fetch('/api/interfaces')
        .then(response => response.json())
        .then(data => {
            console.log('Available interfaces:', data.interfaces);
        })
        .catch(error => console.error('Error getting interfaces:', error));

    // Check if there's a debug param in the URL
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.has('debug')) {
        console.log('Debug mode enabled');
        // Add a debug button
        const debugBtn = document.createElement('button');
        debugBtn.innerText = 'Debug Info';
        debugBtn.className = 'btn btn-info ms-2';
        debugBtn.onclick = () => window.open('/debug', '_blank');
        document.querySelector('.d-flex.justify-content-between').appendChild(debugBtn);
    }
}

// Set up event listeners
function setupEventListeners() {
    startBtn.addEventListener('click', startMonitoring);
    stopBtn.addEventListener('click', stopMonitoring);
    generateReportBtn.addEventListener('click', generateReport);
    document.getElementById('downloadReportBtn').addEventListener('click', downloadReport);
}

// Start monitoring
function startMonitoring() {
    monitoring = true;
    startTime = new Date();
    startBtn.disabled = true;
    stopBtn.disabled = false;
    
    // Update status
    updateStatus('info', 'Starting Snort monitoring...');
    
    // Start uptime counter
    uptimeInterval = setInterval(updateUptime, 1000);
    
    // Start Snort via the backend
    fetch('/api/start', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            interface: 'enp0s3' // Make sure this matches your actual interface
        }),
    })
    .then(response => response.json())
    .then(data => {
        console.log('Start response:', data);
        if (data.status === 'started') {
            updateStatus('success', 'Snort monitoring started. Listening for alerts...');
            // Start polling for alerts
            pollAlerts();
        } else if (data.status === 'already_running') {
            updateStatus('warning', 'Snort is already running');
            pollAlerts();
        } else {
            updateStatus('danger', 'Failed to start Snort: ' + (data.message || 'Unknown error'));
        }
    })
    .catch(error => {
        console.error('Error starting Snort:', error);
        updateStatus('danger', 'Error connecting to backend: ' + error);
    });
}

// Poll for alerts
function pollAlerts() {
    if (!monitoring) return;
    
    console.log('Polling for alerts...');
    
    fetch('/api/status')
        .then(response => response.json())
        .then(data => {
            console.log('Status response:', data);
            // Update counters
            alertCount = data.alerts;
            attackCount = data.attacks;
            packetCount = data.packets;
            updateCounters();
        })
        .catch(error => console.error('Error fetching status:', error));

    fetch('/api/alerts?limit=100')
        .then(response => response.json())
        .then(alerts => {
            console.log('Alerts response received, count:', alerts.length);
            // Clear current alerts
            alertTableBody.innerHTML = '';
            
            // Process each alert
            alerts.forEach(alert => {
                addAlertToLog(alert);
            });
            
            // If no alerts yet, add a message
            if (alerts.length === 0) {
                const row = document.createElement('tr');
                row.innerHTML = '<td colspan="5" class="text-center">No alerts detected yet. Try generating some traffic that would trigger your Snort rules.</td>';
                alertTableBody.appendChild(row);
            }
        })
        .catch(error => console.error('Error fetching alerts:', error));

    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            console.log('Stats response:', data);
            // Update alert types and source IPs
            alertTypes = data.alert_types;
            sourceIPs = data.source_ips;
            
            // Update UI
            updateSourceIPs();
            updateCharts();
        })
        .catch(error => console.error('Error fetching stats:', error));
    
    // Add a new data point to the trend chart
    const now = new Date();
    const timeStr = now.toLocaleTimeString();
    
    // Add new data point
    timeLabels.push(timeStr);
    alertData.push(alertCount);
    
    // Limit to last 10 data points for readability
    if (timeLabels.length > 10) {
        timeLabels.shift();
        alertData.shift();
    }
    
    // Update trend chart
    alertTrendChart.update();
    
    // Continue polling if still monitoring
    if (monitoring) {
        setTimeout(pollAlerts, 2000); // Poll every 2 seconds
    }
}

// Stop monitoring
function stopMonitoring() {
    monitoring = false;
    startBtn.disabled = false;
    stopBtn.disabled = true;
    
    // Clear uptime interval
    clearInterval(uptimeInterval);
    
    // Update status
    updateStatus('info', 'Stopping Snort monitoring...');
    
    // Stop Snort via the backend
    fetch('/api/stop', {
        method: 'POST',
    })
    .then(response => response.json())
    .then(data => {
        console.log('Stop response:', data);
        updateStatus('warning', 'Snort monitoring stopped.');
    })
    .catch(error => {
        console.error('Error stopping Snort:', error);
        updateStatus('danger', 'Error stopping Snort: ' + error);
    });
}

// Update status bar
function updateStatus(type, message) {
    statusBar.innerHTML = `
        <div class="alert alert-${type}">
            <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'warning' ? 'exclamation-circle' : type === 'info' ? 'info-circle' : 'times-circle'} me-2"></i> ${message}
        </div>
    `;
}

// Update uptime counter
function updateUptime() {
    if (!startTime) return;
    
    const now = new Date();
    const diff = Math.floor((now - startTime) / 1000);
    const minutes = Math.floor(diff / 60);
    const seconds = diff % 60;
    
    uptimeEl.textContent = `${minutes}:${seconds.toString().padStart(2, '0')}`;
}

// Update counter displays
function updateCounters() {
    totalAlertsEl.textContent = alertCount;
    attackAlertsEl.textContent = attackCount;
    packetCountEl.textContent = packetCount;
}

// Add alert to log display
function addAlertToLog(alert) {
    // Create a new row
    const row = document.createElement('tr');
    
    // Set the appropriate class based on the alert type
    switch(alert.type.toLowerCase()) {
        case 'ping of death':
            row.className = 'ping-of-death';
            break;
        case 'ping flood':
            row.className = 'ping-flood';
            break;
        case 'ssh attack':
            row.className = 'ssh-attack';
            break;
        case 'nmap scan':
            row.className = 'nmap-scan';
            break;
        case 'sql injection':
            row.className = 'sql-injection';
            break;
        case 'xss attack':
            row.className = 'xss-attack';
            break;
        default:
            row.className = alert.type.toLowerCase();
    }
    
    // Format timestamp
    const timestamp = alert.timestamp || new Date().toLocaleTimeString();
    
    // Add cells with data
    row.innerHTML = `
        <td>${timestamp}</td>
        <td>${alert.type}</td>
        <td>${alert.message || 'No message'}</td>
        <td>${alert.source || 'unknown'}</td>
        <td>${alert.destination || 'unknown'}</td>
    `;
    
    // Add to table
    alertTableBody.appendChild(row);
    
    // Limit the number of rows to prevent performance issues
    if (alertTableBody.children.length > 100) {
        alertTableBody.removeChild(alertTableBody.children[0]);
    }
    
    // Scroll to bottom if table is in a scrollable container
    const tableContainer = alertTableBody.closest('.table-responsive');
    if (tableContainer) {
        tableContainer.scrollTop = tableContainer.scrollHeight;
    }
}

// Update source IPs list
function updateSourceIPs() {
    // Sort IPs by count
    const sortedIPs = Object.entries(sourceIPs)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5); // Top 5
    
    // Clear current list
    sourceIPsEl.innerHTML = '';
    
    // Add sorted IPs
    if (sortedIPs.length === 0) {
        sourceIPsEl.innerHTML = `
            <li class="list-group-item d-flex justify-content-between align-items-center">
                No data available
            </li>
        `;
    } else {
        sortedIPs.forEach(([ip, count]) => {
            const li = document.createElement('li');
            li.className = 'list-group-item d-flex justify-content-between align-items-center';
            li.innerHTML = `
                ${ip}
                <span class="badge bg-primary rounded-pill">${count}</span>
            `;
            sourceIPsEl.appendChild(li);
        });
    }
}

// Update charts
function updateCharts() {
    // Update distribution chart
    alertDistributionChart.data.datasets[0].data = Object.values(alertTypes);
    alertDistributionChart.update();
}

// Generate report
function generateReport() {
    // Show modal
    reportModal.show();
    
    // Generate report content (this would be more sophisticated in a real implementation)
    setTimeout(() => {
        const reportContent = document.getElementById('reportContent');
        reportContent.innerHTML = `
            <div class="report-container">
                <h2 class="text-center mb-4">Snort IDS Activity Report</h2>
                <p class="text-muted">Generated on ${new Date().toLocaleString()}</p>
                
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>Summary</h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <p><strong>Total Alerts:</strong> ${alertCount}</p>
                                <p><strong>Attack Alerts:</strong> ${attackCount}</p>
                                <p><strong>Packets Analyzed:</strong> ${packetCount}</p>
                            </div>
                            <div class="col-md-6">
                                <p><strong>Monitoring Duration:</strong> ${uptimeEl.textContent}</p>
                                <p><strong>Start Time:</strong> ${startTime ? startTime.toLocaleString() : 'N/A'}</p>
                                <p><strong>End Time:</strong> ${new Date().toLocaleString()}</p>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>Alert Distribution</h5>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table">
                                <thead>
                                    <tr>
                                        <th>Alert Type</th>
                                        <th>Count</th>
                                        <th>Percentage</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${Object.entries(alertTypes).map(([type, count]) => `
                                        <tr>
                                            <td>${type}</td>
                                            <td>${count}</td>
                                            <td>${alertCount ? Math.round((count / alertCount) * 100) : 0}%</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
                
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>Top Source IPs</h5>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table">
                                <thead>
                                    <tr>
                                        <th>IP Address</th>
                                        <th>Alert Count</th>
                                        <th>Percentage</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${Object.entries(sourceIPs)
                                        .sort((a, b) => b[1] - a[1])
                                        .slice(0, 10)
                                        .map(([ip, count]) => `
                                            <tr>
                                                <td>${ip}</td>
                                                <td>${count}</td>
                                                <td>${alertCount ? Math.round((count / alertCount) * 100) : 0}%</td>
                                            </tr>
                                        `).join('')}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h5>Recent Alerts</h5>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-striped">
                                <thead>
                                    <tr>
                                        <th>Time</th>
                                        <th>Type</th>
                                        <th>Message</th>
                                        <th>Source → Destination</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${Array.from(alertTableBody.children).map(row => {
                                        if (row.cells.length === 5) {
                                            return `
                                                <tr>
                                                    <td>${row.cells[0].textContent}</td>
                                                    <td>${row.cells[1].textContent}</td>
                                                    <td>${row.cells[2].textContent}</td>
                                                    <td>${row.cells[3].textContent} → ${row.cells[4].textContent}</td>
                                                </tr>
                                            `;
                                        }
                                        return '';
                                    }).join('')}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }, 1000);
}

// Download report as PDF
function downloadReport() {
    // Show loading message
    updateStatus('info', 'Generating PDF report...');
    
    // Get report from the backend
    fetch('/api/report')
        .then(response => {
            if (!response.ok) {
                throw new Error('Report generation failed');
            }
            return response.blob();
        })
        .then(blob => {
            // Create a URL for the blob
            const url = window.URL.createObjectURL(blob);
            
            // Create a temporary link to download the file
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            a.download = 'snort_report.pdf';
            
            // Add to body, click, and remove
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            a.remove();
            
            updateStatus('success', 'PDF report downloaded successfully');
        })
        .catch(error => {
            console.error('Error downloading report:', error);
            updateStatus('danger', `Error generating PDF report: ${error.message}`);
        });
}

// Run initialization when DOM is loaded
document.addEventListener('DOMContentLoaded', init);