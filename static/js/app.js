let threatChart = null;
let lastBlockedCount = 0;
let updateCountdown = 30;
let countdownInterval = null;

document.addEventListener('DOMContentLoaded', function() {
    initializeChart();
    updateData();
    startCountdown();
    setInterval(updateData, 30000);
    
    const logFilter = document.getElementById('log-filter');
    if (logFilter) {
        logFilter.addEventListener('input', filterLogs);
    }
});

function startCountdown() {
    updateCountdown = 30;
    if (countdownInterval) clearInterval(countdownInterval);
    
    const timer = document.getElementById('update-timer');
    if (timer) {
        timer.textContent = updateCountdown + 's';
    }
    
    countdownInterval = setInterval(() => {
        updateCountdown--;
        if (timer) {
            timer.textContent = updateCountdown + 's';
        }
        if (updateCountdown <= 0) {
            clearInterval(countdownInterval);
        }
    }, 1000);
}

function initializeChart() {
    const ctx = document.getElementById('threat-chart');
    if (!ctx) return;
    
    threatChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Failed Attempts',
                data: [],
                borderColor: '#dc3545',
                backgroundColor: 'rgba(220, 53, 69, 0.1)',
                tension: 0.4,
                fill: true,
                pointRadius: 4,
                pointBackgroundColor: '#dc3545'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: true,
                    labels: { font: { size: 12 } }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    max: 10
                }
            }
        }
    });
}

function updateData() {
    updateStats();
    updateBlockedIPs();
    updateLogs();
    startCountdown();
}

function updateStats() {
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            const statsDiv = document.getElementById('stats-content');
            
            const colors = [
                'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)',
                'linear-gradient(135deg, #4facfe 0%, #00f2fe 100%)',
                'linear-gradient(135deg, #43e97b 0%, #38f9d7 100%)'
            ];
            
            const icons = ['📊', '⚠️', '✅', '🚨'];
            
            const stats = [
                { title: 'Total Logs', value: data.total_logs, icon: icons[0] },
                { title: 'Failed Attempts', value: data.failed_attempts, icon: icons[1] },
                { title: 'Successful Logins', value: data.successful_attempts, icon: icons[2] },
                { title: 'Suspicious IPs', value: data.suspicious_ips_count, icon: icons[3] }
            ];
            
            statsDiv.innerHTML = stats.map((stat, idx) => `
                <div class="stat-card stat-item" style="background: ${colors[idx]};">
                    <div style="font-size: 2.5rem; margin-bottom: 0.5rem;">${stat.icon}</div>
                    <h3>${stat.title}</h3>
                    <p>${stat.value}</p>
                </div>
            `).join('');
            
            updateChart(data.failed_attempts);
        })
        .catch(error => console.error('Error fetching stats:', error));
}

function updateChart(failedCount) {
    if (!threatChart) return;
    
    const now = new Date().toLocaleTimeString();
    
    if (threatChart.data.labels.length > 10) {
        threatChart.data.labels.shift();
        threatChart.data.datasets[0].data.shift();
    }
    
    threatChart.data.labels.push(now);
    threatChart.data.datasets[0].data.push(failedCount);
    threatChart.update('none');
}

function updateBlockedIPs() {
    fetch('/api/blocked')
        .then(response => response.json())
        .then(data => {
            const list = document.getElementById('blocked-list');
            
            if (data.length === 0) {
                list.innerHTML = '<li class="empty-state">✓ No blocked IPs - System secure</li>';
            } else {
                list.innerHTML = data.map(ip => `
                    <li>
                        <span><i class="fas fa-ban"></i> ${ip}</span>
                        <span style="font-size: 0.85rem; color: #666;">Blocked</span>
                    </li>
                `).join('');
                
                if (data.length > lastBlockedCount) {
                    showAlert(`New IP blocked: ${data[data.length - 1]}`, 'danger');
                    lastBlockedCount = data.length;
                }
            }
        })
        .catch(error => console.error('Error fetching blocked IPs:', error));
}

function updateLogs() {
    fetch('/api/logs')
        .then(response => response.json())
        .then(data => {
            const tbody = document.getElementById('logs-body');
            
            if (data.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No log entries</td></tr>';
                return;
            }
            
            const recentLogs = data.slice(-50).reverse();
            tbody.innerHTML = recentLogs.map(log => `
                <tr>
                    <td><span style="font-family: monospace; font-size: 0.85rem;">${log.timestamp}</span></td>
                    <td><strong>${log.username}</strong></td>
                    <td><span style="font-family: monospace; font-size: 0.9rem;">${log.ip}</span></td>
                    <td><span class="${log.status}">${log.status.toUpperCase()}</span></td>
                    <td><button class="btn btn-danger" onclick="blockIP('${log.ip}')">Block</button></td>
                </tr>
            `).join('');
        })
        .catch(error => console.error('Error fetching logs:', error));
}

function filterLogs() {
    const filter = document.getElementById('log-filter').value.toLowerCase();
    const rows = document.querySelectorAll('#logs-body tr');
    
    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(filter) ? '' : 'none';
    });
}

function blockIP(ip) {
    fetch('/api/block-ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip })
    })
    .then(response => response.json())
    .then(data => {
        if (data.newly_blocked) {
            showAlert(`🚫 IP ${ip} has been BLOCKED!`, 'danger');
        } else {
            showAlert(`⚠️ IP ${ip} was already blocked`, 'info');
        }
        updateData();
    })
    .catch(error => {
        console.error('Error blocking IP:', error);
        showAlert('Error blocking IP', 'danger');
    });
}

function showAlert(message, type = 'info') {
    const container = document.getElementById('alert-container');
    const alert = document.createElement('div');
    alert.className = `alert alert-${type}`;
    alert.innerHTML = `
        <span>${message}</span>
        <span class="alert-close" onclick="this.parentElement.remove()">✕</span>
    `;
    
    container.appendChild(alert);
    
    setTimeout(() => {
        if (alert.parentElement) {
            alert.remove();
        }
    }, 5000);
}