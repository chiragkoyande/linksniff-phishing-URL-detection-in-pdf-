// Dashboard for ThreatVision  Extension
// Displays statistics and history of scanned PDFs/URLs

document.addEventListener('DOMContentLoaded', function() {
  initDashboard();
});

// Initialize dashboard elements
function initDashboard() {
  // Theme toggle
  const themeToggle = document.getElementById('themeToggle');
  themeToggle.addEventListener('click', toggleTheme);
  
  // Fetch and display history data
  fetchAnalysisHistory();
  
  // Set up interval to refresh data every 5 minutes
  setInterval(fetchAnalysisHistory, 300000);
}

// Toggle between light and dark themes
function toggleTheme() {
  const body = document.body;
  const isDarkMode = body.classList.contains('dark-mode');
  
  if (isDarkMode) {
    body.classList.remove('dark-mode');
    body.classList.add('light-mode');
    themeToggle.textContent = '🌙';
  } else {
    body.classList.remove('light-mode');
    body.classList.add('dark-mode');
    themeToggle.textContent = '☀️';
  }
  
  // Redraw charts with new theme colors
  refreshAllCharts();
}

// Fetch analysis history and statistics
async function fetchAnalysisHistory() {
  try {
    const response = await fetch('/get-history');
    const data = await response.json();
    
    // Update statistics
    updateStats(data.statistics);
    
    // Update feature statistics
    updateFeatureStats(data.feature_stats);
    
    // Update history table
    updateHistoryTable(data.history);
    
    // Update charts
    updateCharts(data);
  } catch (error) {
    console.error('Error fetching history data:', error);
    document.getElementById('error-message').textContent = 'Error loading dashboard data. Please try again.';
    document.getElementById('error-message').style.display = 'block';
  }
}

// Update summary statistics
function updateStats(stats) {
  document.getElementById('total-scans').textContent = stats.total_scans;
  document.getElementById('high-risk-count').textContent = stats.high_risk;
  document.getElementById('medium-risk-count').textContent = stats.medium_risk;
  document.getElementById('low-risk-count').textContent = stats.low_risk;
  
  // Calculate percentages
  const highRiskPercentage = stats.total_scans > 0 ? Math.round((stats.high_risk / stats.total_scans) * 100) : 0;
  const mediumRiskPercentage = stats.total_scans > 0 ? Math.round((stats.medium_risk / stats.total_scans) * 100) : 0;
  const lowRiskPercentage = stats.total_scans > 0 ? Math.round((stats.low_risk / stats.total_scans) * 100) : 0;
  
  document.getElementById('high-risk-percentage').textContent = `${highRiskPercentage}%`;
  document.getElementById('medium-risk-percentage').textContent = `${mediumRiskPercentage}%`;
  document.getElementById('low-risk-percentage').textContent = `${lowRiskPercentage}%`;
  
  // Update progress bars
  document.getElementById('high-risk-bar').style.width = `${highRiskPercentage}%`;
  document.getElementById('medium-risk-bar').style.width = `${mediumRiskPercentage}%`;
  document.getElementById('low-risk-bar').style.width = `${lowRiskPercentage}%`;
}

// Update feature statistics
function updateFeatureStats(featureStats) {
  const featureList = document.getElementById('feature-stats-list');
  featureList.innerHTML = '';
  
  // Sort features by frequency (descending)
  const sortedFeatures = Object.entries(featureStats)
    .sort((a, b) => b[1] - a[1]);
  
  // Display top 10 features
  const topFeatures = sortedFeatures.slice(0, 10);
  
  topFeatures.forEach(([feature, count]) => {
    const featureItem = document.createElement('div');
    featureItem.className = 'feature-item';
    
    // Format feature name for display
    const formattedName = feature
      .replace(/_/g, ' ')
      .split(' ')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ');
    
    featureItem.innerHTML = `
      <div class="feature-name">${formattedName}</div>
      <div class="feature-count">${count}</div>
      <div class="feature-bar-container">
        <div class="feature-bar" style="width: ${Math.min(100, (count / topFeatures[0][1]) * 100)}%"></div>
      </div>
    `;
    
    featureList.appendChild(featureItem);
  });
}

// Update history table
function updateHistoryTable(history) {
  const historyTable = document.getElementById('history-table-body');
  historyTable.innerHTML = '';
  
  // Sort history by timestamp (most recent first)
  history.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  
  history.forEach(entry => {
    const row = document.createElement('tr');
    
    // Determine risk class
    let riskClass = '';
    if (entry.risk_percentage >= 70) {
      riskClass = 'high-risk';
    } else if (entry.risk_percentage >= 40) {
      riskClass = 'medium-risk';
    } else {
      riskClass = 'low-risk';
    }
    
    // Format timestamp
    const timestamp = new Date(entry.timestamp).toLocaleString();
    
    // Format features
    const activeFeatures = Object.entries(entry.features)
      .filter(([_, value]) => value)
      .map(([key, _]) => key.replace(/_/g, ' '))
      .map(feature => feature.charAt(0).toUpperCase() + feature.slice(1))
      .join(', ');
    
    row.innerHTML = `
      <td>${timestamp}</td>
      <td class="url-cell"><div class="url-text">${entry.url}</div></td>
      <td><span class="risk-badge ${riskClass}">${entry.risk_percentage}%</span></td>
      <td><div class="features-tooltip">
        ${activeFeatures.length > 50 ? activeFeatures.substring(0, 50) + '...' : activeFeatures}
        <span class="tooltip-text">${activeFeatures}</span>
      </div></td>
    `;
    
    historyTable.appendChild(row);
  });
}

// Update all charts
function updateCharts(data) {
  const stats = data.statistics;
  const featureStats = data.feature_stats;
  
  // Distribution by risk level chart
  updateRiskDistributionChart(stats);
  
  // Trend chart by date
  updateTrendChart(stats.by_date);
  
  // Feature frequency chart
  updateFeatureFrequencyChart(featureStats);
}

// Update risk distribution chart
function updateRiskDistributionChart(stats) {
  const ctx = document.getElementById('risk-distribution-chart').getContext('2d');
  
  // Check if chart already exists
  if (window.riskDistributionChart) {
    window.riskDistributionChart.destroy();
  }
  
  const isDarkMode = document.body.classList.contains('dark-mode');
  const textColor = isDarkMode ? '#e9ecef' : '#212529';
  
  window.riskDistributionChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['High Risk', 'Medium Risk', 'Low Risk'],
      datasets: [{
        data: [stats.high_risk, stats.medium_risk, stats.low_risk],
        backgroundColor: ['#ff4444', '#ffaa00', '#00cc44'],
        borderColor: isDarkMode ? '#1e1e1e' : '#ffffff',
        borderWidth: 2
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'bottom',
          labels: {
            color: textColor,
            padding: 20,
            font: {
              size: 12
            }
          }
        },
        tooltip: {
          callbacks: {
            label: function(context) {
              const value = context.raw;
              const total = context.dataset.data.reduce((a, b) => a + b, 0);
              const percentage = total > 0 ? Math.round((value / total) * 100) : 0;
              return `${context.label}: ${value} (${percentage}%)`;
            }
          }
        }
      },
      cutout: '60%',
      animation: {
        animateScale: true,
        animateRotate: true
      }
    }
  });
}

// Update trend chart
function updateTrendChart(dateData) {
  const ctx = document.getElementById('trend-chart').getContext('2d');
  
  // Check if chart already exists
  if (window.trendChart) {
    window.trendChart.destroy();
  }
  
  // Sort dates
  const sortedDates = Object.keys(dateData).sort();
  
  const isDarkMode = document.body.classList.contains('dark-mode');
  const textColor = isDarkMode ? '#e9ecef' : '#212529';
  const gridColor = isDarkMode ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)';
  
  window.trendChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: sortedDates,
      datasets: [{
        label: 'Scans',
        data: sortedDates.map(date => dateData[date]),
        borderColor: '#00b4d8',
        backgroundColor: 'rgba(0, 180, 216, 0.2)',
        tension: 0.3,
        fill: true,
        pointBackgroundColor: '#0077b6',
        pointBorderColor: isDarkMode ? '#1e1e1e' : '#ffffff',
        pointRadius: 4,
        pointHoverRadius: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          grid: {
            color: gridColor
          },
          ticks: {
            color: textColor
          }
        },
        y: {
          beginAtZero: true,
          grid: {
            color: gridColor
          },
          ticks: {
            color: textColor,
            precision: 0
          }
        }
      },
      plugins: {
        legend: {
          display: false
        },
        tooltip: {
          mode: 'index',
          intersect: false
        }
      }
    }
  });
}

// Update feature frequency chart
function updateFeatureFrequencyChart(featureStats) {
  const ctx = document.getElementById('feature-chart').getContext('2d');
  
  // Check if chart already exists
  if (window.featureChart) {
    window.featureChart.destroy();
  }
  
  // Sort features by frequency and take top 8
  const sortedFeatures = Object.entries(featureStats)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8);
  
  // Format feature names
  const labels = sortedFeatures.map(([feature, _]) => 
    feature
      .replace(/_/g, ' ')
      .split(' ')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ')
  );
  
  const data = sortedFeatures.map(([_, count]) => count);
  
  const isDarkMode = document.body.classList.contains('dark-mode');
  const textColor = isDarkMode ? '#e9ecef' : '#212529';
  const gridColor = isDarkMode ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)';
  
  window.featureChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{
        label: 'Frequency',
        data: data,
        backgroundColor: [
          'rgba(255, 99, 132, 0.7)',
          'rgba(54, 162, 235, 0.7)',
          'rgba(255, 206, 86, 0.7)',
          'rgba(75, 192, 192, 0.7)',
          'rgba(153, 102, 255, 0.7)',
          'rgba(255, 159, 64, 0.7)',
          'rgba(199, 199, 199, 0.7)',
          'rgba(83, 102, 255, 0.7)'
        ],
        borderColor: [
          'rgb(255, 99, 132)',
          'rgb(54, 162, 235)',
          'rgb(255, 206, 86)',
          'rgb(75, 192, 192)',
          'rgb(153, 102, 255)',
          'rgb(255, 159, 64)',
          'rgb(199, 199, 199)',
          'rgb(83, 102, 255)'
        ],
        borderWidth: 1
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          beginAtZero: true,
          grid: {
            color: gridColor
          },
          ticks: {
            color: textColor,
            precision: 0
          }
        },
        y: {
          grid: {
            display: false
          },
          ticks: {
            color: textColor
          }
        }
      },
      plugins: {
        legend: {
          display: false
        }
      }
    }
  });
}

// Refresh all charts (after theme change)
function refreshAllCharts() {
  fetchAnalysisHistory();
}

// Export report as PDF
function exportAsPdf() {
  const doc = new jsPDF();
  
  // Add title
  doc.setFontSize(20);
  doc.text('ThreatVision  Analysis Report', 20, 20);
  
  // Add date
  doc.setFontSize(12);
  doc.text(`Generated on: ${new Date().toLocaleString()}`, 20, 30);
  
  // Add summary data
  doc.setFontSize(16);
  doc.text('Summary', 20, 45);
  
  const totalScans = document.getElementById('total-scans').textContent;
  const highRisk = document.getElementById('high-risk-count').textContent;
  const mediumRisk = document.getElementById('medium-risk-count').textContent;
  const lowRisk = document.getElementById('low-risk-count').textContent;
  
  doc.setFontSize(12);
  doc.text(`Total Scans: ${totalScans}`, 25, 55);
  doc.text(`High Risk URLs: ${highRisk}`, 25, 65);
  doc.text(`Medium Risk URLs: ${mediumRisk}`, 25, 75);
  doc.text(`Low Risk URLs: ${lowRisk}`, 25, 85);
  
  // Add charts as images
  // Distribution chart
  doc.setFontSize(16);
  doc.text('Risk Distribution', 20, 105);
  
  const riskChartCanvas = document.getElementById('risk-distribution-chart');
  const riskChartImage = riskChartCanvas.toDataURL('image/png');
  doc.addImage(riskChartImage, 'PNG', 20, 110, 80, 60);
  
  // Feature chart
  doc.text('Common Phishing Features', 120, 105);
  
  const featureChartCanvas = document.getElementById('feature-chart');
  const featureChartImage = featureChartCanvas.toDataURL('image/png');
  doc.addImage(featureChartImage, 'PNG', 120, 110, 80, 60);
  
  // Add new page for trend chart
  doc.addPage();
  
  // Trend chart
  doc.setFontSize(16);
  doc.text('Scan Trend', 20, 20);
  
  const trendChartCanvas = document.getElementById('trend-chart');
  const trendChartImage = trendChartCanvas.toDataURL('image/png');
  doc.addImage(trendChartImage, 'PNG', 20, 25, 170, 60);
  
  // Save PDF
  doc.save('ThreatVision_report.pdf');
}

// Export data as CSV
function exportAsCsv() {
  // Get history table data
  const historyTable = document.getElementById('history-table-body');
  const rows = historyTable.getElementsByTagName('tr');
  
  const csvData = [];
  
  // Add header row
  csvData.push(['Timestamp', 'URL', 'Risk Score', 'Features']);
  
  // Add data rows
  for (const row of rows) {
    const cells = row.getElementsByTagName('td');
    
    const timestamp = cells[0].textContent;
    const url = cells[1].querySelector('.url-text').textContent;
    const riskScore = cells[2].querySelector('.risk-badge').textContent;
    
    // Get full features from tooltip
    const features = cells[3].querySelector('.tooltip-text').textContent;
    
    csvData.push([timestamp, url, riskScore, features]);
  }
  
  // Generate CSV content
  const csv = Papa.unparse(csvData);
  
  // Create download link
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', 'ThreatVision_history.csv');
  link.style.visibility = 'hidden';
  
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

// Add event listeners for export buttons
document.addEventListener('DOMContentLoaded', function() {
  document.getElementById('export-pdf').addEventListener('click', exportAsPdf);
  document.getElementById('export-csv').addEventListener('click', exportAsCsv);
});
