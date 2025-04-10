/**
 * ThreatVision  URL Scanner JavaScript
 * Handles URL analysis for potential phishing threats
 */

document.addEventListener('DOMContentLoaded', function() {
  // DOM Elements
  const urlInput = document.getElementById('urlInput');
  const scanUrlBtn = document.getElementById('scanUrlBtn');
  const scanProgress = document.getElementById('scanProgress');
  const progressBarFill = document.getElementById('progressBarFill');
  const scanStatus = document.getElementById('scanStatus');
  const resultSection = document.getElementById('resultSection');
  const statusIndicator = document.getElementById('statusIndicator');
  const resultText = document.getElementById('resultText');
  const scannedUrl = document.getElementById('scannedUrl');
  const riskPercentage = document.getElementById('riskPercentage');
  const riskCircle = document.getElementById('riskCircle');
  const featuresList = document.getElementById('featuresList');
  const exportReportBtn = document.getElementById('exportReportBtn');
  const resetBtn = document.getElementById('resetBtn');
  const errorMessage = document.getElementById('error-message');

  // Current scan results
  let currentResults = null;

  // Event Listeners
  scanUrlBtn.addEventListener('click', handleScanUrl);
  resetBtn.addEventListener('click', resetScan);
  exportReportBtn.addEventListener('click', exportReport);
  urlInput.addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
      handleScanUrl();
    }
  });

  /**
   * Handle URL scan initiation
   */
  function handleScanUrl() {
    const url = urlInput.value.trim();
    
    if (!url) {
      showError('Please enter a URL to scan');
      return;
    }

    // Validate URL format
    let formattedUrl = url;
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      formattedUrl = 'http://' + url;
    }

    try {
      new URL(formattedUrl);
    } catch (e) {
      showError('Please enter a valid URL (e.g., example.com or https://example.com)');
      return;
    }

    // Reset previous scan
    hideError();
    resetResultDisplay();
    
    // Show progress bar
    scanProgress.style.display = 'block';
    progressBarFill.style.width = '0%';
    scanStatus.textContent = 'Analyzing URL...';
    
    // Start progress animation
    let progress = 0;
    const progressInterval = setInterval(() => {
      if (progress < 90) {
        progress += 2;
        progressBarFill.style.width = `${progress}%`;
      }
    }, 50);

    // Send URL to server for analysis
    fetch('/analyze', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url: formattedUrl })
    })
    .then(response => {
      clearInterval(progressInterval);
      
      if (!response.ok) {
        throw new Error(`Server responded with status: ${response.status}`);
      }
      
      progressBarFill.style.width = '100%';
      return response.json();
    })
    .then(data => {
      if (!data.success) {
        throw new Error(data.error || 'URL analysis failed');
      }
      
      // Store results for export
      currentResults = {
        url: formattedUrl,
        timestamp: new Date().toISOString(),
        risk_percentage: data.risk_percentage,
        features: data.features
      };
      
      // Display results
      setTimeout(() => {
        scanProgress.style.display = 'none';
        displayResults(data, formattedUrl);
      }, 500);
    })
    .catch(error => {
      clearInterval(progressInterval);
      console.error('Error analyzing URL:', error);
      
      // Fallback to local analysis if server fails
      scanStatus.textContent = 'Server analysis failed, performing local analysis...';
      progressBarFill.style.width = '100%';
      
      try {
        const results = performLocalAnalysis(formattedUrl);
        currentResults = {
          url: formattedUrl,
          timestamp: new Date().toISOString(),
          risk_percentage: results.riskScore,
          features: results.features
        };
        
        setTimeout(() => {
          scanProgress.style.display = 'none';
          displayLocalResults(results, formattedUrl);
        }, 500);
      } catch (e) {
        showError('Unable to analyze URL. Please try again later.');
        scanProgress.style.display = 'none';
      }
    });
  }

  /**
   * Perform a local URL analysis as fallback
   * @param {string} url - The URL to analyze
   * @returns {object} Analysis results
   */
  function performLocalAnalysis(url) {
    let urlObj;
    try {
      urlObj = new URL(url);
    } catch (error) {
      return {
        riskScore: 80,
        features: {
          malformed_url: true
        },
        issues: [{
          feature: 'malformed_url',
          risk: 'high',
          description: 'Invalid or malformed URL structure',
          weight: 80
        }]
      };
    }

    const features = {
      ip_address: /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(urlObj.hostname),
      url_length: url.length > 75,
      tiny_url: /bit\.ly|goo\.gl|tinyurl\.com|t\.co|is\.gd|cli\.gs|ow\.ly|shortened\.link/i.test(url),
      at_symbol: url.includes('@'),
      double_slash: (url.match(/\/{2,}/g) || []).length > 1,
      prefix_suffix: urlObj.hostname.includes('-'),
      sub_domains: (urlObj.hostname.match(/\./g) || []).length > 2,
      https: urlObj.protocol !== 'https:',
      port_specified: urlObj.port !== '',
      suspicious_tld: /\.tk|\.ml|\.ga|\.cf|\.xyz|\.info|\.ru|\.cn|\.top/i.test(urlObj.hostname),
      special_chars: /[<>{}\[\]()'`\\]/.test(url),
      encoded_chars: /%[0-9a-fA-F]{2}/.test(url),
      excessive_dots: (url.match(/\./g) || []).length > 4,
      excessive_hyphens: (url.match(/-/g) || []).length > 2,
      suspicious_keywords: /login|account|secure|banking|verify|signin|password|update/i.test(url)
    };

    const riskWeights = {
      ip_address: 40,
      url_length: 15,
      tiny_url: 35,
      at_symbol: 30,
      double_slash: 25,
      prefix_suffix: 20,
      sub_domains: 25,
      port_specified: 25,
      https: 30,
      suspicious_tld: 35,
      special_chars: 25,
      encoded_chars: 25,
      excessive_dots: 20,
      excessive_hyphens: 20,
      suspicious_keywords: 30
    };

    let weightedScore = 0;
    let totalWeight = 0;
    const detectedIssues = [];

    for (const [feature, isPresent] of Object.entries(features)) {
      if (isPresent && riskWeights[feature]) {
        const weight = riskWeights[feature];
        weightedScore += weight;
        totalWeight += weight;
        
        detectedIssues.push({
          feature,
          risk: weight >= 30 ? 'high' : weight >= 20 ? 'medium' : 'low',
          description: getFeatureDescription(feature),
          weight
        });
      }
    }

    const riskScore = totalWeight > 0 ? Math.min(Math.round((weightedScore / totalWeight) * 100), 100) : 0;

    return {
      riskScore,
      issues: detectedIssues,
      features
    };
  }

  /**
   * Reset result display elements
   */
  function resetResultDisplay() {
    resultSection.style.display = 'none';
    statusIndicator.className = 'status-indicator';
    resultText.textContent = 'Analyzing...';
    scannedUrl.textContent = '';
    riskPercentage.textContent = '0%';
    riskCircle.style.strokeDashoffset = '339.292';
    riskCircle.style.stroke = '#00b4d8';
    featuresList.innerHTML = '';
  }

  /**
   * Display server analysis results
   * @param {object} data - Server response data
   * @param {string} url - The URL that was analyzed
   */
  function displayResults(data, url) {
    resultSection.style.display = 'block';
    scannedUrl.textContent = url;
    
    const riskPercentVal = data.risk_percentage;
    riskPercentage.textContent = `${riskPercentVal}%`;
    
    // Adjust risk circle
    const dashOffset = 339.292 * (1 - riskPercentVal / 100);
    riskCircle.style.strokeDashoffset = dashOffset;
    
    // Set risk color
    const riskColor = getRiskColor(riskPercentVal);
    riskCircle.style.stroke = riskColor;
    
    // Set risk status
    const riskLevel = riskPercentVal >= 70 ? 'high' : riskPercentVal >= 40 ? 'medium' : 'low';
    statusIndicator.className = `status-indicator ${riskLevel}-risk`;
    resultText.textContent = `${riskPercentVal}% - ${riskLevel === 'high' ? 'High Risk' : riskLevel === 'medium' ? 'Medium Risk' : 'Low Risk'}`;
    
    // Display features
    featuresList.innerHTML = '';
    
    const detectedFeatures = Object.keys(data.features).filter(key => data.features[key]);
    
    if (detectedFeatures.length === 0) {
      featuresList.innerHTML = '<div class="feature-item safe"><div class="feature-header"><span class="feature-name">No suspicious patterns detected</span><span class="risk-badge low">SAFE</span></div></div>';
      return;
    }
    
    detectedFeatures.forEach(feature => {
      const featureRisk = getRiskLevelForFeature(feature);
      const element = document.createElement('div');
      element.className = `feature-item ${featureRisk}`;
      element.innerHTML = `
        <div class="feature-header">
          <span class="feature-name">${getFeatureDescription(feature)}</span>
          <span class="risk-badge ${featureRisk}">${featureRisk.toUpperCase()}</span>
        </div>
        <div class="feature-impact">This feature contributes to phishing risk assessment</div>
      `;
      featuresList.appendChild(element);
    });
  }

  /**
   * Display local analysis results
   * @param {object} results - Local analysis results
   * @param {string} url - The URL that was analyzed
   */
  function displayLocalResults(results, url) {
    resultSection.style.display = 'block';
    scannedUrl.textContent = url;
    
    const riskPercentVal = results.riskScore;
    riskPercentage.textContent = `${riskPercentVal}%`;
    
    // Adjust risk circle
    const dashOffset = 339.292 * (1 - riskPercentVal / 100);
    riskCircle.style.strokeDashoffset = dashOffset;
    
    // Set risk color
    const riskColor = getRiskColor(riskPercentVal);
    riskCircle.style.stroke = riskColor;
    
    // Set risk status
    const riskLevel = riskPercentVal >= 70 ? 'high' : riskPercentVal >= 40 ? 'medium' : 'low';
    statusIndicator.className = `status-indicator ${riskLevel}-risk`;
    resultText.textContent = `${riskPercentVal}% - ${riskLevel === 'high' ? 'High Risk' : riskLevel === 'medium' ? 'Medium Risk' : 'Low Risk'}`;
    
    // Display features
    featuresList.innerHTML = '';
    
    if (results.issues.length === 0) {
      featuresList.innerHTML = '<div class="feature-item safe"><div class="feature-header"><span class="feature-name">No suspicious patterns detected</span><span class="risk-badge low">SAFE</span></div></div>';
      return;
    }
    
    results.issues.forEach(issue => {
      const element = document.createElement('div');
      element.className = `feature-item ${issue.risk}`;
      element.innerHTML = `
        <div class="feature-header">
          <span class="feature-name">${issue.description}</span>
          <span class="risk-badge ${issue.risk}">${issue.risk.toUpperCase()}</span>
        </div>
        <div class="feature-impact">Impact Score: ${issue.weight}</div>
      `;
      featuresList.appendChild(element);
    });
  }

  /**
   * Reset scan to start over
   */
  function resetScan() {
    urlInput.value = '';
    resetResultDisplay();
    hideError();
    resultSection.style.display = 'none';
    currentResults = null;
  }

  /**
   * Export report as JSON or CSV
   */
  function exportReport() {
    if (!currentResults) {
      showError('No scan results to export');
      return;
    }
    
    const filename = `ThreatVision-report-${new Date().toISOString().slice(0, 10)}.json`;
    const jsonData = JSON.stringify(currentResults, null, 2);
    const blob = new Blob([jsonData], { type: 'application/json' });
    
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }

  /**
   * Show error message
   * @param {string} message - Error message to display
   */
  function showError(message) {
    errorMessage.textContent = message;
    errorMessage.style.display = 'block';
  }

  /**
   * Hide error message
   */
  function hideError() {
    errorMessage.textContent = '';
    errorMessage.style.display = 'none';
  }

  /**
   * Get color for risk percentage
   * @param {number} percentage - Risk percentage
   * @returns {string} CSS color
   */
  function getRiskColor(percentage) {
    if (percentage >= 70) {
      return '#ff4444'; // High risk - red
    } else if (percentage >= 40) {
      return '#ffaa00'; // Medium risk - amber
    } else {
      return '#00cc44'; // Low risk - green
    }
  }

  /**
   * Get risk level for a specific feature
   * @param {string} feature - Feature name
   * @returns {string} Risk level (high, medium, low)
   */
  function getRiskLevelForFeature(feature) {
    const highRiskFeatures = ['ip_address', 'suspicious_tld', 'brand_impersonation', 'suspicious_keywords', 'encoded_chars', 'https_domain'];
    const mediumRiskFeatures = ['at_symbol', 'special_chars', 'sub_domains', 'prefix_suffix', 'redirecting', 'https', 'tiny_url', 'sfh'];
    const lowRiskFeatures = ['url_length', 'anchor', 'links', 'favicon', 'numeric_domain'];
    
    if (highRiskFeatures.includes(feature)) {
      return 'high';
    } else if (mediumRiskFeatures.includes(feature)) {
      return 'medium';
    } else {
      return 'low';
    }
  }

  /**
   * Get human-readable description for a feature
   * @param {string} feature - Feature name
   * @returns {string} Description
   */
  function getFeatureDescription(feature) {
    const descriptions = {
      ip_address: 'IP address used instead of domain name',
      url_length: 'Unusually long URL',
      tiny_url: 'URL shortening service detected',
      at_symbol: 'Contains @ symbol in URL',
      redirecting: 'URL contains redirection',
      prefix_suffix: 'Hyphen in domain name',
      sub_domains: 'Excessive number of subdomains',
      https: 'Not using HTTPS protocol',
      favicon: 'Favicon from external domain',
      port: 'Non-standard port specified',
      https_domain: 'HTTPS in domain name',
      request_url: 'Request in URL path',
      anchor: 'Suspicious anchor tag',
      links: 'Abnormal link patterns',
      sfh: 'Server form handler manipulation',
      mailto: 'Mailto function detected',
      iframes: 'Hidden iframes detected',
      suspicious_tld: 'Suspicious top-level domain',
      special_chars: 'Special characters in URL',
      encoded_chars: 'Encoded characters in URL',
      brand_impersonation: 'Possible brand impersonation',
      numeric_domain: 'Excessive numbers in domain',
      suspicious_keywords: 'Contains suspicious keywords',
      double_slash: 'Multiple forward slashes',
      port_specified: 'Non-standard port specified',
      excessive_dots: 'Excessive dots in URL',
      excessive_hyphens: 'Excessive hyphens in domain',
      malformed_url: 'Invalid or malformed URL structure'
    };
    
    return descriptions[feature] || 'Unknown suspicious feature detected';
  }

  // Theme toggle functionality (if present in the page)
  const themeToggle = document.getElementById('themeToggle');
  if (themeToggle) {
    themeToggle.addEventListener('click', function() {
      document.body.classList.toggle('light-mode');
      document.body.classList.toggle('dark-mode');
      themeToggle.textContent = document.body.classList.contains('light-mode') ? '🌙' : '☀️';
    });
  }
});