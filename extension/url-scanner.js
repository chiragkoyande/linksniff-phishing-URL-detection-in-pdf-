document.addEventListener('DOMContentLoaded', function() {
  // DOM Elements
  const urlInput = document.getElementById('urlInput');
  const scanButton = document.getElementById('scanUrlBtn');
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
  const themeToggle = document.getElementById('themeToggle');
  
  // Theme toggle
  themeToggle.addEventListener('click', function() {
    const body = document.body;
    if (body.classList.contains('dark-mode')) {
      body.classList.remove('dark-mode');
      body.classList.add('light-mode');
      themeToggle.textContent = '🌙';
    } else {
      body.classList.remove('light-mode');
      body.classList.add('dark-mode');
      themeToggle.textContent = '☀️';
    }
  });
  
  // Scan button click
  scanButton.addEventListener('click', function() {
    const url = urlInput.value.trim();
    if (!url) {
      showError('Please enter a URL to scan');
      return;
    }
    
    startURLScan(url);
  });
  
  // URL input enter key
  urlInput.addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
      scanButton.click();
    }
  });
  
  // Export report button
  exportReportBtn.addEventListener('click', function() {
    if (window.scanResults) {
      const format = window.confirm('Do you want to export as PDF? Click Cancel for CSV format.') ? 'pdf' : 'csv';
      exportReport(format);
    }
  });
  
  // Reset button click
  resetBtn.addEventListener('click', function() {
    urlInput.value = '';
    resultSection.style.display = 'none';
    window.scanResults = null;
  });

  // Start URL scan function
  function startURLScan(url) {
    scanProgress.style.display = 'block';
    resultSection.style.display = 'none';
    progressBarFill.style.width = '0%';
    scanStatus.textContent = 'Analyzing URL...';
    
    // Simulate progress
    let progress = 0;
    const progressInterval = setInterval(function() {
      progress += 5;
      if (progress > 90) {
        progress = 90;
        clearInterval(progressInterval);
      }
      progressBarFill.style.width = progress + '%';
    }, 100);

    // Perform the analysis locally first
    const localResults = analyzeUrl(url);
    
    // Make request to backend API if available
    chrome.runtime.sendMessage({
      action: 'analyzeUrl',
      url: url
    }, function(response) {
      clearInterval(progressInterval);
      progressBarFill.style.width = '100%';
      scanStatus.textContent = 'Analysis complete!';
      
      let results;
      
      // If backend API response is valid, use it, otherwise fallback to local analysis
      if (response && response.success) {
        // Merge API results with local analysis
        results = {
          riskScore: response.risk_percentage,
          features: response.features || localResults.features,
          issues: Object.entries(response.features || {})
            .filter(([_, value]) => value)
            .map(([feature, _]) => {
              const risk = getFeatureRiskLevel(feature);
              return {
                feature,
                risk,
                description: getFeatureDescription(feature),
                weight: getFeatureWeight(feature)
              };
            })
        };
      } else {
        results = localResults;
      }
      
      // Store results globally for report export
      window.scanResults = {
        url: url,
        results: results,
        timestamp: new Date().toISOString()
      };
      
      // Display results
      displayResults(results, url);
      
      // Hide progress after a delay
      setTimeout(function() {
        scanProgress.style.display = 'none';
      }, 500);
    });
  }
  
  // Analyze URL locally function
  function analyzeUrl(url) {
    let urlObj;
    try {
      urlObj = new URL(url);
    } catch (error) {
      return {
        riskScore: 100,
        issues: [{
          feature: 'invalid_url',
          risk: 'high',
          description: 'Invalid or malformed URL',
          weight: 100
        }],
        features: { invalid_url: true }
      };
    }

    const features = {
      // URL Structure Analysis
      ip_address: /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(urlObj.hostname),
      url_length: url.length > 75,
      tiny_url: /bit\.ly|goo\.gl|tinyurl\.com|t\.co|is\.gd|cli\.gs|ow\.ly|shortened\.link/i.test(url),
      at_symbol: url.includes('@'),
      double_slash: url.replace(/(^\w+:|^)\/\//, '').includes('//'),
      prefix_suffix: urlObj.hostname.includes('-'),
      sub_domains: (urlObj.hostname.match(/\./g) || []).length > 2,
      https: urlObj.protocol !== 'https:',
      port_specified: urlObj.port !== '',
      suspicious_tld: /\.tk|\.ml|\.ga|\.cf|\.xyz|\.info|\.ru|\.cn|\.top$/i.test(urlObj.hostname),
      special_chars: /[<>{}\[\]()'`\\]/.test(url),
      encoded_chars: /%[0-9a-fA-F]{2}/.test(url),
      excessive_dots: (url.match(/\./g) || []).length > 4,
      excessive_hyphens: (url.match(/-/g) || []).length > 3,
      suspicious_keywords: /login|account|secure|banking|verify|signin|password|update|confirm/i.test(url),
      brand_impersonation: /paypal|apple|microsoft|google|amazon|facebook|instagram|netflix|gmail/i.test(urlObj.hostname) && 
                           !/(paypal\.com|apple\.com|microsoft\.com|google\.com|amazon\.com|facebook\.com|instagram\.com|netflix\.com|gmail\.com)$/i.test(urlObj.hostname),
      redirecting: url.includes('redirect') || url.includes('forward') || url.includes('goto')
    };

    const detectedIssues = [];
    let totalRiskScore = 0;
    let featureCount = 0;

    for (const [feature, isPresent] of Object.entries(features)) {
      if (isPresent) {
        const featureWeight = getFeatureWeight(feature);
        totalRiskScore += featureWeight;
        featureCount++;
        
        detectedIssues.push({
          feature,
          risk: getFeatureRiskLevel(feature),
          description: getFeatureDescription(feature),
          weight: featureWeight
        });
      }
    }

    // Calculate final risk score (max 100)
    const riskScore = featureCount > 0 ? Math.min(Math.round(totalRiskScore / featureCount), 100) : 0;

    return {
      riskScore,
      issues: detectedIssues,
      features
    };
  }
  
  // Get feature weight
  function getFeatureWeight(feature) {
    const weights = {
      ip_address: 85,
      url_length: 20,
      tiny_url: 60,
      at_symbol: 65,
      double_slash: 45,
      prefix_suffix: 30,
      sub_domains: 40,
      port_specified: 40,
      https: 70,
      suspicious_tld: 75,
      special_chars: 45,
      encoded_chars: 55,
      excessive_dots: 35,
      excessive_hyphens: 30,
      suspicious_keywords: 50,
      brand_impersonation: 85,
      redirecting: 60,
      invalid_url: 100
    };
    
    return weights[feature] || 50;
  }
  
  // Get feature risk level
  function getFeatureRiskLevel(feature) {
    const highRiskFeatures = [
      'ip_address', 'https', 'suspicious_tld', 'brand_impersonation', 'invalid_url', 'tiny_url'
    ];
    
    const mediumRiskFeatures = [
      'at_symbol', 'redirecting', 'encoded_chars', 'special_chars', 'suspicious_keywords', 'port_specified'
    ];
    
    if (highRiskFeatures.includes(feature)) {
      return 'high';
    } else if (mediumRiskFeatures.includes(feature)) {
      return 'medium';
    } else {
      return 'low';
    }
  }

  // Get feature description
  function getFeatureDescription(feature) {
    const descriptions = {
      ip_address: 'IP address used instead of domain name - commonly used in phishing',
      url_length: 'Unusually long URL - may be hiding malicious content',
      tiny_url: 'URL shortening service detected - masks the actual destination',
      at_symbol: 'Contains @ symbol - can lead to URL confusion',
      double_slash: 'Multiple forward slashes - potential redirect attempt',
      prefix_suffix: 'Hyphen in domain name - possible typosquatting attempt',
      sub_domains: 'Excessive number of subdomains - complex URL structure',
      port_specified: 'Non-standard port specified - unusual configuration',
      https: 'Not using HTTPS protocol - connection not secure',
      suspicious_tld: 'Suspicious top-level domain - commonly used in phishing',
      special_chars: 'Contains special characters - possible obfuscation',
      encoded_chars: 'Contains encoded characters - possible obfuscation',
      excessive_dots: 'Excessive dots in URL - complex structure',
      excessive_hyphens: 'Excessive hyphens - possible typosquatting',
      suspicious_keywords: 'Contains suspicious keywords - common in phishing URLs',
      brand_impersonation: 'Possible brand impersonation attempt - common phishing tactic',
      redirecting: 'URL contains redirection - may lead to malicious site',
      invalid_url: 'Invalid or malformed URL - cannot be analyzed properly'
    };
    
    return descriptions[feature] || 'Suspicious URL pattern detected';
  }
  
  // Display results function
  function displayResults(data, url) {
    resultSection.style.display = 'block';
    
    // Set scanned URL
    scannedUrl.textContent = url;
    
    // Update risk percentage
    const riskScore = data.riskScore;
    riskPercentage.textContent = riskScore + '%';
    
    // Update circle progress
    const circumference = 2 * Math.PI * 54;
    const offset = circumference - (circumference * riskScore / 100);
    riskCircle.style.strokeDasharray = `${circumference} ${circumference}`;
    riskCircle.style.strokeDashoffset = offset;
    
    // Set risk color and status
    let riskColor, riskStatus;
    if (riskScore >= 70) {
      riskColor = '#ff4444';
      riskStatus = 'High Risk';
      statusIndicator.className = 'status-indicator danger';
    } else if (riskScore >= 40) {
      riskColor = '#ffaa00';
      riskStatus = 'Medium Risk';
      statusIndicator.className = 'status-indicator warning';
    } else {
      riskColor = '#00cc44';
      riskStatus = 'Low Risk';
      statusIndicator.className = 'status-indicator safe';
    }
    
    riskCircle.style.stroke = riskColor;
    resultText.textContent = riskStatus;
    resultText.style.color = riskColor;
    
    // Update features list
    featuresList.innerHTML = '';
    
    if (data.issues && data.issues.length > 0) {
      // Sort issues by risk level (high to low)
      const sortedIssues = [...data.issues].sort((a, b) => {
        const riskOrder = { high: 3, medium: 2, low: 1 };
        return riskOrder[b.risk] - riskOrder[a.risk];
      });
      
      sortedIssues.forEach(issue => {
        const element = document.createElement('div');
        element.className = `feature-item ${issue.risk}`;
        element.innerHTML = `
          <div class="feature-header">
            <span class="feature-name">${issue.description}</span>
            <span class="risk-badge ${issue.risk}">${issue.risk.toUpperCase()}</span>
          </div>
          <div class="feature-impact">Impact Factor: ${issue.weight}%</div>
        `;
        featuresList.appendChild(element);
      });
    } else {
      featuresList.innerHTML = '<div class="feature-item safe">No suspicious features detected</div>';
    }
  }
  
  // Export report
  function exportReport(format) {
    if (!window.scanResults) return;
    
    const data = window.scanResults;
    
    // Forward to the service worker to handle the report generation
    chrome.runtime.sendMessage({
      action: 'generateReport',
      data: data,
      format: format
    });
  }
  
  // Show error
  function showError(message) {
    errorMessage.textContent = message;
    errorMessage.style.display = 'block';
    
    setTimeout(function() {
      errorMessage.style.display = 'none';
    }, 5000);
  }
  
  // Initialize particles background
  initParticles();
  
  function initParticles() {
    const canvas = document.getElementById('particles-canvas');
    const ctx = canvas.getContext('2d');
    
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    
    const particles = [];
    const particleCount = 50;
    
    for (let i = 0; i < particleCount; i++) {
      particles.push({
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        radius: Math.random() * 2 + 1,
        color: `rgba(0, 119, 182, ${Math.random() * 0.5 + 0.1})`,
        speedX: (Math.random() - 0.5) * 0.5,
        speedY: (Math.random() - 0.5) * 0.5
      });
    }
    
    function drawParticles() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      
      for (let i = 0; i < particleCount; i++) {
        const p = particles[i];
        
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
        ctx.fillStyle = p.color;
        ctx.fill();
        
        // Update position
        p.x += p.speedX;
        p.y += p.speedY;
        
        // Bounce off edges
        if (p.x < 0 || p.x > canvas.width) p.speedX *= -1;
        if (p.y < 0 || p.y > canvas.height) p.speedY *= -1;
      }
      
      requestAnimationFrame(drawParticles);
    }
    
    drawParticles();
    
    // Resize handling
    window.addEventListener('resize', function() {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    });
  }
});