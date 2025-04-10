document.addEventListener('DOMContentLoaded', function() {
  // DOM Elements
  const pdfFileInput = document.getElementById('pdfFile');
  const uploadSection = document.getElementById('uploadSection');
  const fileName = document.getElementById('fileName');
  const analyzeBtn = document.getElementById('analyzeBtn');
  const resultSection = document.getElementById('resultSection');
  const riskValue = document.getElementById('riskValue');
  const riskStatus = document.getElementById('riskStatus');
  const featuresGrid = document.getElementById('featuresGrid');
  const urlAnalysis = document.getElementById('urlAnalysis');
  const resetBtn = document.getElementById('resetBtn');
  const viewPdfBtn = document.getElementById('viewPdfBtn');
  const exportReportBtn = document.getElementById('exportReportBtn');
  const themeToggle = document.getElementById('themeToggle');
  const body = document.body;
  const circleProgress = document.querySelector('.circle-progress');
  const canvas = document.getElementById('particles-canvas');
  const scanProgress = document.getElementById('scanProgress');
  const progressBarFill = document.querySelector('.progress-bar-fill');

  // Server URL
  const serverUrl = 'http://localhost:5000';

  // Initialize particles animation
  initParticles();

  // Event Listeners
  uploadSection.addEventListener('click', () => {
    pdfFileInput.click();
  });

  pdfFileInput.addEventListener('change', () => {
    if (pdfFileInput.files[0]) {
      fileName.textContent = pdfFileInput.files[0].name;
    }
  });

  analyzeBtn.addEventListener('click', analyzePdf);
  resetBtn.addEventListener('click', resetAnalysis);
  viewPdfBtn.addEventListener('click', viewPdfWithHighlights);
  exportReportBtn.addEventListener('click', exportReport);
  themeToggle.addEventListener('click', toggleTheme);

  // Functions
  function initParticles() {
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    const particles = [];
    const isDarkMode = body.classList.contains('dark-mode');

    // Create particles
    for (let i = 0; i < 50; i++) {
      particles.push({
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        radius: Math.random() * 2 + 1,
        speed: Math.random() * 0.5 + 0.1,
        color: `rgba(${isDarkMode ? '0, 180, 216' : '0, 119, 182'}, ${Math.random() * 0.5 + 0.2})`
      });
    }

    function animate() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      particles.forEach(particle => {
        ctx.beginPath();
        ctx.arc(particle.x, particle.y, particle.radius, 0, Math.PI * 2);
        ctx.fillStyle = particle.color;
        ctx.fill();

        particle.y += particle.speed;

        if (particle.y > canvas.height) {
          particle.y = 0;
          particle.x = Math.random() * canvas.width;
        }
      });

      requestAnimationFrame(animate);
    }

    animate();

    window.addEventListener('resize', () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    });
  }

  function toggleTheme() {
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

    // Reinitialize particles with new theme colors
    initParticles();
  }

  async function analyzePdf() {
    if (!pdfFileInput.files[0]) {
      alert('Please select a PDF file first');
      return;
    }

    // Show progress
    scanProgress.style.display = 'block';
    resultSection.style.display = 'none';
    
    // Start progress animation
    let progress = 0;
    const progressInterval = setInterval(() => {
      progress += 2;
      if (progress >= 90) {
        progress = 90;
        clearInterval(progressInterval);
      }
      progressBarFill.style.width = `${progress}%`;
    }, 50);

    const formData = new FormData();
    formData.append('pdf', pdfFileInput.files[0]);

    try {
      const response = await fetch(`${serverUrl}/analyze`, {
        method: 'POST',
        body: formData
      });

      if (!response.ok) {
        throw new Error(`Server responded with ${response.status}: ${response.statusText}`);
      }

      const result = await response.json();
      
      // Complete progress animation
      clearInterval(progressInterval);
      progressBarFill.style.width = '100%';
      
      // Save analysis results
      chrome.storage.local.set({ pdfAnalysisResults: result });
      
      // Display results
      displayResults(result);
      
      // Hide progress after a small delay
      setTimeout(() => {
        scanProgress.style.display = 'none';
      }, 500);
    } catch (error) {
      console.error('Error:', error);
      clearInterval(progressInterval);
      scanProgress.style.display = 'none';
      alert('Error analyzing PDF. Please make sure the backend server is running.');
    }
  }

  function displayResults(result) {
    resultSection.style.display = 'block';

    // Update risk percentage
    const riskPercentage = result.risk_percentage;
    riskValue.textContent = `${riskPercentage}%`;
    riskValue.style.color = getRiskColor(riskPercentage);

    // Update circle progress
    const circumference = 2 * Math.PI * 54;
    const offset = circumference - (circumference * riskPercentage / 100);
    circleProgress.style.strokeDasharray = `${circumference} ${circumference}`;
    circleProgress.style.strokeDashoffset = offset;
    circleProgress.style.stroke = getRiskColor(riskPercentage);

    // Update risk status
    if (riskPercentage >= 70) {
      riskStatus.innerHTML = `
        <svg class="risk-status-icon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ff4444" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
          <line x1="12" y1="9" x2="12" y2="13"></line>
          <line x1="12" y1="17" x2="12.01" y2="17"></line>
        </svg>
        <span style="color: #ff4444;">High Risk Detected</span>
      `;
    } else if (riskPercentage >= 40) {
      riskStatus.innerHTML = `
        <svg class="risk-status-icon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ffaa00" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
        </svg>
        <span style="color: #ffaa00;">Medium Risk</span>
      `;
    } else {
      riskStatus.innerHTML = `
        <svg class="risk-status-icon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#00cc44" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
        </svg>
        <span style="color: #00cc44;">Low Risk</span>
      `;
    }

    // Clear previous results
    featuresGrid.innerHTML = '';
    urlAnalysis.innerHTML = '';

    // Display feature tags
    if (result.features && Object.keys(result.features).length > 0) {
      const features = [
        { name: 'IP Address', key: 'ip_address' },
        { name: 'URL Length', key: 'url_length' },
        { name: 'Tiny URL', key: 'tiny_url' },
        { name: '@ Symbol', key: 'at_symbol' },
        { name: 'Redirecting', key: 'redirecting' },
        { name: 'Prefix/Suffix', key: 'prefix_suffix' },
        { name: 'Sub Domains', key: 'sub_domains' },
        { name: 'HTTPS', key: 'https' },
        { name: 'Favicon', key: 'favicon' },
        { name: 'Port', key: 'port' },
        { name: 'HTTPS Domain', key: 'https_domain' },
        { name: 'Request URL', key: 'request_url' },
        { name: 'Anchor', key: 'anchor' },
        { name: 'Links', key: 'links' },
        { name: 'SFH', key: 'sfh' },
        { name: 'mailto', key: 'mailto' },
        { name: 'iFrames', key: 'iframes' },
        { name: 'Suspicious TLD', key: 'suspicious_tld' },
        { name: 'Special Chars', key: 'special_chars' },
        { name: 'Encoded Chars', key: 'encoded_chars' }
      ];

      // Display features grid
      features.forEach(feature => {
        const isWarning = result.features[feature.key];
        if (isWarning) {
          const featureElement = document.createElement('div');
          featureElement.className = `feature-tag warning`;
          featureElement.innerHTML = `
            ${feature.name}
            <svg class="feature-tag-icon" xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
              <line x1="12" y1="9" x2="12" y2="13"></line>
              <line x1="12" y1="17" x2="12.01" y2="17"></line>
            </svg>
          `;
          featuresGrid.appendChild(featureElement);
        }
      });
    } else {
      featuresGrid.innerHTML = '<div class="no-features">No suspicious features detected</div>';
    }

    // Display URL analysis
    if (result.url_analysis && result.url_analysis.length > 0) {
      // Sort by risk (highest first)
      result.url_analysis.sort((a, b) => b.risk_percentage - a.risk_percentage);
      
      result.url_analysis.forEach(analysis => {
        const urlElement = document.createElement('div');
        urlElement.className = 'url-analysis';
        const riskColor = getRiskColor(analysis.risk_percentage);

        urlElement.innerHTML = `
          <div class="url-header">
            <span class="url-text">${analysis.url}</span>
            <span class="url-risk" style="background-color: ${riskColor}20; color: ${riskColor};">
              Risk: ${analysis.risk_percentage}%
            </span>
          </div>
          <div class="url-details">
            <span class="url-page">Page: ${analysis.page + 1}</span>
          </div>
          <div class="progress-bar">
            <div class="progress-fill" style="width: ${analysis.risk_percentage}%; background-color: ${riskColor}"></div>
          </div>
        `;

        urlAnalysis.appendChild(urlElement);
      });
    } else {
      urlAnalysis.innerHTML = '<div class="no-urls">No URLs detected in this PDF</div>';
    }
  }

  function resetAnalysis() {
    resultSection.style.display = 'none';
    pdfFileInput.value = '';
    fileName.textContent = '';
    chrome.storage.local.remove('pdfAnalysisResults');
  }

  function viewPdfWithHighlights() {
    chrome.storage.local.get('pdfAnalysisResults', (data) => {
      if (data.pdfAnalysisResults) {
        chrome.tabs.create({ url: chrome.runtime.getURL('pdf-viewer.html') });
      } else {
        alert('No analysis results available. Please analyze a PDF first.');
      }
    });
  }

  function exportReport() {
    chrome.storage.local.get('pdfAnalysisResults', (data) => {
      if (data.pdfAnalysisResults) {
        const reportFormat = window.confirm('Do you want to export as PDF? Click Cancel for CSV format.') ? 'pdf' : 'csv';
        
        // Send message to background script to generate report
        chrome.runtime.sendMessage({
          action: 'generateReport',
          data: data.pdfAnalysisResults,
          format: reportFormat,
          filename: fileName.textContent || 'linksniff_report'
        });
      } else {
        alert('No analysis results available. Please analyze a PDF first.');
      }
    });
  }

  function getRiskColor(percentage) {
    if (percentage >= 75) return '#ff4444';
    if (percentage >= 50) return '#ffaa00';
    if (percentage >= 25) return '#ffdd00';
    return '#00cc44';
  }
});
