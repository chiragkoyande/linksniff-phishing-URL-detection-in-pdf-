// linksniff Content Script
// Handles scanning page links, highlighting suspicious URLs, and PDF detection

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  // Check if current page is a PDF
  if (isPdfPage()) {
    handlePdfPage();
  }
  
  // Listen for messages from background script or popup
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    console.log('Content script received message:', message);
    
    if (message.action === 'scanPageLinks') {
      scanPageLinks();
      return true;
    }
    
    if (message.action === 'scanUrlResult') {
      handleUrlScanResult(message.url, message.result);
      return true;
    }
    
    if (message.action === 'showNotification') {
      showPageNotification(message.type, message.message);
      return true;
    }
    
    if (message.action === 'highlightLinks') {
      highlightLinks(message.data);
      return true;
    }
  });
});

// Check if current page is a PDF
function isPdfPage() {
  const contentType = document.contentType;
  const url = window.location.href;
  
  return (
    contentType === 'application/pdf' ||
    url.toLowerCase().endsWith('.pdf') ||
    url.toLowerCase().includes('.pdf?') ||
    url.toLowerCase().includes('pdf=')
  );
}

// Handle PDF pages
function handlePdfPage() {
  console.log('PDF detected. Preparing analysis...');
  
  // Check settings to see if we should auto-scan PDFs
  chrome.storage.local.get('settings', (data) => {
    if (data.settings && data.settings.autoScanPdfs) {
      // Get PDF data
      getPdfData()
        .then(pdfData => {
          if (pdfData) {
            // Send message to analyze PDF
            chrome.runtime.sendMessage({
              action: 'analyzePdf',
              pdfData: pdfData
            });
          }
        })
        .catch(error => {
          console.error('Error getting PDF data:', error);
        });
    } else {
      // Add scan button to the page
      addPdfScanButton();
    }
  });
}

// Get PDF data from the page
function getPdfData() {
  return new Promise((resolve, reject) => {
    try {
      // Try to get PDF data from embedded object or iframe
      const pdfObjects = document.querySelectorAll('object[type="application/pdf"], embed[type="application/pdf"]');
      
      if (pdfObjects.length > 0) {
        const pdfUrl = pdfObjects[0].data || pdfObjects[0].src;
        
        if (pdfUrl) {
          fetch(pdfUrl)
            .then(response => response.arrayBuffer())
            .then(buffer => resolve(buffer))
            .catch(error => reject(error));
        } else {
          reject(new Error('PDF object found but no data URL available'));
        }
      } else {
        // If we can't find embedded PDF, try to get it from the current page
        fetch(window.location.href)
          .then(response => response.arrayBuffer())
          .then(buffer => resolve(buffer))
          .catch(error => reject(error));
      }
    } catch (error) {
      reject(error);
    }
  });
}

// Add a button to scan PDF
function addPdfScanButton() {
  const button = document.createElement('div');
  button.className = 'linksniff -scan-button';
  button.innerHTML = `
    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
    </svg>
    Scan for Phishing Links
  `;
  
  button.addEventListener('click', () => {
    button.classList.add('scanning');
    button.textContent = 'Scanning...';
    
    getPdfData()
      .then(pdfData => {
        if (pdfData) {
          chrome.runtime.sendMessage({
            action: 'analyzePdf',
            pdfData: pdfData
          });
        }
      })
      .catch(error => {
        console.error('Error getting PDF data:', error);
        button.textContent = 'Scan Failed';
        setTimeout(() => {
          button.classList.remove('scanning');
          button.innerHTML = `
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
            </svg>
            Scan for Phishing Links
          `;
        }, 3000);
      });
  });
  
  // Add button to page
  document.body.appendChild(button);
  
  // Add styles
  const style = document.createElement('style');
  style.textContent = `
    .linksniff -scan-button {
      position: fixed;
      bottom: 20px;
      right: 20px;
      padding: 10px 15px;
      background: #00b4d8;
      color: white;
      border-radius: 5px;
      display: flex;
      align-items: center;
      gap: 8px;
      cursor: pointer;
      box-shadow: 0 2px 10px rgba(0, 0, 0, 0.2);
      z-index: 9999;
      font-family: Arial, sans-serif;
      font-size: 14px;
      transition: all 0.3s ease;
    }
    
    .linksniff -scan-button:hover {
      background: #0077b6;
    }
    
    .linksniff -scan-button.scanning {
      background: #666;
    }
  `;
  
  document.head.appendChild(style);
}

// Scan all links on the current page
function scanPageLinks() {
  const links = document.querySelectorAll('a[href]');
  
  if (links.length === 0) {
    showPageNotification('info', 'No links found on this page');
    return;
  }
  
  const linkUrls = Array.from(links).map(link => link.href);
  
  // Show scanning notification
  showPageNotification('info', `Scanning ${linkUrls.length} links for phishing threats...`);
  
  // Batch process links to avoid overloading the server
  const batchSize = 5;
  let processedCount = 0;
  let suspiciousLinks = [];
  
  function processBatch(startIndex) {
    const endIndex = Math.min(startIndex + batchSize, linkUrls.length);
    const batch = linkUrls.slice(startIndex, endIndex);
    
    Promise.all(batch.map(url => scanSingleUrl(url)))
      .then(results => {
        results.forEach((result, index) => {
          if (result && result.risk_percentage >= 40) {
            suspiciousLinks.push({
              url: batch[index],
              risk: result.risk_percentage
            });
          }
        });
        
        processedCount += batch.length;
        
        // Update notification
        showPageNotification('info', `Scanning progress: ${processedCount}/${linkUrls.length} links`);
        
        // Process next batch or finish
        if (endIndex < linkUrls.length) {
          setTimeout(() => processBatch(endIndex), 500);
        } else {
          // Finished scanning all links
          if (suspiciousLinks.length > 0) {
            showPageNotification('warning', `Found ${suspiciousLinks.length} suspicious links on this page`);
            highlightLinks(suspiciousLinks);
          } else {
            showPageNotification('success', 'No suspicious links detected on this page');
          }
        }
      })
      .catch(error => {
        console.error('Error processing batch:', error);
        showPageNotification('error', 'Error scanning links: ' + error.message);
      });
  }
  
  // Start processing batches
  processBatch(0);
}

// Scan a single URL
function scanSingleUrl(url) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({
      action: 'scanUrl',
      url: url
    }, response => {
      if (chrome.runtime.lastError) {
        reject(chrome.runtime.lastError);
      } else {
        resolve(response);
      }
    });
  });
}

// Handle URL scan result
function handleUrlScanResult(url, result) {
  // Highlight the link if it's suspicious
  if (result.risk_percentage >= 40) {
    highlightLinks([{ url: url, risk: result.risk_percentage }]);
  }
}

// Highlight links on the page
function highlightLinks(links) {
  if (!links || links.length === 0) return;
  
  // Get settings for highlight colors
  chrome.storage.local.get('settings', (data) => {
    const settings = data.settings || {};
    const colors = settings.highlightColor || {
      high: '#ff4444',
      medium: '#ffaa00',
      low: '#00cc44'
    };
    
    // Find all matching links
    const allLinks = document.querySelectorAll('a[href]');
    
    links.forEach(link => {
      const matchingLinks = Array.from(allLinks).filter(a => a.href === link.url);
      
      matchingLinks.forEach(element => {
        // Determine color based on risk
        let color;
        if (link.risk >= 70) {
          color = colors.high;
        } else if (link.risk >= 40) {
          color = colors.medium;
        } else {
          color = colors.low;
        }
        
        // Add highlight
        element.style.backgroundColor = `${color}33`; // 20% opacity
        element.style.border = `1px solid ${color}`;
        element.style.padding = '2px 4px';
        element.style.borderRadius = '3px';
        element.style.position = 'relative';
        
        // Add risk indicator
        const indicator = document.createElement('span');
        indicator.style.backgroundColor = color;
        indicator.style.color = 'white';
        indicator.style.padding = '2px 4px';
        indicator.style.borderRadius = '3px';
        indicator.style.fontSize = '10px';
        indicator.style.position = 'absolute';
        indicator.style.top = '-10px';
        indicator.style.right = '-10px';
        indicator.style.zIndex = '1000';
        indicator.textContent = `${link.risk}%`;
        
        element.appendChild(indicator);
        
        // Add tooltip with details
        element.setAttribute('title', `Phishing Risk: ${link.risk}% - Scanned by linksniff `);
        
        // Add click warning for high-risk links
        if (link.risk >= 70) {
          element.addEventListener('click', function(e) {
            if (!confirm(`WARNING: This link has a ${link.risk}% risk of being a phishing attempt. Are you sure you want to proceed?`)) {
              e.preventDefault();
            }
          });
        }
      });
    });
  });
}

// Show notification on the page
function showPageNotification(type, message) {
  // Remove any existing notification
  const existingNotification = document.querySelector('.linksniff -notification');
  if (existingNotification) {
    existingNotification.remove();
  }
  
  // Create notification element
  const notification = document.createElement('div');
  notification.className = `linksniff -notification linksniff -${type}`;
  
  // Set icon based on type
  let icon;
  switch (type) {
    case 'success':
      icon = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>';
      break;
    case 'warning':
      icon = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>';
      break;
    case 'error':
      icon = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>';
      break;
    default:
      icon = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>';
  }
  
  notification.innerHTML = `
    <div class="linksniff -notification-icon">${icon}</div>
    <div class="linksniff -notification-message">${message}</div>
    <div class="linksniff -notification-close">×</div>
  `;
  
  // Add styles
  const style = document.createElement('style');
  style.textContent = `
    .linksniff -notification {
      position: fixed;
      top: 20px;
      right: 20px;
      padding: 12px 15px;
      background: #333;
      color: white;
      border-radius: 5px;
      display: flex;
      align-items: center;
      gap: 10px;
      box-shadow: 0 2px 10px rgba(0, 0, 0, 0.2);
      z-index: 9999;
      font-family: Arial, sans-serif;
      font-size: 14px;
      max-width: 350px;
      animation: linksniff -slide-in 0.3s ease-out;
    }
    
    @keyframes linksniff -slide-in {
      from { transform: translateX(100%); opacity: 0; }
      to { transform: translateX(0); opacity: 1; }
    }
    
    .linksniff-success {
      background: #00cc44;
    }
    
    .linksniff-warning {
      background: #ffaa00;
    }
    
    .linksniff-error {
      background: #ff4444;
    }
    
    .linksniff-info {
      background: #00b4d8;
    }
    
    .linksniff-notification-icon {
      display: flex;
      align-items: center;
    }
    
    .linksniff-notification-message {
      flex: 1;
    }
    
    .linksniff-notification-close {
      cursor: pointer;
      font-size: 18px;
      margin-left: 10px;
    }
  `;
  
  document.head.appendChild(style);
  
  // Add to page
  document.body.appendChild(notification);
  
  // Add close functionality
  const closeButton = notification.querySelector('.linksniff-notification-close');
  closeButton.addEventListener('click', () => {
    notification.remove();
  });
  
  // Auto-hide after 5 seconds
  setTimeout(() => {
    if (notification.parentNode) {
      notification.style.animation = 'linksniff-slide-out 0.3s ease-in forwards';
      setTimeout(() => {
        if (notification.parentNode) {
          notification.remove();
        }
      }, 300);
    }
  }, 5000);
}
