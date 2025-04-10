// linksniff  Context Menu Handler
// This script extends the functionality of the background.js by providing additional context menu functions

// Event listener for messages specifically for context menu operations
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'contextMenuScanUrl') {
    performContextMenuScan(message.url, sender.tab.id);
    return true;
  }
});

// Perform URL scan from context menu
async function performContextMenuScan(url, tabId) {
  try {
    // Show notification in the content script
    chrome.tabs.sendMessage(tabId, {
      action: 'showNotification',
      type: 'info',
      message: `Scanning URL: ${url}`
    });
    
    // Call the scan API
    const response = await fetch('http://localhost:5000/analyze', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ url: url })
    });
    
    if (!response.ok) {
      throw new Error(`Server responded with ${response.status}`);
    }
    
    const result = await response.json();
    
    // Save result to scan history
    saveToScanHistory(url, result);
    
    // Determine risk level
    let riskLevel = 'Low Risk';
    let notificationType = 'success';
    
    if (result.risk_percentage >= 70) {
      riskLevel = 'High Risk';
      notificationType = 'error';
    } else if (result.risk_percentage >= 40) {
      riskLevel = 'Medium Risk';
      notificationType = 'warning';
    }
    
    // Show result notification
    chrome.tabs.sendMessage(tabId, {
      action: 'showNotification',
      type: notificationType,
      message: `Scan result: ${riskLevel} (${result.risk_percentage}%)`
    });
    
    // Create detailed report in popup
    chrome.runtime.sendMessage({
      action: 'showScanResult',
      url: url,
      result: result
    });
    
    return result;
  } catch (error) {
    console.error('Error scanning URL:', error);
    
    // Show error notification
    chrome.tabs.sendMessage(tabId, {
      action: 'showNotification',
      type: 'error',
      message: `Error scanning URL: ${error.message}`
    });
    
    return { error: error.message };
  }
}

// Save scan results to history
function saveToScanHistory(url, result) {
  chrome.storage.local.get('scanHistory', (data) => {
    const history = data.scanHistory || [];
    
    history.push({
      url: url,
      timestamp: new Date().toISOString(),
      result: result
    });
    
    // Keep only the last 100 entries
    if (history.length > 100) {
      history.shift();
    }
    
    chrome.storage.local.set({ scanHistory: history });
  });
}

// Create a context menu item for scanning PDFs
chrome.contextMenus.create({
  id: 'linksniff-scan-pdf',
  title: 'Scan PDF for phishing links',
  contexts: ['link'],
  targetUrlPatterns: ['*://*/*.pdf', '*://*/*.pdf?*']
});

// Handle PDF context menu click
chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === 'linksniff-scan-pdf') {
    downloadAndScanPdf(info.linkUrl, tab.id);
  }
});

// Download and scan PDF
async function downloadAndScanPdf(pdfUrl, tabId) {
  try {
    // Show notification
    chrome.tabs.sendMessage(tabId, {
      action: 'showNotification',
      type: 'info',
      message: 'Downloading and scanning PDF...'
    });
    
    // Download the PDF
    const response = await fetch(pdfUrl);
    if (!response.ok) {
      throw new Error(`Failed to download PDF: ${response.status}`);
    }
    
    const pdfData = await response.arrayBuffer();
    
    // Convert to base64
    const base64Data = arrayBufferToBase64(pdfData);
    
    // Send to server for analysis
    const analysisResponse = await fetch('http://localhost:5000/analyze-pdf-data', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        pdfData: `data:application/pdf;base64,${base64Data}`
      })
    });
    
    if (!analysisResponse.ok) {
      throw new Error(`Analysis failed: ${analysisResponse.status}`);
    }
    
    const result = await analysisResponse.json();
    
    // Store result
    chrome.storage.local.set({ pdfAnalysisResults: result });
    
    // Determine risk level
    let message = 'No suspicious URLs found in PDF';
    let type = 'success';
    
    if (result.risk_percentage >= 70) {
      message = `High risk detected (${result.risk_percentage}%). Found ${result.url_analysis.length} suspicious URLs.`;
      type = 'error';
    } else if (result.risk_percentage >= 40) {
      message = `Medium risk detected (${result.risk_percentage}%). Found ${result.url_analysis.length} suspicious URLs.`;
      type = 'warning';
    } else if (result.url_analysis && result.url_analysis.length > 0) {
      message = `Low risk (${result.risk_percentage}%). Found ${result.url_analysis.length} URLs to analyze.`;
      type = 'info';
    }
    
    // Show result notification
    chrome.tabs.sendMessage(tabId, {
      action: 'showNotification',
      type: type,
      message: message
    });
    
    // Ask user if they want to view the PDF with highlights
    if (result.url_analysis && result.url_analysis.length > 0) {
      chrome.tabs.sendMessage(tabId, {
        action: 'showConfirmDialog',
        title: 'PDF Analysis Complete',
        message: 'Would you like to view the PDF with highlighted suspicious links?',
        callback: 'viewPdfWithHighlights'
      });
    }
    
    return result;
  } catch (error) {
    console.error('Error scanning PDF:', error);
    
    chrome.tabs.sendMessage(tabId, {
      action: 'showNotification',
      type: 'error',
      message: `Error scanning PDF: ${error.message}`
    });
    
    return { error: error.message };
  }
}

// Convert ArrayBuffer to base64
function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  
  return btoa(binary);
}
