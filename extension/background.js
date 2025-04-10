// linksniff  Background Script
// Handles context menu integration, report generation, and communication with API

// Server URL
const SERVER_URL = 'http://localhost:5000';

// Initialize extension
chrome.runtime.onInstalled.addListener(() => {
  console.log('linksniff extension installed');
  
  // Create context menu items
  chrome.contextMenus.create({
    id: 'linksniff-scan-url',
    title: 'Scan URL for phishing',
    contexts: ['link']
  });
  
  chrome.contextMenus.create({
    id: 'linksniff -scan-page',
    title: 'Scan this page for phishing links',
    contexts: ['page']
  });
  
  // Initialize storage with default settings
  chrome.storage.local.get('settings', (data) => {
    if (!data.settings) {
      chrome.storage.local.set({
        settings: {
          theme: 'dark',
          highlightColor: {
            high: '#ff4444',
            medium: '#ffaa00',
            low: '#00cc44'
          },
          autoScanPdfs: true,
          notificationsEnabled: true
        }
      });
    }
  });
});

// Handle context menu clicks
chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === 'linksniff -scan-url' && info.linkUrl) {
    // Scan individual URL
    scanUrl(info.linkUrl, tab.id);
  } else if (info.menuItemId === 'linksniff-scan-page') {
    // Scan all links on the current page
    chrome.tabs.sendMessage(tab.id, { action: 'scanPageLinks' });
  }
});

// Listen for messages from popup or content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('Background script received message:', message);
  
  if (message.action === 'scanUrl') {
    scanUrl(message.url, sender.tab ? sender.tab.id : null);
    return true;
  }
  
  if (message.action === 'generateReport') {
    generateReport(message.data, message.format, message.filename);
    return true;
  }
  
  if (message.action === 'analyzePdf') {
    analyzePdf(message.pdfData, sender.tab ? sender.tab.id : null);
    return true;
  }
  
  if (message.action === 'openPdfViewer') {
    chrome.tabs.create({ url: chrome.runtime.getURL('pdf-viewer.html') });
    return true;
  }
});

// Scan URL for phishing
async function scanUrl(url, tabId) {
  try {
    // Show scanning notification
    if (tabId) {
      chrome.tabs.sendMessage(tabId, { 
        action: 'showNotification', 
        type: 'info',
        message: 'Scanning URL for phishing threats...'
      });
    }
    
    const response = await fetch(`${SERVER_URL}/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ url: url })
    });
    
    if (!response.ok) {
      throw new Error(`Server responded with ${response.status}: ${response.statusText}`);
    }
    
    const result = await response.json();
    
    // Store result in local storage
    const storedResults = await chrome.storage.local.get('scanHistory');
    const history = storedResults.scanHistory || [];
    
    // Add new scan with timestamp
    history.push({
      url: url,
      timestamp: new Date().toISOString(),
      result: result
    });
    
    // Keep only the last 100 entries
    if (history.length > 100) {
      history.shift();
    }
    
    await chrome.storage.local.set({ scanHistory: history });
    
    // Send result to content script
    if (tabId) {
      chrome.tabs.sendMessage(tabId, { 
        action: 'scanUrlResult', 
        url: url,
        result: result
      });
    }
    
    // Show risk notification
    if (result.risk_percentage >= 70) {
      showNotification('High Phishing Risk', `The URL "${url}" has a ${result.risk_percentage}% risk of being a phishing attempt.`);
    } else if (result.risk_percentage >= 40) {
      showNotification('Medium Phishing Risk', `The URL "${url}" has a ${result.risk_percentage}% risk of being suspicious.`);
    }
    
    return result;
  } catch (error) {
    console.error('Error scanning URL:', error);
    
    // Show error notification
    if (tabId) {
      chrome.tabs.sendMessage(tabId, { 
        action: 'showNotification', 
        type: 'error',
        message: 'Error scanning URL: ' + error.message
      });
    }
    
    return { error: error.message };
  }
}

// Analyze PDF data
async function analyzePdf(pdfData, tabId) {
  try {
    // Convert binary data to base64
    const base64Data = arrayBufferToBase64(pdfData);
    
    // Send to server for analysis
    const response = await fetch(`${SERVER_URL}/analyze-pdf-data`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        pdfData: `data:application/pdf;base64,${base64Data}`
      })
    });
    
    if (!response.ok) {
      throw new Error(`Server responded with ${response.status}: ${response.statusText}`);
    }
    
    const result = await response.json();
    
    // Store result
    chrome.storage.local.set({ pdfAnalysisResults: result });
    
    // Send result to content script
    if (tabId) {
      chrome.tabs.sendMessage(tabId, { 
        action: 'pdfAnalysisResult', 
        result: result
      });
    }
    
    // Show notification if high risk
    if (result.risk_percentage >= 70) {
      showNotification('High Risk PDF', `The PDF contains links with a ${result.risk_percentage}% risk of being phishing.`);
    }
    
    return result;
  } catch (error) {
    console.error('Error analyzing PDF:', error);
    return { error: error.message };
  }
}

// Generate report (PDF or CSV)
function generateReport(data, format, filename) {
  if (format === 'pdf') {
    // For PDF, we'll open a new tab with the report
    chrome.storage.local.set({ reportData: data, reportFormat: 'pdf' }, () => {
      chrome.tabs.create({ url: chrome.runtime.getURL('report.html') });
    });
  } else {
    // For CSV, we'll generate it directly
    generateCsvReport(data, filename);
  }
}

// Generate CSV report
function generateCsvReport(data, filename) {
  // Prepare CSV data
  const csvData = [];
  
  // Add header row
  csvData.push(['URL', 'Risk Percentage', 'Page Number', 'Features']);
  
  // Add data rows
  if (data.url_analysis && data.url_analysis.length > 0) {
    data.url_analysis.forEach(url => {
      const features = url.features ? 
        Object.entries(url.features)
          .filter(([_, value]) => value)
          .map(([key, _]) => key)
          .join(', ') : 
        '';
      
      csvData.push([
        url.url,
        url.risk_percentage,
        url.page + 1,
        features
      ]);
    });
  }
  
  // Convert to CSV string
  let csvContent = '';
  csvData.forEach(row => {
    const formattedRow = row.map(cell => {
      // Wrap with quotes if it contains commas
      if (typeof cell === 'string' && cell.includes(',')) {
        return `"${cell.replace(/"/g, '""')}"`;
      }
      return cell;
    });
    csvContent += formattedRow.join(',') + '\n';
  });
  
  // Create download
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  
  chrome.downloads.download({
    url: url,
    filename: `${filename || 'linksniff_report'}.csv`,
    saveAs: true
  });
}

// Show Chrome notification
function showNotification(title, message) {
  chrome.storage.local.get('settings', (data) => {
    if (data.settings && data.settings.notificationsEnabled !== false) {
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon128.png',
        title: title,
        message: message
      });
    }
  });
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
