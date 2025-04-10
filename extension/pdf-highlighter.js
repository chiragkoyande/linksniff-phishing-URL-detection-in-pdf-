// linksniff PDF Highlighter
// Handles PDF rendering and highlighting of suspicious links

// PDF rendering scale
let pdfScale = 1.5;
// Current PDF document
let pdfDoc = null;
// Current page being rendered
let pageNum = 1;
// Flag to indicate if rendering is in progress
let renderInProgress = false;
// Queue for next page to render
let pendingPage = null;
// Store of detected suspicious URLs
let suspiciousUrls = [];
// Canvas contexts
let canvas = null;
let ctx = null;

// Initialize the PDF viewer and highlighter
async function initPdfViewer() {
  // Initialize PDF.js if not already initialized
  if (typeof pdfjsLib === 'undefined') {
    console.error('PDF.js library not loaded');
    showError('PDF.js library not loaded. Please make sure all dependencies are available.');
    return;
  }
  
  // Set up the canvas
  canvas = document.getElementById('pdf-canvas');
  if (!canvas) {
    console.error('PDF canvas element not found');
    return;
  }
  
  ctx = canvas.getContext('2d');
  
  // Add UI event listeners
  setupEventListeners();
  
  // Retrieve PDF analysis results from storage
  chrome.storage.local.get('pdfAnalysisResults', async (data) => {
    if (data.pdfAnalysisResults && data.pdfAnalysisResults.url_analysis) {
      suspiciousUrls = data.pdfAnalysisResults.url_analysis;
      
      // Also retrieve actual PDF data if available
      chrome.storage.local.get('pdfData', async (pdfDataObj) => {
        if (pdfDataObj.pdfData) {
          // Load PDF from storage
          await loadPdfFromData(pdfDataObj.pdfData);
        } else {
          // Show file upload UI if no PDF data in storage
          showPdfUploadInterface();
        }
      });
    } else {
      // No analysis results, show file upload interface
      showPdfUploadInterface();
    }
  });
}

// Set up event listeners for PDF viewer controls
function setupEventListeners() {
  const prevBtn = document.getElementById('prev-page');
  const nextBtn = document.getElementById('next-page');
  const zoomInBtn = document.getElementById('zoom-in');
  const zoomOutBtn = document.getElementById('zoom-out');
  const pageInput = document.getElementById('page-num');
  const fileInput = document.getElementById('pdf-file-input');
  
  if (prevBtn) prevBtn.addEventListener('click', onPrevPage);
  if (nextBtn) nextBtn.addEventListener('click', onNextPage);
  if (zoomInBtn) zoomInBtn.addEventListener('click', onZoomIn);
  if (zoomOutBtn) zoomOutBtn.addEventListener('click', onZoomOut);
  
  if (pageInput) {
    pageInput.addEventListener('change', () => {
      const newPage = parseInt(pageInput.value);
      if (!isNaN(newPage) && newPage > 0 && newPage <= pdfDoc.numPages) {
        pageNum = newPage;
        renderPage(pageNum);
      }
    });
  }
  
  if (fileInput) {
    fileInput.addEventListener('change', handleFileInputChange);
  }
  
  // Keyboard navigation
  document.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowLeft') {
      onPrevPage();
    } else if (e.key === 'ArrowRight') {
      onNextPage();
    }
  });
}

// Show PDF upload interface
function showPdfUploadInterface() {
  const uploadElement = document.getElementById('pdf-upload-container');
  if (uploadElement) {
    uploadElement.style.display = 'flex';
  }
  
  const viewerElement = document.getElementById('pdf-viewer-container');
  if (viewerElement) {
    viewerElement.style.display = 'none';
  }
}

// Handle file input change
async function handleFileInputChange(e) {
  const file = e.target.files[0];
  if (file && file.type === 'application/pdf') {
    try {
      const arrayBuffer = await file.arrayBuffer();
      
      // Store the PDF data
      chrome.storage.local.set({ pdfData: arrayBuffer });
      
      // Analyze the PDF
      analyzePdf(arrayBuffer);
      
      // Load the PDF
      await loadPdfFromData(arrayBuffer);
    } catch (error) {
      console.error('Error loading PDF:', error);
      showError('Error loading PDF: ' + error.message);
    }
  }
}

// Load PDF from ArrayBuffer data
async function loadPdfFromData(pdfData) {
  try {
    // Show loading indicator
    const loadingIndicator = document.getElementById('loading-indicator');
    if (loadingIndicator) loadingIndicator.style.display = 'block';
    
    // Show viewer container, hide upload container
    const uploadElement = document.getElementById('pdf-upload-container');
    if (uploadElement) uploadElement.style.display = 'none';
    
    const viewerElement = document.getElementById('pdf-viewer-container');
    if (viewerElement) viewerElement.style.display = 'block';
    
    // Load the PDF document
    const loadingTask = pdfjsLib.getDocument({ data: pdfData });
    
    pdfDoc = await loadingTask.promise;
    
    // Update page count
    const pageCount = document.getElementById('page-count');
    if (pageCount) pageCount.textContent = pdfDoc.numPages;
    
    // Render first page
    renderPage(1);
    
    // Hide loading indicator
    if (loadingIndicator) loadingIndicator.style.display = 'none';
  } catch (error) {
    console.error('Error loading PDF:', error);
    showError('Error loading PDF: ' + error.message);
  }
}

// Analyze PDF with backend API
async function analyzePdf(pdfData) {
  try {
    // Convert to base64
    const base64Data = arrayBufferToBase64(pdfData);
    
    // Send to server for analysis
    const response = await fetch('http://localhost:5000/analyze-pdf-data', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        pdfData: `data:application/pdf;base64,${base64Data}`
      })
    });
    
    if (!response.ok) {
      throw new Error(`Server responded with ${response.status}`);
    }
    
    const result = await response.json();
    
    // Store result
    chrome.storage.local.set({ pdfAnalysisResults: result });
    
    // Update suspicious URLs list
    if (result.url_analysis && result.url_analysis.length > 0) {
      suspiciousUrls = result.url_analysis;
      
      // Re-render current page to show highlights
      renderPage(pageNum);
    }
    
    return result;
  } catch (error) {
    console.error('Error analyzing PDF:', error);
    showError('Error analyzing PDF: ' + error.message);
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

// Render PDF page with highlights
async function renderPage(num) {
  if (!pdfDoc) return;
  
  if (renderInProgress) {
    pendingPage = num;
    return;
  }
  
  renderInProgress = true;
  
  try {
    // Update current page
    pageNum = num;
    
    // Update page input
    const pageNumInput = document.getElementById('page-num');
    if (pageNumInput) pageNumInput.value = pageNum;
    
    // Get the page
    const page = await pdfDoc.getPage(pageNum);
    
    // Get the viewport
    const viewport = page.getViewport({ scale: pdfScale });
    
    // Set canvas dimensions
    canvas.width = viewport.width;
    canvas.height = viewport.height;
    
    // Render the page
    const renderContext = {
      canvasContext: ctx,
      viewport: viewport
    };
    
    await page.render(renderContext).promise;
    
    // Highlight suspicious URLs
    await highlightSuspiciousUrls(page, viewport);
    
    // Update navigation buttons
    updateNavButtons();
    
    // Check if there's a pending page
    renderInProgress = false;
    if (pendingPage !== null && pendingPage !== pageNum) {
      const nextPage = pendingPage;
      pendingPage = null;
      renderPage(nextPage);
    }
  } catch (error) {
    console.error('Error rendering page:', error);
    renderInProgress = false;
  }
}

// Highlight suspicious URLs on the current page
async function highlightSuspiciousUrls(page, viewport) {
  if (!suspiciousUrls || suspiciousUrls.length === 0) return;
  
  // Filter URLs for current page
  const currentPageUrls = suspiciousUrls.filter(url => url.page === pageNum - 1);
  
  if (currentPageUrls.length === 0) return;
  
  try {
    // Get text content to find positions of URLs
    const textContent = await page.getTextContent();
    const items = textContent.items;
    
    for (const urlData of currentPageUrls) {
      const url = urlData.url;
      
      // Find occurrences of this URL in the text content
      for (let i = 0; i < items.length; i++) {
        const item = items[i];
        
        if (item.str.includes(url)) {
          // Calculate position
          const x = item.transform[4];
          const y = item.transform[5];
          const width = item.width;
          const height = item.height;
          
          // Determine highlight color based on risk
          let highlightColor;
          if (urlData.risk_percentage >= 70) {
            highlightColor = 'rgba(255, 77, 77, 0.3)'; // High risk - red
          } else if (urlData.risk_percentage >= 40) {
            highlightColor = 'rgba(255, 170, 0, 0.3)'; // Medium risk - orange
          } else {
            highlightColor = 'rgba(0, 204, 68, 0.3)'; // Low risk - green
          }
          
          // Draw highlight
          ctx.fillStyle = highlightColor;
          ctx.fillRect(x, viewport.height - y, width, height + 4);
          
          // Draw border
          ctx.strokeStyle = highlightColor.replace('0.3', '0.7');
          ctx.lineWidth = 1;
          ctx.strokeRect(x, viewport.height - y, width, height + 4);
          
          // Add risk indicator
          const riskBadgeSize = 16;
          ctx.fillStyle = highlightColor.replace('0.3', '0.7');
          ctx.beginPath();
          ctx.arc(x + width + 10, viewport.height - y - height/2, riskBadgeSize/2, 0, Math.PI * 2);
          ctx.fill();
          
          // Add risk percentage text
          ctx.fillStyle = 'white';
          ctx.font = '10px Arial';
          ctx.textAlign = 'center';
          ctx.textBaseline = 'middle';
          ctx.fillText(urlData.risk_percentage + '%', x + width + 10, viewport.height - y - height/2);
        }
      }
    }
  } catch (error) {
    console.error('Error highlighting URLs:', error);
  }
}

// Update navigation buttons
function updateNavButtons() {
  const prevBtn = document.getElementById('prev-page');
  const nextBtn = document.getElementById('next-page');
  
  if (prevBtn) prevBtn.disabled = pageNum <= 1;
  if (nextBtn) nextBtn.disabled = pageNum >= pdfDoc.numPages;
}

// Navigate to previous page
function onPrevPage() {
  if (pageNum <= 1) return;
  renderPage(pageNum - 1);
}

// Navigate to next page
function onNextPage() {
  if (!pdfDoc || pageNum >= pdfDoc.numPages) return;
  renderPage(pageNum + 1);
}

// Zoom in
function onZoomIn() {
  pdfScale += 0.25;
  renderPage(pageNum);
}

// Zoom out
function onZoomOut() {
  if (pdfScale <= 0.5) return;
  pdfScale -= 0.25;
  renderPage(pageNum);
}

// Show error message
function showError(message) {
  const errorElement = document.getElementById('error-message');
  if (errorElement) {
    errorElement.textContent = message;
    errorElement.style.display = 'block';
    
    // Hide after 5 seconds
    setTimeout(() => {
      errorElement.style.display = 'none';
    }, 5000);
  }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', initPdfViewer);
