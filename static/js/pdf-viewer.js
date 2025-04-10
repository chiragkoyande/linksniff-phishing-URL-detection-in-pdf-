// PDF Viewer with Highlighting Functionality

let pdfDoc = null;
let pageNum = 1;
let pageRendering = false;
let pageNumPending = null;
let scale = 1.5;
let canvas = null;
let ctx = null;
let pdfWorker = null;
let highlightedLinks = [];

// Initialize the PDF.js viewer
function initPdfViewer() {
  canvas = document.getElementById('pdf-canvas');
  ctx = canvas.getContext('2d');
  
  // Add event listeners for navigation
  document.getElementById('prev-page').addEventListener('click', onPrevPage);
  document.getElementById('next-page').addEventListener('click', onNextPage);
  document.getElementById('zoom-in').addEventListener('click', onZoomIn);
  document.getElementById('zoom-out').addEventListener('click', onZoomOut);
  document.getElementById('download-report').addEventListener('click', downloadReport);
  
  // Listen for messages from extension
  window.addEventListener('message', handleExtensionMessage);
}

// Handle messages from extension
function handleExtensionMessage(event) {
  const data = event.data;
  
  if (data.type === 'loadPDF') {
    loadPDF(data.data);
  } else if (data.type === 'highlightURLs') {
    highlightedLinks = data.urls || [];
    queueRenderPage(pageNum);
  }
}

// Load PDF from array buffer
function loadPDF(pdfData) {
  const pdfDataArray = new Uint8Array(pdfData);
  const loadingTask = pdfjsLib.getDocument({data: pdfDataArray});
  
  document.getElementById('loading-indicator').style.display = 'block';
  
  loadingTask.promise.then(pdf => {
    pdfDoc = pdf;
    document.getElementById('page-count').textContent = pdfDoc.numPages;
    document.getElementById('loading-indicator').style.display = 'none';
    
    // Initial/first page rendering
    renderPage(pageNum);
    
    // Update UI
    document.getElementById('pdf-controls').style.display = 'flex';
  }).catch(error => {
    console.error('Error loading PDF:', error);
    document.getElementById('loading-indicator').style.display = 'none';
    document.getElementById('error-message').textContent = 'Error loading PDF. Please try again.';
    document.getElementById('error-message').style.display = 'block';
  });
}

// Render the specified page
function renderPage(num) {
  pageRendering = true;
  
  // Update page counters
  document.getElementById('page-num').textContent = num;
  
  // Get page
  pdfDoc.getPage(num).then(page => {
    const viewport = page.getViewport({scale: scale});
    canvas.height = viewport.height;
    canvas.width = viewport.width;
    
    // Render PDF page into canvas context
    const renderContext = {
      canvasContext: ctx,
      viewport: viewport
    };
    
    const renderTask = page.render(renderContext);
    
    // Wait for rendering to finish
    renderTask.promise.then(() => {
      pageRendering = false;
      
      // Highlight suspicious URLs if any
      highlightURLsOnPage(page, num - 1, viewport);
      
      if (pageNumPending !== null) {
        // New page rendering is pending
        renderPage(pageNumPending);
        pageNumPending = null;
      }
    }).catch(error => {
      console.error('Error rendering page:', error);
      pageRendering = false;
    });
  }).catch(error => {
    console.error('Error getting page:', error);
    pageRendering = false;
  });
}

// Highlight suspicious URLs on the current page
async function highlightURLsOnPage(page, pageIndex, viewport) {
  // Filter links for current page
  const pageLinks = highlightedLinks.filter(link => link.page === pageIndex);
  
  if (pageLinks.length === 0) return;
  
  try {
    // Get text content to find positions of URLs
    const textContent = await page.getTextContent();
    
    for (const link of pageLinks) {
      const url = link.url;
      const riskLevel = link.risk_percentage || 0;
      
      // Find text item containing the URL
      for (const item of textContent.items) {
        if (item.str.includes(url)) {
          // Calculate position based on viewport
          const x = item.transform[4];
          const y = item.transform[5];
          const width = item.width;
          const height = item.height;
          
          // Draw highlight based on risk level
          ctx.save();
          
          // Set highlight color based on risk level
          if (riskLevel >= 70) {
            ctx.fillStyle = 'rgba(255, 77, 77, 0.4)'; // High risk - red
          } else if (riskLevel >= 40) {
            ctx.fillStyle = 'rgba(255, 193, 7, 0.4)'; // Medium risk - yellow
          } else {
            ctx.fillStyle = 'rgba(0, 204, 102, 0.4)'; // Low risk - green
          }
          
          // Draw rectangle and border
          ctx.fillRect(x, viewport.height - y - height, width, height + 4);
          
          // Add risk indicator dot
          ctx.beginPath();
          ctx.arc(x + width + 10, viewport.height - y - height/2, 5, 0, 2 * Math.PI);
          
          if (riskLevel >= 70) {
            ctx.fillStyle = 'rgb(255, 77, 77)';
          } else if (riskLevel >= 40) {
            ctx.fillStyle = 'rgb(255, 193, 7)';
          } else {
            ctx.fillStyle = 'rgb(0, 204, 102)';
          }
          
          ctx.fill();
          ctx.restore();
        }
      }
    }
  } catch (error) {
    console.error('Error highlighting URLs:', error);
  }
}

// Queue a page for rendering
function queueRenderPage(num) {
  if (pageRendering) {
    pageNumPending = num;
  } else {
    renderPage(num);
  }
}

// Display previous page
function onPrevPage() {
  if (pageNum <= 1) return;
  pageNum--;
  queueRenderPage(pageNum);
}

// Display next page
function onNextPage() {
  if (pageNum >= pdfDoc.numPages) return;
  pageNum++;
  queueRenderPage(pageNum);
}

// Zoom in
function onZoomIn() {
  scale += 0.25;
  queueRenderPage(pageNum);
}

// Zoom out
function onZoomOut() {
  if (scale <= 0.5) return;
  scale -= 0.25;
  queueRenderPage(pageNum);
}

// Generate and download PDF report
function downloadReport() {
  const reportData = {
    pdfTitle: 'PDF Analysis Report',
    urls: highlightedLinks,
    timestamp: new Date().toISOString()
  };
  
  // Send message to parent window to generate report
  window.parent.postMessage({
    type: 'generateReport',
    data: reportData
  }, '*');
}

// Initialize the viewer when DOM content is loaded
document.addEventListener('DOMContentLoaded', initPdfViewer);
