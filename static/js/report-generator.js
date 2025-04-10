// Report Generator for ThreatVision  Extension
// Generates PDF and CSV reports of phishing analysis

// Initialize report generator
function initReportGenerator() {
  // Listen for messages to generate reports
  window.addEventListener('message', handleReportRequest);
}

// Handle report generation requests
function handleReportRequest(event) {
  const data = event.data;
  
  if (data.type === 'generateReport') {
    if (data.format === 'pdf' || !data.format) {
      generatePdfReport(data.data);
    } else if (data.format === 'csv') {
      generateCsvReport(data.data);
    }
  }
}

// Generate PDF report
function generatePdfReport(reportData) {
  const { pdfTitle, urls, timestamp } = reportData;
  
  // Create new PDF document
  const doc = new jsPDF();
  
  // Add title and header
  doc.setFontSize(22);
  doc.setTextColor(0, 119, 182);
  doc.text('linksniff Phishing Analysis Report', 20, 20);
  
  // Add timestamp
  doc.setFontSize(12);
  doc.setTextColor(100, 100, 100);
  doc.text(`Generated: ${new Date(timestamp).toLocaleString()}`, 20, 30);
  
  // Add document title if available
  if (pdfTitle) {
    doc.setFontSize(16);
    doc.setTextColor(0, 0, 0);
    doc.text(`Analyzed Document: ${pdfTitle}`, 20, 45);
  }
  
  // Add summary
  doc.setFontSize(16);
  doc.setTextColor(0, 0, 0);
  doc.text('Summary', 20, 60);
  
  const totalUrls = urls.length;
  const highRiskUrls = urls.filter(url => url.risk_percentage >= 70).length;
  const mediumRiskUrls = urls.filter(url => url.risk_percentage >= 40 && url.risk_percentage < 70).length;
  const lowRiskUrls = urls.filter(url => url.risk_percentage < 40).length;
  
  doc.setFontSize(12);
  doc.text(`Total URLs found: ${totalUrls}`, 25, 70);
  doc.text(`High Risk URLs: ${highRiskUrls}`, 25, 78);
  doc.text(`Medium Risk URLs: ${mediumRiskUrls}`, 25, 86);
  doc.text(`Low Risk URLs: ${lowRiskUrls}`, 25, 94);
  
  // Add risk score visualization if URLs exist
  if (totalUrls > 0) {
    // Calculate average risk
    const totalRisk = urls.reduce((sum, url) => sum + url.risk_percentage, 0);
    const averageRisk = Math.round(totalRisk / totalUrls);
    
    // Draw risk gauge
    doc.setFontSize(14);
    doc.text('Overall Risk Assessment', 20, 110);
    
    // Draw gauge background
    doc.setDrawColor(220, 220, 220);
    doc.setFillColor(240, 240, 240);
    doc.roundedRect(25, 120, 160, 25, 3, 3, 'FD');
    
    // Draw risk level
    let riskColor;
    if (averageRisk >= 70) {
      riskColor = [255, 77, 77];
    } else if (averageRisk >= 40) {
      riskColor = [255, 170, 0];
    } else {
      riskColor = [0, 204, 68];
    }
    
    doc.setFillColor(riskColor[0], riskColor[1], riskColor[2]);
    doc.roundedRect(25, 120, Math.min(160, (averageRisk / 100) * 160), 25, 3, 3, 'F');
    
    // Add risk percentage text
    doc.setFontSize(14);
    doc.setTextColor(255, 255, 255);
    if (averageRisk >= 40) {
      doc.text(`${averageRisk}%`, 25 + ((averageRisk / 100) * 160) / 2 - 7, 135);
    }
    
    doc.setTextColor(0, 0, 0);
    doc.text('0%', 20, 155);
    doc.text('100%', 180, 155);
    
    // Risk label
    doc.setFontSize(16);
    doc.setTextColor(riskColor[0], riskColor[1], riskColor[2]);
    let riskLabel = averageRisk >= 70 ? 'High Risk' : averageRisk >= 40 ? 'Medium Risk' : 'Low Risk';
    doc.text(riskLabel, 95, 175);
  }
  
  // Add detailed URL list
  let yPosition = 195;
  const pageHeight = doc.internal.pageSize.height;
  
  // Section header
  doc.setFontSize(16);
  doc.setTextColor(0, 0, 0);
  doc.text('Detected URLs', 20, yPosition);
  yPosition += 10;
  
  // Sort URLs by risk (highest first)
  const sortedUrls = [...urls].sort((a, b) => b.risk_percentage - a.risk_percentage);
  
  // Add each URL with risk level
  doc.setFontSize(10);
  
  for (const url of sortedUrls) {
    // Check if we need a new page
    if (yPosition > pageHeight - 20) {
      doc.addPage();
      yPosition = 20;
    }
    
    // Set color based on risk
    if (url.risk_percentage >= 70) {
      doc.setTextColor(255, 77, 77);
    } else if (url.risk_percentage >= 40) {
      doc.setTextColor(255, 170, 0);
    } else {
      doc.setTextColor(0, 204, 68);
    }
    
    doc.text(`Risk: ${url.risk_percentage}% - Page ${url.page + 1}`, 20, yPosition);
    yPosition += 7;
    
    // Reset color for URL
    doc.setTextColor(0, 0, 0);
    
    // Handle long URLs
    const maxWidth = 170;
    const url_text = url.url;
    
    if (doc.getTextWidth(url_text) > maxWidth) {
      // Split URL into chunks
      let currentUrl = url_text;
      while (currentUrl.length > 0) {
        // Find maximum substring that fits
        let i = currentUrl.length;
        while (doc.getTextWidth(currentUrl.substring(0, i)) > maxWidth && i > 0) {
          i--;
        }
        
        // Write this chunk
        doc.text(currentUrl.substring(0, i), 25, yPosition);
        yPosition += 7;
        
        // Continue with remainder
        currentUrl = currentUrl.substring(i);
      }
    } else {
      doc.text(url_text, 25, yPosition);
      yPosition += 7;
    }
    
    // Add detected features if available
    if (url.features) {
      const activeFeatures = Object.entries(url.features)
        .filter(([_, value]) => value)
        .map(([key, _]) => {
          return key.replace(/_/g, ' ')
            .split(' ')
            .map(word => word.charAt(0).toUpperCase() + word.slice(1))
            .join(' ');
        });
      
      if (activeFeatures.length > 0) {
        doc.setTextColor(100, 100, 100);
        
        // Group features in rows to save space
        const featuresPerRow = 2;
        for (let i = 0; i < activeFeatures.length; i += featuresPerRow) {
          const rowFeatures = activeFeatures.slice(i, i + featuresPerRow);
          const featureText = rowFeatures.join(', ');
          
          // Check if we need a new page
          if (yPosition > pageHeight - 15) {
            doc.addPage();
            yPosition = 20;
          }
          
          doc.text(`• ${featureText}`, 30, yPosition);
          yPosition += 7;
        }
      }
    }
    
    // Add spacing between URLs
    yPosition += 5;
  }
  
  // Add footer
  const totalPages = doc.internal.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    doc.setFontSize(10);
    doc.setTextColor(150, 150, 150);
    doc.text(`linksniff  Phishing Detection - Page ${i} of ${totalPages}`, 20, pageHeight - 10);
  }
  
  // Save the PDF
  doc.save('linksniff _analysis_report.pdf');
}

// Generate CSV report
function generateCsvReport(reportData) {
  const { urls } = reportData;
  
  // Prepare CSV data
  const csvData = [];
  
  // Add header row
  csvData.push(['URL', 'Risk Percentage', 'Page Number', 'Features']);
  
  // Add data rows
  for (const url of urls) {
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
  }
  
  // Generate CSV
  const csv = Papa.unparse(csvData);
  
  // Create download link
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const csvUrl = URL.createObjectURL(blob);
  
  const link = document.createElement('a');
  link.href = csvUrl;
  link.setAttribute('download', 'ThreatVision_analysis.csv');
  link.style.visibility = 'hidden';
  
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', initReportGenerator);
