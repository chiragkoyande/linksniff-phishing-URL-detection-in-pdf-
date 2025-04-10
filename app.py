from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS
import PyPDF2
import re
import urllib.parse
from urllib.parse import urlparse
import tldextract
import json
from datetime import datetime
import os
import logging
import base64

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Secret key for session management
app.secret_key = os.environ.get("SESSION_SECRET", "linksniff_secret_key")

# Ensure logs directory exists
base_dir = os.path.dirname(os.path.abspath(__file__))
log_dir = os.path.join(base_dir, 'logs')
os.makedirs(log_dir, exist_ok=True)

# Store analysis history in memory (in production, this should use a database)
analysis_history = []

def log_malicious_url(url, risk_percentage, features):
    try:
        log_file = os.path.join(log_dir, 'malicious_urls.log')
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        log_entry = {
            'timestamp': timestamp,
            'url': url,
            'risk_percentage': risk_percentage,
            'features': features
        }
        
        # Add to analysis history
        analysis_history.append(log_entry)
        
        # Keep only the last 1000 entries in memory
        if len(analysis_history) > 1000:
            analysis_history.pop(0)
        
        # Write to log file
        try:
            with open(log_file, 'a+', encoding='utf-8') as f:
                json.dump(log_entry, f, ensure_ascii=False)
                f.write('\n')
        except Exception as e:
            logger.error(f"Error writing to log file: {str(e)}")
            # Try to create a backup log file in case of permission issues
            backup_file = os.path.join(base_dir, 'malicious_urls_backup.log')
            with open(backup_file, 'a+', encoding='utf-8') as f:
                json.dump(log_entry, f, ensure_ascii=False)
                f.write('\n')
            
    except Exception as e:
        logger.error(f"Failed to log malicious URL {url}: {str(e)}")

def extract_urls_from_pdf(pdf_file):
    urls = []
    try:
        pdf_reader = PyPDF2.PdfReader(pdf_file)
        
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        
        for page_num, page in enumerate(pdf_reader.pages):
            text = page.extract_text()
            found_urls = re.findall(url_pattern, text)
            
            # Store URLs with page number for highlighting
            for url in found_urls:
                urls.append({
                    'url': url,
                    'page': page_num
                })
        
        return urls
    except Exception as e:
        logger.error(f"Error extracting URLs from PDF: {str(e)}")
        return []

def analyze_url(url):
    # Handle incomplete URLs
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    parsed = urlparse(url)
    extracted = tldextract.extract(url)
    
    # Enhanced feature weights based on importance in phishing detection
    weights = {
        'ip_address': 3.5,           # Critical risk - direct IP usage
        'url_length': 1.0,           # Longer URLs more suspicious
        'tiny_url': 2.0,             # Short URLs can hide malicious destinations
        'at_symbol': 2.5,            # Very suspicious in URLs
        'redirecting': 2.0,          # Multiple redirects are suspicious
        'prefix_suffix': 2.0,        # Domain obfuscation technique
        'sub_domains': 2.0,          # Multiple subdomains can be suspicious
        'https': 2.0,                # Missing HTTPS is concerning
        'favicon': 0.8,              # Minor indicator
        'port': 2.0,                 # Non-standard ports are suspicious
        'https_domain': 2.0,         # HTTPS in domain name is suspicious
        'request_url': 3.0,          # Common in phishing URLs
        'anchor': 1.5,               # Can be used for obfuscation
        'links': 1.2,                # Potential indicator
        'sfh': 2.2,                  # Server form handler manipulation
        'mailto': 1.8,               # Can be used for data collection
        'iframes': 2.0,              # Often used in phishing
        'suspicious_tld': 3.5,       # High-risk TLDs
        'special_chars': 2.2,        # URL obfuscation technique
        'encoded_chars': 2.5,        # URL obfuscation technique
        'brand_impersonation': 4.0,  # Brand impersonation attempts
        'numeric_domain': 2.0,       # Domains with many numbers
        'suspicious_keywords': 2.5   # Known phishing keywords
    }
    
    # Expanded suspicious TLDs and patterns
    suspicious_tlds = {'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'xyz', 'top', 'work', 'party', 'date', 'stream', 'racing', 'win'}
    suspicious_keywords = {'security', 'update', 'verify', 'authentication', 'confirm', 'account', 'banking', 'subscription', 'password'}
    common_brands = {'paypal', 'apple', 'microsoft', 'amazon', 'google', 'facebook', 'netflix', 'bank'}
    
    # Enhanced feature detection
    features = {
        'ip_address': bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parsed.netloc)),
        'url_length': len(url) > 75,
        'tiny_url': len(url) < 20 and any(service in url.lower() for service in ['bit.ly', 'tinyurl', 't.co', 'goo.gl']),
        'at_symbol': '@' in parsed.netloc,
        'redirecting': '//' in parsed.path or 'redirect' in url.lower() or 'forward' in url.lower(),
        'prefix_suffix': '-' in parsed.netloc or any(c.isdigit() for c in parsed.netloc.split('.')[0]),
        'sub_domains': len(extracted.subdomain.split('.')) > 2 or len(parsed.netloc.split('.')) > 3,
        'https': parsed.scheme != 'https',
        'favicon': 'favicon' in url.lower() or 'icon' in parsed.path.lower(),
        'port': bool(parsed.port) and parsed.port not in {80, 443},
        'https_domain': 'https' in parsed.netloc or 'ssl' in parsed.netloc,
        'request_url': any(req in url.lower() for req in ['request', 'login', 'signin', 'account', 'verify', 'secure', 'update', 'confirm']),
        'anchor': '#' in url or 'javascript:' in url.lower(),
        'links': 'link' in url.lower() or 'url' in url.lower() or 'click' in url.lower(),
        'sfh': 'about:blank' in url or 'javascript:void' in url or 'data:' in url,
        'mailto': 'mailto:' in url or 'mail' in parsed.path.lower(),
        'iframes': 'iframe' in url.lower() or 'frame' in url.lower(),
        'suspicious_tld': extracted.suffix in suspicious_tlds,
        'special_chars': bool(re.search(r'[<>{}\[\]\\\^~`]', url)) or url.count('-') > 3,
        'encoded_chars': '%' in url and bool(re.search(r'%[0-9a-fA-F]{2}', url)),
        'brand_impersonation': any(brand in parsed.netloc.lower() for brand in common_brands) and not any(f'.{brand}.' in url.lower() for brand in common_brands),
        'numeric_domain': sum(c.isdigit() for c in parsed.netloc) > 3,
        'suspicious_keywords': any(keyword in url.lower() for keyword in suspicious_keywords)
    }
    
    # Improved risk calculation with feature combinations
    risk_score = 0
    max_score = 0
    
    # Calculate base risk score
    for feature, value in features.items():
        if value:
            risk_score += weights.get(feature, 0.75)
        max_score += weights.get(feature, 0.75)
    
    # Add additional weight for dangerous combinations
    if features['ip_address'] and features['request_url']:
        risk_score += 4.5
    if features['suspicious_tld'] and features['brand_impersonation']:
        risk_score += 6.0
    if features['encoded_chars'] and features['special_chars']:
        risk_score += 3.75
    if features['brand_impersonation'] and features['request_url']:
        risk_score += 5.25
    if features['tiny_url'] and features['suspicious_tld']:
        risk_score += 3.75
    if features['ip_address'] and features['suspicious_keywords']:
        risk_score += 4.5
    if features['brand_impersonation'] and features['special_chars']:
        risk_score += 4.5
    if features['suspicious_tld'] and features['request_url']:
        risk_score += 3.75
    if features['encoded_chars'] and features['brand_impersonation']:
        risk_score += 4.5
    if features['suspicious_keywords'] and features['brand_impersonation']:
        risk_score += 5.25
    if features['suspicious_tld'] and features['suspicious_keywords']:
        risk_score += 4.5
    
    # Add new dangerous combinations
    if features['ip_address'] and features['encoded_chars']:
        risk_score += 4.5  # IP with encoding is highly suspicious
    if features['tiny_url'] and features['request_url']:
        risk_score += 4.0  # Short URL with login/request
    if features['special_chars'] and features['suspicious_keywords']:
        risk_score += 3.75  # Obfuscation with suspicious keywords
    
    risk_percentage = min(100, int((risk_score / max_score) * 100))  # Cap at 100%
    
    return features, risk_percentage

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/pdf-viewer')
def pdf_viewer():
    return render_template('pdf-viewer.html')

@app.route('/url-scanner')
def url_scanner():
    return render_template('url-scanner.html')

@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)

@app.route('/analyze', methods=['POST'])
def analyze_pdf():
    if 'pdf' in request.files:
        pdf_file = request.files['pdf']
        if not pdf_file.filename.endswith('.pdf'):
            return jsonify({'error': 'File must be a PDF'}), 400
        
        try:
            # Extract URLs from PDF file
            urls_with_pages = extract_urls_from_pdf(pdf_file)
            
            if not urls_with_pages:
                return jsonify({
                    'risk_percentage': 0,
                    'features': {},
                    'detected_urls': [],
                    'url_analysis': []
                })
            
            # Analyze all URLs and calculate overall risk
            url_analysis = []
            total_risk = 0
            
            for url_obj in urls_with_pages:
                url = url_obj['url']
                page = url_obj['page']
                features, risk = analyze_url(url)
                
                url_analysis.append({
                    'url': url,
                    'page': page,
                    'risk_percentage': risk,
                    'features': features
                })
                
                # Log all URLs with suspicious features as potentially malicious
                if any(features.values()):
                    log_malicious_url(url, risk, features)
                total_risk += risk
            
            # Calculate weighted risk percentage based on all high-risk URLs
            url_risks = [analysis['risk_percentage'] for analysis in url_analysis]
            url_risks.sort(reverse=True)
            
            # Enhanced weighted risk calculation with more aggressive thresholds
            weighted_risk = 0
            if len(url_risks) > 0:
                # Lower thresholds for risk categories
                high_risk_urls = [risk for risk in url_risks if risk >= 40]
                medium_risk_urls = [risk for risk in url_risks if 25 <= risk < 40]
                low_risk_urls = [risk for risk in url_risks if risk < 25]
                
                # More aggressive weight distribution
                if high_risk_urls:
                    high_risk_weight = sum(high_risk_urls) / len(high_risk_urls) * 1.2
                    weighted_risk += high_risk_weight
                
                if medium_risk_urls:
                    medium_risk_weight = sum(medium_risk_urls) / len(medium_risk_urls) * 0.8
                    weighted_risk += medium_risk_weight
                
                if low_risk_urls:
                    low_risk_weight = sum(low_risk_urls) / len(low_risk_urls) * 0.4
                    weighted_risk += low_risk_weight
                
                # Normalize to percentage
                weighted_risk = min(100, int(weighted_risk))
            
            # Get unique features across all URLs for summary
            all_detected_features = {}
            for analysis in url_analysis:
                for feature, value in analysis['features'].items():
                    if value and feature not in all_detected_features:
                        all_detected_features[feature] = True
            
            return jsonify({
                'success': True,
                'risk_percentage': weighted_risk,
                'features': all_detected_features,
                'url_analysis': url_analysis
            })
            
        except Exception as e:
            logger.error(f"Error in PDF analysis: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    elif 'url' in request.json:
        # Analyze single URL
        url = request.json['url']
        try:
            features, risk_percentage = analyze_url(url)
            
            # Log if suspicious
            if any(features.values()):
                log_malicious_url(url, risk_percentage, features)
            
            return jsonify({
                'success': True,
                'risk_percentage': risk_percentage,
                'features': features,
                'url': url
            })
        
        except Exception as e:
            logger.error(f"Error analyzing URL: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    else:
        return jsonify({'error': 'No PDF file or URL provided'}), 400

@app.route('/analyze-pdf-data', methods=['POST'])
def analyze_pdf_data():
    try:
        data = request.json
        if 'pdfData' not in data:
            return jsonify({'error': 'No PDF data provided'}), 400
        
        # Decode base64 PDF data
        pdf_data = base64.b64decode(data['pdfData'].split(',')[1])
        
        # Save to temporary file
        temp_pdf_path = os.path.join(log_dir, 'temp.pdf')
        with open(temp_pdf_path, 'wb') as f:
            f.write(pdf_data)
        
        # Open the PDF file and analyze
        with open(temp_pdf_path, 'rb') as pdf_file:
            urls_with_pages = extract_urls_from_pdf(pdf_file)
            
            if not urls_with_pages:
                return jsonify({
                    'risk_percentage': 0,
                    'features': {},
                    'detected_urls': [],
                    'url_analysis': []
                })
            
            # Analyze all URLs
            url_analysis = []
            
            for url_obj in urls_with_pages:
                url = url_obj['url']
                page = url_obj['page']
                features, risk = analyze_url(url)
                
                url_analysis.append({
                    'url': url,
                    'page': page,
                    'risk_percentage': risk,
                    'features': features
                })
                
                # Log suspicious URLs
                if any(features.values()):
                    log_malicious_url(url, risk, features)
            
            # Calculate weighted risk
            url_risks = [analysis['risk_percentage'] for analysis in url_analysis]
            url_risks.sort(reverse=True)
            
            weighted_risk = 0
            if len(url_risks) > 0:
                high_risk_urls = [risk for risk in url_risks if risk >= 40]
                medium_risk_urls = [risk for risk in url_risks if 25 <= risk < 40]
                low_risk_urls = [risk for risk in url_risks if risk < 25]
                
                if high_risk_urls:
                    high_risk_weight = sum(high_risk_urls) / len(high_risk_urls) * 1.2
                    weighted_risk += high_risk_weight
                
                if medium_risk_urls:
                    medium_risk_weight = sum(medium_risk_urls) / len(medium_risk_urls) * 0.8
                    weighted_risk += medium_risk_weight
                
                if low_risk_urls:
                    low_risk_weight = sum(low_risk_urls) / len(low_risk_urls) * 0.4
                    weighted_risk += low_risk_weight
                
                weighted_risk = min(100, int(weighted_risk))
            
            # Get unique features across all URLs
            all_detected_features = {}
            for analysis in url_analysis:
                for feature, value in analysis['features'].items():
                    if value and feature not in all_detected_features:
                        all_detected_features[feature] = True
            
            # Remove temporary file
            try:
                os.remove(temp_pdf_path)
            except:
                pass
            
            return jsonify({
                'success': True,
                'risk_percentage': weighted_risk,
                'features': all_detected_features,
                'url_analysis': url_analysis
            })
    
    except Exception as e:
        logger.error(f"Error in PDF data analysis: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/get-history', methods=['GET'])
def get_history():
    # Group by date
    history_by_date = {}
    for entry in analysis_history:
        date = entry['timestamp'].split(' ')[0]
        if date not in history_by_date:
            history_by_date[date] = []
        history_by_date[date].append(entry)
    
    # Calculate statistics
    stats = {
        'total_scans': len(analysis_history),
        'high_risk': len([e for e in analysis_history if e['risk_percentage'] >= 70]),
        'medium_risk': len([e for e in analysis_history if 40 <= e['risk_percentage'] < 70]),
        'low_risk': len([e for e in analysis_history if e['risk_percentage'] < 40]),
        'by_date': {date: len(entries) for date, entries in history_by_date.items()}
    }
    
    # Get feature frequency
    feature_stats = {}
    for entry in analysis_history:
        for feature, value in entry['features'].items():
            if value:
                if feature not in feature_stats:
                    feature_stats[feature] = 0
                feature_stats[feature] += 1
    
    return jsonify({
        'history': analysis_history[-100:],  # Return last 100 entries
        'statistics': stats,
        'feature_stats': feature_stats
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
