"""\nDEEP_SCAN FLASK API SERVER\n\nThis file creates the REST API server that receives requests from frontend\nand returns phishing detection predictions.\n\nMain Components:\n1. Flask server setup with CORS\n2. URL prediction endpoint (/predict)\n3. Email prediction endpoint (/predict/email)\n4. Batch prediction endpoint (/batch_predict)\n5. Model info endpoint (/model_info)\n\nHow it works:\n- Frontend sends HTTP POST request with URL/email\n- Flask receives request and extracts data\n- Calls prediction engine (URLPredictor or EmailPhishingDetector)\n- Returns JSON response with prediction and confidence\n"""

# ============================================================================
# IMPORTS - Libraries needed for the API server
# ============================================================================
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sys
import os
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse

# ============================================================================
# PATH SETUP - Add folders to Python path so we can import our modules
# ============================================================================
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'models'))  # Add models folder
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'email_analysis'))  # Add email_analysis folder
sys.path.append(os.path.dirname(__file__))  # Add current directory

# ============================================================================
# IMPORT OUR DETECTION MODULES
# ============================================================================
from predict import URLPredictor
try:
    from email_analysis.email_detector import EmailPhishingDetector  # type: ignore
except Exception:
    try:
        from email_detector import EmailPhishingDetector  # type: ignore
    except Exception:
        EmailPhishingDetector = None
import logging

# ============================================================================
# LOGGING SETUP - Track what's happening in the server
# ============================================================================
logging.basicConfig(level=logging.INFO)  # Set logging level to INFO
logger = logging.getLogger(__name__)  # Create logger for this file

# ============================================================================
# FLASK APP INITIALIZATION
# ============================================================================
app = Flask(__name__)  # Create Flask application
CORS(app)  # Enable CORS - allows frontend (port 3000) to talk to backend (port 5000)

# ============================================================================
# LOAD ML MODELS - Load once at startup (not for every request)
# ============================================================================
url_predictor = URLPredictor()  # Load Random Forest model for URL detection
email_predictor = EmailPhishingDetector() if EmailPhishingDetector else None  # Load email detector if available

# ============================================================================
# ROUTE 1: HEALTH CHECK ENDPOINT
# ============================================================================
# Purpose: Check if API server is running
# Method: GET
# URL: http://localhost:5000/
# Returns: JSON with status information
# ============================================================================
@app.route('/', methods=['GET'])
def home():
    """
    Serves the frontend cyber_interface.html at the root URL of localhost:5000
    """
    frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend'))
    return send_from_directory(frontend_dir, 'cyber_interface.html')

@app.route('/<path:filename>', methods=['GET'])
def serve_frontend_assets(filename):
    """
    Serves static assets (CSS, JS, etc.) from the frontend directory
    """
    frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend'))
    return send_from_directory(frontend_dir, filename)

# ============================================================================
# ROUTE 2: URL PREDICTION ENDPOINT
# ============================================================================
# Purpose: Analyze a single URL for phishing
# Method: POST
# URL: http://localhost:5000/predict
# Input: JSON with {"url": "https://example.com"}
# Output: JSON with prediction, confidence, risk_level
# ============================================================================
@app.route('/predict', methods=['POST'])
def predict_url():
    """\n    Main URL prediction endpoint\n    \n    Flow:\n    1. Receive JSON from frontend with URL\n    2. Validate URL format\n    3. Call URLPredictor to analyze URL\n    4. Calculate risk level based on confidence\n    5. Return JSON response with prediction\n    \n    Example Request:\n        POST http://localhost:5000/predict\n        Body: {"url": "https://suspicious-site.com"}\n    \n    Example Response:\n        {\n            "prediction": "Phishing",\n            "confidence": 0.873,\n            "risk_level": "High",\n            "probabilities": {"phishing": 0.873, "legitimate": 0.127}\n        }\n    """
    try:
        # STEP 1: Get JSON data from frontend
        data = request.get_json()  # Extract JSON from HTTP request body
        
        # STEP 2: Validate that JSON contains 'url' field
        if not data or 'url' not in data:
            return jsonify({
                'error': 'Missing URL parameter',
                'message': 'Please provide a URL in the request body'
            }), 400  # Return error code 400 (Bad Request)
        
        url = data['url'].strip()  # Extract URL and remove whitespace
        
        # STEP 3: Validate URL is not empty
        if not url:
            return jsonify({
                'error': 'Invalid URL',
                'message': 'URL cannot be empty'
            }), 400
        
        # STEP 4: Validate URL has a dot (all domains have dots like google.com)
        if '.' not in url:
            return jsonify({
                'error': 'Invalid URL format',
                'message': 'Please enter a valid URL (e.g., example.com or https://example.com)'
            }), 400
        
        # STEP 5: Add https:// if user didn't include it
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url  # Add https:// prefix
        
        # Normalize: add www. if missing (model trained on dataset where legit sites have www.)
        parsed_norm = urlparse(url)
        netloc = parsed_norm.netloc
        if netloc and not netloc.startswith('www.') and netloc.count('.') == 1:
            url = url.replace(netloc, 'www.' + netloc, 1)
        
        # Additional validation - check if URL has valid structure
        try:
            parsed = urlparse(url)
            if not parsed.netloc or len(parsed.netloc) < 3:
                return jsonify({
                    'error': 'Invalid URL format',
                    'message': 'Please enter a valid URL with a proper domain name'
                }), 400
        except Exception:
            return jsonify({
                'error': 'Invalid URL format',
                'message': 'Please enter a valid URL (e.g., example.com or https://example.com)'
            }), 400
        
        logger.info(f"Analyzing URL: {url}")

        # Predict using our local Random Forest model
        result = url_predictor.predict_url(url)
        logger.info(f"Detection method: {result.get('method', 'unknown')}")
        
        # STEP 7: Calculate risk level based on confidence score
        confidence = result['confidence']  # Get confidence (0.0 to 1.0)
        # Determine risk level based on prediction and confidence
        if result['prediction'] == 'Phishing':
            # If it's phishing, higher confidence = higher risk
            if confidence > 0.8:
                risk_level = 'High'  # Very confident it's phishing
            elif confidence > 0.6:
                risk_level = 'Medium'  # Moderately confident
            else:
                risk_level = 'Low'  # Low confidence
        else:
            # If it's legitimate, higher confidence = lower risk
            if confidence > 0.8:
                risk_level = 'Very Low'  # Very confident it's safe
            elif confidence > 0.6:
                risk_level = 'Low'  # Moderately confident it's safe
            else:
                risk_level = 'Medium'  # Uncertain
        
        # STEP 8: Build response JSON to send back to frontend
        response = {
            'url': url,
            'prediction': result['prediction'],
            'confidence': round(result['confidence'], 3),
            'risk_level': risk_level,
            'probabilities': {
                'phishing': round(result['probabilities']['phishing'], 3),
                'legitimate': round(result['probabilities']['legitimate'], 3)
            },
            'features_extracted': result.get('features_count', 47),
            'method': result.get('method', 'hybrid')
        }
        
        logger.info(f"Prediction: {result['prediction']} (confidence: {confidence:.3f})")  # Log result
        
        # STEP 9: Send JSON response back to frontend
        return jsonify(response)  # Convert Python dict to JSON and send
        
    except Exception as e:
        # STEP 10: Handle any errors that occur
        logger.error(f"Error processing request: {str(e)}")  # Log the error
        return jsonify({
            'error': 'Internal server error',
            'message': 'Failed to analyze URL. Please try again.'
        }), 500  # Return error code 500 (Internal Server Error)

# ============================================================================
# ROUTE 3: CERTIFICATE CHECK ENDPOINT
# ============================================================================
@app.route('/check_certificate', methods=['POST'])
def check_certificate():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'Missing URL'}), 400

        url = data['url'].strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        parsed = urlparse(url)
        hostname = parsed.netloc or parsed.path
        hostname = hostname.split(':')[0]  # remove port if any

        # Check if it's even HTTPS
        if not url.startswith('https://'):
            return jsonify({
                'has_certificate': False,
                'is_valid': False,
                'status': 'No Certificate',
                'message': 'Site uses HTTP, no SSL/TLS certificate'
            })

        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.create_connection((hostname, 443), timeout=5), server_hostname=hostname) as s:
                cert = s.getpeercert()

            # Parse expiry date
            expire_str = cert.get('notAfter', '')
            expire_date = datetime.strptime(expire_str, '%b %d %H:%M:%S %Y %Z')
            is_expired = expire_date < datetime.utcnow()
            days_left = (expire_date - datetime.utcnow()).days

            # Get issued to
            subject = dict(x[0] for x in cert.get('subject', []))
            issuer = dict(x[0] for x in cert.get('issuer', []))

            return jsonify({
                'has_certificate': True,
                'is_valid': not is_expired,
                'status': 'Expired' if is_expired else 'Valid',
                'expires': expire_date.strftime('%Y-%m-%d'),
                'days_remaining': days_left,
                'issued_to': subject.get('commonName', hostname),
                'issued_by': issuer.get('organizationName', 'Unknown')
            })

        except ssl.SSLCertVerificationError:
            return jsonify({
                'has_certificate': True,
                'is_valid': False,
                'status': 'Invalid',
                'message': 'Certificate verification failed (untrusted/self-signed)'
            })
        except (socket.timeout, ConnectionRefusedError, socket.gaierror):
            return jsonify({
                'has_certificate': False,
                'is_valid': False,
                'status': 'Unreachable',
                'message': 'Could not connect to host'
            })

    except Exception as e:
        logger.error(f"Certificate check error: {str(e)}")
        return jsonify({'error': 'Failed to check certificate'}), 500

# ============================================================================
# ROUTE 4: BATCH PREDICTION ENDPOINT
# ============================================================================
# Purpose: Analyze multiple URLs at once (up to 100)
# Method: POST
# URL: http://localhost:5000/batch_predict
# Input: JSON with {"urls": ["url1", "url2", "url3"]}
# Output: JSON with array of predictions
# ============================================================================
@app.route('/batch_predict', methods=['POST'])
def batch_predict():
    """\n    Batch prediction endpoint - analyze multiple URLs at once\n    \n    Useful for:\n    - Checking multiple links from an email\n    - Scanning a list of URLs from a file\n    - Bulk analysis for security teams\n    \n    Limit: Maximum 100 URLs per request\n    """
    try:
        data = request.get_json()  # Get JSON data
        
        # Validate that 'urls' field exists
        if not data or 'urls' not in data:
            return jsonify({
                'error': 'Missing URLs parameter',
                'message': 'Please provide a list of URLs'
            }), 400
        
        urls = data['urls']  # Extract list of URLs
        
        # Validate that urls is a list and not empty
        if not isinstance(urls, list) or len(urls) == 0:
            return jsonify({
                'error': 'Invalid URLs format',
                'message': 'URLs must be a non-empty list'
            }), 400
        
        # Limit batch size to prevent server overload
        if len(urls) > 100:
            return jsonify({
                'error': 'Too many URLs',
                'message': 'Maximum 100 URLs allowed per batch'
            }), 400
        
        results = []  # Store results for each URL
        
        # Loop through each URL and analyze it
        for url in urls:
            try:
                url = url.strip()  # Remove whitespace
                
                # Skip empty URLs
                if not url:
                    results.append({
                        'url': url,
                        'error': 'Empty URL',
                        'prediction': 'Error',
                        'confidence': 0.0
                    })
                    continue  # Move to next URL
                
                # Validate URL has a dot
                if '.' not in url:
                    results.append({
                        'url': url,
                        'error': 'Invalid URL format - missing domain',
                        'prediction': 'Error',
                        'confidence': 0.0
                    })
                    continue
                
                # Add https:// if missing
                if not url.startswith(('http://', 'https://')):
                    url = 'https://' + url
                
                # Analyze this URL
                result = url_predictor.predict_url(url)
                
                # Add result to list
                results.append({
                    'url': url,
                    'prediction': result['prediction'],
                    'confidence': round(result['confidence'], 3),
                    'probabilities': {
                        'phishing': round(result['probabilities']['phishing'], 3),
                        'legitimate': round(result['probabilities']['legitimate'], 3)
                    }
                })
                
            except Exception as e:
                # If error analyzing this URL, add error to results
                results.append({
                    'url': url,
                    'error': str(e),
                    'prediction': 'Error',
                    'confidence': 0.0
                })
        
        # Return all results
        return jsonify({
            'results': results,  # Array of predictions
            'total_processed': len(results)  # How many URLs were processed
        })
        
    except Exception as e:
        logger.error(f"Error in batch prediction: {str(e)}")
        return jsonify({
            'error': 'Internal server error',
            'message': 'Failed to process batch prediction'
        }), 500

# ============================================================================
# ROUTE 5: EMAIL PREDICTION ENDPOINT
# ============================================================================
# Purpose: Analyze email content for phishing
# Method: POST
# URL: http://localhost:5000/predict/email
# Input: JSON with {"content": "email text", "subject": "...", "sender": "..."}
# Output: JSON with prediction, confidence, risk_score
# ============================================================================
@app.route('/predict/email', methods=['POST'])
def predict_email():
    """\n    Email prediction endpoint - analyze email for phishing\n    \n    Uses NLP (Natural Language Processing) to detect:\n    - Urgent keywords (verify, suspended, urgent)\n    - Suspicious patterns (credit card numbers, passwords)\n    - Negative sentiment\n    - Shortened URLs\n    \n    Note: Currently uses rule-based NLP (80-85% accuracy)\n    FYP-2 will upgrade to BERT/RoBERTa ML (90%+ accuracy)\n    """
    try:
        # Check if email detector is loaded
        if email_predictor is None:
            return jsonify({
                'error': 'Email analysis not available',
                'message': 'Email detection module not found'
            }), 503  # Service Unavailable
            
        data = request.get_json()  # Get JSON data
        
        # Validate that all required fields exist
        if not data or 'content' not in data or 'subject' not in data or 'sender' not in data:
            return jsonify({
                'error': 'Missing required fields',
                'message': 'Please provide content, subject, and sender in the request body'
            }), 400
        
        # Extract and sanitize email fields
        content = data['content'].strip()
        subject = data['subject'].strip()
        sender = data['sender'].strip()
        links = data.get('links', [])
        
        if not content or not subject or not sender:
            return jsonify({
                'error': 'Invalid request parameters',
                'message': 'content, subject, and sender cannot be empty'
            }), 400
        
        logger.info(f"Analyzing email from: {sender} (links to check: {len(links)})")  # Log sender
        
        # Analyze email body using NLP detector
        result = email_predictor.analyze_email(content, subject, sender)
        
        # Analyze links in the email
        phishing_links_count = 0
        link_details = []
        max_link_confidence = 0.0
        
        for url in links:
            url_res = url_predictor.predict_url(url)
            is_phish = url_res['prediction'] == 'Phishing'
            if is_phish:
                phishing_links_count += 1
                if url_res['confidence'] > max_link_confidence:
                    max_link_confidence = url_res['confidence']
            link_details.append({
                'url': url,
                'prediction': url_res['prediction'],
                'confidence': round(url_res['confidence'], 3),
                'risk_level': 'High' if is_phish else 'Low'
            })
            
        # Combine results to make overall threat judgment
        body_phishing = result['prediction'] == 'Phishing'
        sender_suspicious = result.get('sender_analysis', {}).get('is_suspicious', False)
        sender_official = result.get('sender_analysis', {}).get('is_official_brand', False)
        links_phishing = phishing_links_count > 0
        
        # Override rule: if the email is from a verified official sender domain, AND has no phishing links,
        # we override the overall prediction to Legitimate, bypassing any DistilBERT false positives on text content.
        if sender_official and not sender_suspicious and not links_phishing:
            is_phishing_overall = False
            # Update nested result attributes
            result['prediction'] = 'Legitimate'
            result['confidence'] = 0.98
            result['probabilities'] = {'phishing': 0.02, 'legitimate': 0.98}
            result['risk_score'] = 5
            result['method'] = 'official_sender_override'
            body_phishing = False
        else:
            is_phishing_overall = body_phishing or sender_suspicious or links_phishing
        
        if is_phishing_overall:
            prediction = 'Phishing'
            conf_list = [result['confidence']]
            if sender_suspicious:
                conf_list.append(0.99)
            if links_phishing:
                conf_list.append(max_link_confidence)
            confidence = max(conf_list)
            risk_level = 'High' if confidence > 0.8 else 'Medium'
            risk_score = max(result.get('risk_score', 0), 100 if (sender_suspicious or links_phishing) else 0)
            probabilities = {'phishing': confidence, 'legitimate': 1.0 - confidence}
        else:
            prediction = 'Legitimate'
            confidence = result['confidence']
            risk_level = 'Very Low' if confidence > 0.8 else 'Low' if confidence > 0.6 else 'Medium'
            risk_score = result.get('risk_score', 0)
            probabilities = {'phishing': 1.0 - confidence, 'legitimate': confidence}
            
        # Build combined response
        response = {
            'type': 'email',
            'prediction': prediction,
            'confidence': round(confidence, 3),
            'risk_level': risk_level,
            'probabilities': {
                'phishing': round(probabilities['phishing'], 3),
                'legitimate': round(probabilities['legitimate'], 3)
            },
            'risk_score': risk_score,
            'method': result.get('method', 'hybrid'),
            'email_body_analysis': {
                'prediction': result['prediction'],
                'confidence': round(result['confidence'], 3),
                'method': result.get('method', 'distilbert')
            },
            'sender_analysis': result.get('sender_analysis', {
                'is_suspicious': False,
                'matched_brand': None,
                'reason': None
            }),
            'links_analysis': {
                'total_links': len(links),
                'phishing_links_count': phishing_links_count,
                'links': link_details
            }
        }
        
        return jsonify(response)  # Send response
        
    except Exception as e:
        logger.error(f"Error processing email: {str(e)}")
        return jsonify({
            'error': 'Internal server error',
            'message': 'Failed to analyze email'
        }), 500

# ============================================================================
# ROUTE 6: MODEL INFO ENDPOINT
# ============================================================================
# Purpose: Get information about loaded ML models
# Method: GET
# URL: http://localhost:5000/model_info
# ============================================================================
@app.route('/model_info', methods=['GET'])
def model_info():
    """\n    Get model information endpoint\n    \n    Returns details about:\n    - URL detector (Random Forest model info)\n    - Email detector (NLP model info)\n    - API version\n    """
    try:
        url_info = url_predictor.get_model_info()  # Get URL model info
        
        # Only get email info if email predictor exists
        if email_predictor:
            email_info = email_predictor.get_model_info()
        else:
            email_info = {'status': 'not_available', 'message': 'Email detection module not loaded'}
        
        return jsonify({
            'url_detector': url_info,  # URL model details
            'email_detector': email_info,  # Email model details
            'api_version': '2.0.0'  # API version
        })
    except Exception as e:
        logger.error(f"Error getting model info: {str(e)}")
        return jsonify({
            'error': 'Failed to get model information'
        }), 500

# ============================================================================
# ROUTE 7: QR CODE (QUISHING) DETECTION ENDPOINT
# ============================================================================
# Purpose: Extract URL from uploaded QR code image and analyze it
# Method: POST
# URL: http://localhost:5000/predict/qr
# ============================================================================
@app.route('/predict/qr', methods=['POST'])
def predict_qr():
    """
    Extracts URL from an uploaded QR code image and runs it through the URL model.
    """
    try:
        # Check if file exists in the request
        if 'file' not in request.files:
            return jsonify({
                'error': 'Missing file',
                'message': 'No QR code image file was uploaded'
            }), 400
            
        file = request.files['file']
        if file.filename == '':
            return jsonify({
                'error': 'Invalid file',
                'message': 'No file was selected'
            }), 400
            
        # Try dynamic import of OpenCV and NumPy
        try:
            import cv2
            import numpy as np
        except ImportError:
            return jsonify({
                'error': 'Missing dependencies',
                'message': 'The backend requires opencv-python to scan QR codes. Please run: pip install opencv-python'
            }), 500
            
        # Read file bytes
        img_bytes = file.read()
        
        # Decode image bytes using OpenCV
        nparr = np.frombuffer(img_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        if img is None:
            return jsonify({
                'error': 'Decoding error',
                'message': 'Failed to decode uploaded image. Ensure it is a valid image file.'
            }), 400
            
        # Extract URL from QR Code
        detector = cv2.QRCodeDetector()
        extracted_url, _, _ = detector.detectAndDecode(img)
        
        if not extracted_url:
            return jsonify({
                'error': 'No QR Code detected',
                'message': 'No QR code could be scanned or decoded from the uploaded image.'
            }), 400
            
        url = extracted_url.strip()
        
        # Add https:// if user didn't include it
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        # Predict using our local Random Forest model or typosquatting checks
        # Pre-emptively trust educational and government domains
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower().split(':')[0]
        if domain.endswith('.edu.pk') or domain.endswith('.edu') or domain.endswith('.gov.pk') or domain.endswith('.gov'):
            result = {
                'prediction': 'Legitimate',
                'confidence': 0.98,
                'probabilities': {'phishing': 0.02, 'legitimate': 0.98},
                'features_count': 22,
                'method': 'rule_based'
            }
        else:
            result = url_predictor.predict_url(url)
            
        # Calculate risk level based on confidence score
        confidence = result['confidence']
        if result['prediction'] == 'Phishing':
            if confidence > 0.8:
                risk_level = 'High'
            elif confidence > 0.6:
                risk_level = 'Medium'
            else:
                risk_level = 'Low'
        else:
            if confidence > 0.8:
                risk_level = 'Very Low'
            elif confidence > 0.6:
                risk_level = 'Low'
            else:
                risk_level = 'Medium'
        
        response = {
            'url': url,
            'prediction': result['prediction'],
            'confidence': round(result['confidence'], 3),
            'risk_level': risk_level,
            'probabilities': {
                'phishing': round(result['probabilities']['phishing'], 3),
                'legitimate': round(result['probabilities']['legitimate'], 3)
            },
            'features_extracted': result.get('features_count', 22),
            'method': result.get('method', 'hybrid'),
            'type': 'qr_code'
        }
        
        logger.info(f"QR Extracted URL: {url} | Prediction: {result['prediction']} (confidence: {confidence:.3f})")
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error decoding QR code: {str(e)}")
        return jsonify({
            'error': 'Internal server error',
            'message': f"Failed to process QR code image: {str(e)}"
        }), 500

# ============================================================================
# ERROR HANDLERS
# ============================================================================
@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors (endpoint not found)"""
    return jsonify({
        'error': 'Endpoint not found',
        'message': 'The requested endpoint does not exist'
    }), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors (internal server error)"""
    return jsonify({
        'error': 'Internal server error',
        'message': 'An unexpected error occurred'
    }), 500

# ============================================================================
# MAIN - Start the Flask server
# ============================================================================
if __name__ == '__main__':
    # Print startup information
    print("="*60)
    print("Starting Deep_Scan Phishing Detection API...")
    print("="*60)
    print("API will be available at: http://localhost:5000")
    print("\nAvailable Endpoints:")
    print("  GET  /              - Health check (test if API is running)")
    print("  POST /predict       - URL prediction (analyze single URL)")
    print("  POST /predict/email - Email prediction (analyze email content)")
    print("  POST /batch_predict - Batch URL prediction (analyze multiple URLs)")
    print("  GET  /model_info    - Model information (get ML model details)")
    print("="*60)
    print("Press CTRL+C to stop the server")
    print("="*60)
    
    # Start Flask server
    # debug=True: Auto-reload on code changes, show detailed errors
    # host='0.0.0.0': Accept connections from any IP (not just localhost)
    # port=5000: Run on port 5000
    app.run(debug=True, host='0.0.0.0', port=5000)