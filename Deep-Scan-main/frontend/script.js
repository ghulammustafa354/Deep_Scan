/*
============================================================================
DEEP_SCAN FRONTEND JAVASCRIPT
============================================================================

This file handles all frontend logic:
1. User interactions (button clicks, Enter key)
2. Sending HTTP requests to backend API
3. Receiving and displaying results
4. Theme toggling (dark/light mode)

Flow:
User enters URL → Clicks SCAN → Send to backend → Get response → Display result

============================================================================
*/

// ============================================================================
// API CONFIGURATION
// ============================================================================
// Backend API URL - where Flask server is running
const API_URL = 'http://localhost:5000';  // Port 5000 is where Flask runs

// ============================================================================
// THEME TOGGLE FUNCTION
// ============================================================================
// Purpose: Switch between dark mode and light mode
function toggleTheme() {
    const body = document.body;  // Get body element
    const currentTheme = body.getAttribute('data-theme');  // Get current theme
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';  // Toggle theme
    body.setAttribute('data-theme', newTheme);  // Set new theme
    
    // Change icon (moon for dark, sun for light)
    const icon = document.getElementById('themeIcon');
    icon.className = newTheme === 'dark' ? 'fas fa-moon' : 'fas fa-sun';
}

// ============================================================================
// MAIN SCAN FUNCTION
// ============================================================================
// Purpose: Send URL to backend API and get phishing prediction
// Called when: User clicks SCAN button or presses Enter
// ============================================================================
async function scanURL() {
    // STEP 1: Get URL from input box
    const urlInput = document.getElementById('urlInput');  // Get input element
    const url = urlInput.value.trim();  // Get value and remove whitespace
    
    // STEP 2: Validate that user entered something
    if (!url) {
        showError('Please enter a URL to scan');  // Show error if empty
        return;  // Stop here
    }
    
    // STEP 3: Show loading animation (spinning circle)
    document.getElementById('loading').style.display = 'block';  // Show loading
    document.getElementById('results').style.display = 'none';  // Hide previous results
    
    try {
        // STEP 4: Send HTTP POST request to backend
        // This is where we communicate with Flask API
        const response = await fetch(`${API_URL}/predict`, {  // URL: http://localhost:5000/predict
            method: 'POST',  // POST method (sending data)
            headers: {
                'Content-Type': 'application/json',  // Tell server we're sending JSON
            },
            body: JSON.stringify({ url: url })  // Convert {url: "..."} to JSON string
        });
        
        // STEP 5: Get JSON response from backend
        const data = await response.json();  // Parse JSON response
        
        // STEP 6: Hide loading animation
        document.getElementById('loading').style.display = 'none';
        
        // STEP 7: Check if there was an error (400 status = validation error)
        if (!response.ok) {
            // Backend returned error (invalid URL format, etc.)
            showError(data.message || 'Invalid URL format. Please enter a valid URL.');
            return;  // Stop here
        }
        
        // STEP 8: Display results to user
        displayResults(data);

        // STEP 9: Check certificate in parallel
        checkCertificate(url);
        
    } catch (error) {
        // STEP 9: Handle network errors (backend not running, no internet, etc.)
        document.getElementById('loading').style.display = 'none';  // Hide loading
        showError('Analysis failed. Ensure the AI system is online.');  // Show error
        console.error('Error:', error);  // Log error to browser console
    }
}

// ============================================================================
// DISPLAY RESULTS FUNCTION
// ============================================================================
// Purpose: Show prediction results to user with colors and icons
// Input: data = {prediction, confidence, risk_level, probabilities}
// ============================================================================
function displayResults(data) {
    // STEP 1: Show results section
    const resultsDiv = document.getElementById('results');
    resultsDiv.style.display = 'block';  // Make results visible
    
    // STEP 2: Determine if URL is phishing or legitimate
    const isPhishing = data.prediction === 'Phishing';  // true if phishing
    const confidence = Math.round(data.confidence * 100);  // Convert 0.87 to 87%
    
    // STEP 3: Get HTML elements to update
    const threatIcon = document.getElementById('threatIcon');  // Icon (✔ or ⚠)
    const threatTitle = document.getElementById('threatTitle');  // Title (SECURE or THREAT DETECTED)
    const threatDesc = document.getElementById('threatDesc');  // Description text
    const threatStatus = document.getElementById('threatStatus');  // Container (for color)
    
    // STEP 4: Update UI based on prediction
    if (isPhishing) {
        // PHISHING DETECTED - Show red warning
        threatIcon.textContent = '⚠';  // Warning icon
        threatTitle.textContent = 'THREAT DETECTED';  // Red title
        threatDesc.textContent = 'This URL has been identified as potentially malicious';  // Warning message
        threatStatus.className = 'threat-status danger';  // Apply red styling
    } else {
        // LEGITIMATE - Show green safe status
        threatIcon.textContent = '✔';  // Checkmark icon
        threatTitle.textContent = 'SECURE';  // Green title
        threatDesc.textContent = 'Target appears to be legitimate and safe';  // Safe message
        threatStatus.className = 'threat-status safe';  // Apply green styling
    }
    
    // STEP 5: Update security score (confidence percentage)
    document.getElementById('securityScore').textContent = `${confidence}%`;  // Show 87%
    
    // STEP 6: Update analysis matrix (detailed info)
    document.getElementById('urlLength').textContent = data.url.length;  // URL length
    document.getElementById('encryptionStatus').textContent = data.url.startsWith('https') ? 'HTTPS' : 'HTTP';  // Encryption
    document.getElementById('riskLevel').textContent = data.risk_level;  // Risk level (High, Medium, Low)
    document.getElementById('confidence').textContent = `${confidence}%`;  // Confidence again
}

// ============================================================================
// SHOW ERROR FUNCTION
// ============================================================================
// Purpose: Display error messages to user (invalid input, server down, etc.)
// ============================================================================
function showError(message) {
    // STEP 1: Show results section (we'll use it to display error)
    const resultsDiv = document.getElementById('results');
    resultsDiv.style.display = 'block';
    
    // STEP 2: Set warning styling (yellow/orange)
    const threatStatus = document.getElementById('threatStatus');
    threatStatus.className = 'threat-status warning';  // Apply warning color
    
    // STEP 3: Update content with error message
    document.getElementById('threatIcon').textContent = '⚠';  // Warning icon
    document.getElementById('threatTitle').textContent = 'INVALID INPUT';  // Error title
    document.getElementById('threatDesc').textContent = message;  // Error message from parameter
    
    // STEP 4: Clear analysis matrix (show dashes)
    document.getElementById('urlLength').textContent = '-';
    document.getElementById('encryptionStatus').textContent = '-';
    document.getElementById('riskLevel').textContent = '-';
    document.getElementById('confidence').textContent = '-';
    document.getElementById('securityScore').textContent = '0%';
    document.getElementById('certStatus').textContent = '-';
    document.getElementById('certDetails').textContent = '';
}

// ============================================================================
// TEST URL FUNCTION
// ============================================================================
// Purpose: Fill input box with example URL and scan it
// Called when: User clicks example URL buttons
// ============================================================================
async function checkCertificate(url) {
    const certStatus = document.getElementById('certStatus');
    const certDetails = document.getElementById('certDetails');
    certStatus.textContent = 'CHECKING...';
    certDetails.textContent = '';

    try {
        const response = await fetch(`${API_URL}/check_certificate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        const data = await response.json();

        if (data.error) {
            certStatus.textContent = 'ERROR';
            return;
        }

        if (!data.has_certificate) {
            certStatus.textContent = 'NONE';
            certStatus.style.color = '#ff0044';
            certDetails.textContent = data.message || 'No SSL certificate';
        } else if (data.is_valid) {
            certStatus.textContent = '✔ VALID';
            certStatus.style.color = '#00ff88';
            certDetails.textContent = `Expires: ${data.expires} (${data.days_remaining}d) · ${data.issued_by}`;
        } else {
            certStatus.textContent = '✘ ' + data.status.toUpperCase();
            certStatus.style.color = '#ff0044';
            certDetails.textContent = data.message || `Issued by: ${data.issued_by}`;
        }
    } catch (e) {
        certStatus.textContent = 'ERROR';
    }
}

function testUrl(url) {
    document.getElementById('urlInput').value = url;  // Put URL in input box
    scanURL();  // Automatically scan it
}

// ============================================================================
// EVENT LISTENERS - Set up button clicks and keyboard shortcuts
// ============================================================================
// Wait for page to fully load before adding event listeners
document.addEventListener('DOMContentLoaded', function() {
    // Get elements
    const scanBtn = document.getElementById('scanBtn');  // SCAN button
    const urlInput = document.getElementById('urlInput');  // URL input box
    
    // LISTENER 1: SCAN button click
    scanBtn.addEventListener('click', scanURL);  // When button clicked, call scanURL()
    
    // LISTENER 2: Enter key in input box
    urlInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {  // If user pressed Enter key
            scanURL();  // Call scanURL() (same as clicking button)
        }
    });
});

/*
============================================================================
COMPLETE FLOW SUMMARY
============================================================================

1. User types URL in input box
2. User clicks SCAN button (or presses Enter)
3. scanURL() function is called
4. Show loading animation
5. Send POST request to http://localhost:5000/predict with {"url": "..."}
6. Backend (Flask) receives request
7. Backend analyzes URL (hybrid detection: rules + ML)
8. Backend sends JSON response: {prediction, confidence, risk_level}
9. Frontend receives response
10. Hide loading animation
11. displayResults() updates UI with prediction
12. User sees result: Green (safe) or Red (phishing) with confidence %

Total time: ~200 milliseconds
============================================================================
*/
