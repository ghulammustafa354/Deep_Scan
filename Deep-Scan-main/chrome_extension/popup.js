const API = 'http://localhost:5000';

document.addEventListener('DOMContentLoaded', async () => {
    document.getElementById('recheckBtn').addEventListener('click', recheck);
    document.getElementById('openDashboardBtn').addEventListener('click', () => {
        chrome.tabs.create({ url: 'http://localhost:5000' });
    });

    const emailBtn = document.getElementById('analyzeEmailBtn');
    if (emailBtn) {
        emailBtn.addEventListener('click', analyzeEmail);
    }

    await loadCurrentTab();
});

async function loadCurrentTab() {
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab || !tab.url) return showStatus('skipped', '—', 'Could not get tab URL.');

        document.getElementById('currentUrl').textContent = tab.url;

        // Show/hide Gmail scan container
        if (tab.url.includes('mail.google.com')) {
            document.getElementById('gmailScanContainer').style.display = 'block';
            return showStatus('skipped', '📧', 'Gmail page. Use "Analyze Open Email" button below.');
        } else {
            document.getElementById('gmailScanContainer').style.display = 'none';
        }

        if (/^(chrome|chrome-extension|moz-extension|about|file):/.test(tab.url)) {
            return showStatus('skipped', 'ℹ️', 'Browser internal page — skipped.');
        }

        // Check cache first
        const cached = await getCache(tab.url);
        if (cached) {
            displayResult(cached.result, tab.url);
            if (cached.cert) displayCert(cached.cert);
            return;
        }

        await analyze(tab.url);
    } catch (e) {
        showStatus('warning', '⚠️', 'Error loading tab.');
    }
}

async function analyze(url) {
    showLoading();
    try {
        const res = await fetch(`${API}/predict`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url }),
            signal: AbortSignal.timeout(10000)
        });

        if (!res.ok) throw new Error('Bad response');
        const result = await res.json();

        displayResult(result, url);
        notifyIfPhishing(result, url);

        // Check certificate in parallel
        checkCert(url);

        // Cache
        await setCache(url, { result });

    } catch (e) {
        const msg = e.message?.includes('fetch') || e.name === 'TypeError'
            ? 'Backend offline. Run: python backend/app.py'
            : e.name === 'TimeoutError' ? 'Request timed out.' : 'Analysis failed.';
        showStatus('warning', '⚠️', msg);
    }
}

async function checkCert(url) {
    try {
        const res = await fetch(`${API}/check_certificate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        const data = await res.json();
        displayCert(data);

        // Update cache with cert
        const cached = await getCache(url);
        if (cached) await setCache(url, { ...cached, cert: data });
    } catch (e) {
        document.getElementById('certStatus').textContent = 'Unavailable';
    }
}

async function analyzeEmail() {
    const btn = document.getElementById('analyzeEmailBtn');
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Extracting email...';

    showLoading();

    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab || !tab.id) {
            throw new Error('Could not communicate with tab.');
        }

        chrome.tabs.sendMessage(tab.id, { type: 'SCRAPE_GMAIL' }, async (response) => {
            if (chrome.runtime.lastError || !response || !response.content) {
                showStatus('warning', '⚠️', 'No open email detected. Open an email in Gmail first.');
                btn.disabled = false;
                btn.innerHTML = '<i class="fas fa-envelope-open-text"></i> Analyze Open Email';
                return;
            }

            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Running AI scan...';

            try {
                const res = await fetch(`${API}/predict/email`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        content: response.content,
                        subject: response.subject,
                        sender: response.sender,
                        links: response.links
                    }),
                    signal: AbortSignal.timeout(15000)
                });

                if (!res.ok) throw new Error('Backend error');
                const result = await res.json();

                displayEmailResult(result);
                notifyIfPhishing(result, tab.url);
            } catch (err) {
                showStatus('warning', '⚠️', 'Email scan failed. Check if backend is running.');
            } finally {
                btn.disabled = false;
                btn.innerHTML = '<i class="fas fa-envelope-open-text"></i> Analyze Open Email';
            }
        });
    } catch (e) {
        showStatus('warning', '⚠️', e.message || 'Failed to analyze email.');
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-envelope-open-text"></i> Analyze Open Email';
    }
}

function displayResult(result, url) {
    const isPhishing = result.prediction === 'Phishing';
    const conf = Math.round(result.confidence * 100);

    if (isPhishing) {
        showStatus('danger', '🚨', `Phishing detected! Confidence: ${conf}%`);
    } else if (result.confidence < 0.8) {
        showStatus('warning', '⚠️', `Suspicious — proceed with caution. (${conf}%)`);
    } else {
        showStatus('safe', '✔', `Site appears legitimate. (${conf}% safe)`);
    }

    // Toggle grids
    document.getElementById('emailDetailsGrid').style.display = 'none';
    const grid = document.getElementById('detailsGrid');
    grid.style.display = 'grid';

    const riskEl = document.getElementById('riskLevel');
    riskEl.textContent = result.risk_level || '-';
    riskEl.className = 'card-value ' + (isPhishing ? 'red' : conf >= 80 ? '' : 'yellow');

    document.getElementById('confidence').textContent = conf + '%';
    document.getElementById('phishingProb').textContent =
        Math.round(result.probabilities.phishing * 100) + '%';
    document.getElementById('legitimateProb').textContent =
        Math.round(result.probabilities.legitimate * 100) + '%';

    // Update badge via background
    chrome.runtime.sendMessage({ type: 'UPDATE_BADGE', result });
}

function displayEmailResult(result) {
    const isPhishing = result.prediction === 'Phishing';
    const conf = Math.round(result.confidence * 100);

    if (isPhishing) {
        showStatus('danger', '🚨', `Email threat detected! Confidence: ${conf}%`);
    } else {
        showStatus('safe', '✔', `Email appears legitimate. (${conf}% safe)`);
    }

    // Toggle grids
    document.getElementById('detailsGrid').style.display = 'none';
    const emailGrid = document.getElementById('emailDetailsGrid');
    emailGrid.style.display = 'grid';

    // 1. Sender Domain status
    const senderStatus = document.getElementById('emailSenderStatus');
    const senderDetails = document.getElementById('emailSenderDetails');
    const sa = result.sender_analysis;
    if (sa.is_suspicious) {
        senderStatus.textContent = '🚨 SUSPICIOUS';
        senderStatus.className = 'card-value red';
        senderDetails.textContent = sa.reason;
    } else if (sa.is_official_brand) {
        senderStatus.textContent = '✔ CLEAN';
        senderStatus.className = 'card-value';
        senderDetails.textContent = 'Sender domain verified as safe or official.';
    } else {
        senderStatus.textContent = '⚠ UNVERIFIED';
        senderStatus.className = 'card-value yellow';
        senderDetails.textContent = 'Sender domain is unverified or unofficial.';
    }

    // 2. Body Scan status
    const bodyStatus = document.getElementById('emailBodyStatus');
    const bodyDetails = document.getElementById('emailBodyDetails');
    const ba = result.email_body_analysis;
    if (ba.prediction === 'Phishing') {
        bodyStatus.textContent = '🚨 PHISHING';
        bodyStatus.className = 'card-value red';
        bodyDetails.textContent = `Flagged by DistilBERT (${Math.round(ba.confidence * 100)}%).`;
    } else {
        bodyStatus.textContent = '✔ CLEAN';
        bodyStatus.className = 'card-value';
        bodyDetails.textContent = 'No text threat patterns detected.';
    }

    // 3. Link Scanner status
    const linksStatus = document.getElementById('emailLinksStatus');
    const linksDetails = document.getElementById('emailLinksDetails');
    const la = result.links_analysis;
    const listCard = document.getElementById('emailLinkListCard');
    const listEl = document.getElementById('emailFlaggedLinks');

    if (la.phishing_links_count > 0) {
        linksStatus.textContent = `🚨 ${la.phishing_links_count} THREATS`;
        linksStatus.className = 'card-value red';
        linksDetails.textContent = `${la.phishing_links_count} of ${la.total_links} links flagged.`;

        listCard.style.display = 'block';
        listEl.innerHTML = '';
        const flagged = la.links.filter(l => l.prediction === 'Phishing');
        flagged.forEach(f => {
            const item = document.createElement('div');
            item.style.marginBottom = '4px';
            item.textContent = `• ${f.url} (${Math.round(f.confidence * 100)}%)`;
            listEl.appendChild(item);
        });
    } else {
        linksStatus.textContent = '✔ CLEAN';
        linksStatus.className = 'card-value';
        linksDetails.textContent = la.total_links > 0
            ? `All ${la.total_links} links verified as safe.`
            : 'No links attached to email.';
        listCard.style.display = 'none';
    }
}

function displayCert(data) {
    const statusEl = document.getElementById('certStatus');
    const detailEl = document.getElementById('certDetails');

    if (!data.has_certificate) {
        statusEl.textContent = 'NONE';
        statusEl.className = 'card-value red';
        detailEl.textContent = data.message || 'No SSL certificate';
    } else if (data.is_valid) {
        statusEl.textContent = '✔ VALID';
        statusEl.className = 'card-value';
        detailEl.textContent = `Expires: ${data.expires} (${data.days_remaining}d) · ${data.issued_by}`;
    } else {
        statusEl.textContent = '✘ ' + data.status.toUpperCase();
        statusEl.className = 'card-value red';
        detailEl.textContent = data.message || `Issued by: ${data.issued_by}`;
    }
}

function showLoading() {
    const b = document.getElementById('statusBlock');
    b.className = 'status-block loading';
    b.innerHTML = `<div class="status-row">
        <div class="status-icon"><div class="spinner"></div></div>
        <div><div class="status-title">Analyzing...</div>
        <div class="status-desc">Scanning with AI model...</div></div>
    </div>`;
    document.getElementById('detailsGrid').style.display = 'none';
    document.getElementById('emailDetailsGrid').style.display = 'none';
}

function showStatus(type, icon, desc) {
    const b = document.getElementById('statusBlock');
    b.className = `status-block ${type}`;
    const titles = { safe: 'SECURE', danger: 'THREAT DETECTED', warning: 'WARNING', skipped: 'SKIPPED' };
    b.innerHTML = `<div class="status-row">
        <div class="status-icon">${icon}</div>
        <div><div class="status-title">${titles[type] || type.toUpperCase()}</div>
        <div class="status-desc">${desc}</div></div>
    </div>`;
}

async function recheck() {
    const btn = document.getElementById('recheckBtn');
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Checking...';
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab?.url) {
            await clearCache(tab.url);
            await loadCurrentTab();
        }
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-sync-alt"></i> Recheck';
    }
}

async function notifyIfPhishing(result, url) {
    if (result.prediction !== 'Phishing') return;
    try {
        const domain = new URL(url).hostname;
        chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icons/icon48.png',
            title: '⚠️ Phishing Detected!',
            message: `${domain} flagged as phishing (${Math.round(result.confidence * 100)}% confidence)`,
            priority: 2
        });
    } catch (_) { }
}

// Cache helpers (5 min TTL)
const TTL = 5 * 60 * 1000;
async function getCache(url) {
    const key = 'c_' + btoa(url).slice(0, 40);
    const r = await chrome.storage.local.get(key);
    const v = r[key];
    return v && Date.now() - v.ts < TTL ? v : null;
}
async function setCache(url, data) {
    const key = 'c_' + btoa(url).slice(0, 40);
    await chrome.storage.local.set({ [key]: { ...data, ts: Date.now() } });
}
async function clearCache(url) {
    const key = 'c_' + btoa(url).slice(0, 40);
    await chrome.storage.local.remove(key);
}
