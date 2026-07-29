(function () {
    'use strict';

    const API = 'http://localhost:5000';
    const CACHE_TTL = 5 * 60 * 1000;
    let lastAnalyzedURL = '';
    let isAnalyzing = false;

    function shouldSkip(url) {
        return /^(chrome|chrome-extension|moz-extension|about|file):/.test(url);
    }

    // ── Main entry point ────────────────────────────────────────────────────
    function start() {
        const url = window.location.href;
        if (shouldSkip(url)) return;
        if (url === lastAnalyzedURL || isAnalyzing) return;
        analyzeCurrentPage(url);
    }

    // Wait for body to exist, then run
    function waitForBodyAndStart() {
        if (document.body) {
            start();
        } else {
            const obs = new MutationObserver(() => {
                if (document.body) {
                    obs.disconnect();
                    start();
                }
            });
            obs.observe(document.documentElement, { childList: true });
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', waitForBodyAndStart);
    } else {
        waitForBodyAndStart();
    }

    // Re-analyze on SPA navigation
    let _lastHref = location.href;
    setInterval(() => {
        if (location.href !== _lastHref) {
            _lastHref = location.href;
            lastAnalyzedURL = '';
            waitForBodyAndStart();
        }
    }, 1500);

    // ── Analysis ─────────────────────────────────────────────────────────────
    async function analyzeCurrentPage(url) {
        isAnalyzing = true;
        lastAnalyzedURL = url;
        try {
            const cached = await getCache(url);
            if (cached) { handleResult(cached, url); return; }

            const res = await fetch(`${API}/predict`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url }),
                signal: AbortSignal.timeout(8000)
            });
            if (!res.ok) return;
            const result = await res.json();
            await setCache(url, result);
            handleResult(result, url);
        } catch (e) {
            // backend offline — silent fail
        } finally {
            isAnalyzing = false;
        }
    }

    function handleResult(result, url) {
        // Always update badge
        chrome.runtime.sendMessage({ type: 'UPDATE_BADGE', result }).catch(() => {});

        if (result.prediction === 'Phishing') {
            chrome.runtime.sendMessage({ type: 'PHISHING_DETECTED', url, result }).catch(() => {});
            showBanner(result, url);
        } else {
            removeBanner();
        }
    }

    // ── Warning Banner ────────────────────────────────────────────────────────
    function showBanner(result, url) {
        removeBanner();
        const conf = (result.confidence * 100).toFixed(1);

        // Inject styles once
        if (!document.getElementById('ds-styles')) {
            const style = document.createElement('style');
            style.id = 'ds-styles';
            style.textContent = `
                #ds-warning {
                    position: fixed !important;
                    top: 0 !important; left: 0 !important; right: 0 !important;
                    z-index: 2147483647 !important;
                    background: linear-gradient(135deg, #c0392b, #e74c3c);
                    color: #fff;
                    padding: 12px 20px;
                    display: flex;
                    align-items: center;
                    gap: 14px;
                    box-shadow: 0 3px 12px #0006;
                    border-bottom: 3px solid #922b21;
                    font-family: -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif;
                }
                #ds-warning .ds-info { flex: 1; }
                #ds-warning .ds-title { font-weight: 700; font-size: 15px; letter-spacing: 1px; }
                #ds-warning .ds-sub   { font-size: 12px; opacity: 0.9; margin-top: 3px; }
                #ds-warning .ds-icon  { font-size: 26px; }
                #ds-warning .ds-btn {
                    background: #922b21;
                    border: 1px solid #c0392b;
                    color: #fff;
                    padding: 7px 12px;
                    border-radius: 5px;
                    cursor: pointer;
                    font-size: 12px;
                    margin-left: 6px;
                }
            `;
            document.documentElement.appendChild(style);
        }

        const wrapper = document.createElement('div');
        wrapper.id = 'ds-warning';

        const icon = document.createElement('span');
        icon.className = 'ds-icon';
        icon.textContent = '\uD83D\uDEA8';

        const info = document.createElement('div');
        info.className = 'ds-info';
        const title = document.createElement('div');
        title.className = 'ds-title';
        title.textContent = 'PHISHING WEBSITE DETECTED \u2014 Deep Scan';
        const sub = document.createElement('div');
        sub.className = 'ds-sub';
        sub.innerHTML = 'This site may steal your info. Confidence: <b>' + conf + '%</b> &nbsp;\u00b7&nbsp; Risk: <b>' + (result.risk_level || 'High') + '</b>';
        info.appendChild(title);
        info.appendChild(sub);

        const detailsBtn = document.createElement('button');
        detailsBtn.className = 'ds-btn';
        detailsBtn.textContent = 'Details';
        detailsBtn.onclick = () => showModal(result, url);

        const closeBtn = document.createElement('button');
        closeBtn.className = 'ds-btn';
        closeBtn.textContent = '\u2715';
        closeBtn.onclick = removeBanner;

        wrapper.appendChild(icon);
        wrapper.appendChild(info);
        wrapper.appendChild(detailsBtn);
        wrapper.appendChild(closeBtn);
        document.body.appendChild(wrapper);
    }

    function removeBanner() {
        const el = document.getElementById('ds-warning');
        if (el) el.remove();
    }

    // ── Detail Modal ──────────────────────────────────────────────────────────
    function showModal(result, url) {
        const existing = document.getElementById('ds-modal');
        if (existing) existing.remove();

        const overlay = document.createElement('div');
        overlay.id = 'ds-modal';
        Object.assign(overlay.style, {
            position: 'fixed', inset: '0', zIndex: '2147483647',
            background: 'rgba(0,0,0,0.75)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontFamily: '-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif'
        });

        const box = document.createElement('div');
        Object.assign(box.style, {
            background: '#1a1a2e', color: '#fff',
            border: '2px solid #00ff88', borderRadius: '14px',
            padding: '28px', maxWidth: '480px', width: '90%',
            boxShadow: '0 0 30px rgba(0,255,136,0.2)'
        });

        // Header
        const hdr = document.createElement('div');
        hdr.style.cssText = 'text-align:center;margin-bottom:20px;';
        hdr.innerHTML = `
            <div style="font-size:44px">🚨</div>
            <div style="font-size:1.3rem;font-weight:700;color:#ff3366;letter-spacing:1px;margin-top:8px">PHISHING DETECTED</div>
            <div style="font-size:0.85rem;color:#aaa;margin-top:4px">Deep Scan AI Analysis</div>
        `;

        // Details
        const details = document.createElement('div');
        Object.assign(details.style, {
            background: '#12122a', borderRadius: '8px',
            padding: '14px', marginBottom: '16px', fontSize: '13px', lineHeight: '1.8'
        });
        details.innerHTML = `
            <div><span style="color:#00d4ff">URL:</span> <span style="font-family:monospace;font-size:11px;word-break:break-all">${url}</span></div>
            <div><span style="color:#00d4ff">Confidence:</span> ${(result.confidence * 100).toFixed(1)}%</div>
            <div><span style="color:#00d4ff">Risk Level:</span> ${result.risk_level || 'High'}</div>
            <div><span style="color:#00d4ff">Phishing Probability:</span> ${(result.probabilities.phishing * 100).toFixed(1)}%</div>
        `;

        // Warning
        const warn = document.createElement('div');
        Object.assign(warn.style, {
            background: '#2a1f00', border: '1px solid #b37700',
            borderRadius: '8px', padding: '12px', marginBottom: '18px',
            fontSize: '12px', color: '#ffaa00'
        });
        warn.textContent = '⚠️ Do NOT enter passwords, credit cards, or personal info on this site.';

        // Close button
        const closeBtn = document.createElement('button');
        closeBtn.textContent = 'CLOSE';
        Object.assign(closeBtn.style, {
            width: '100%', background: 'linear-gradient(135deg,#ff3366,#c0392b)',
            color: '#fff', border: 'none', padding: '11px', borderRadius: '7px',
            cursor: 'pointer', fontSize: '14px', fontWeight: '700', letterSpacing: '1px'
        });
        closeBtn.onclick = () => overlay.remove();

        box.appendChild(hdr);
        box.appendChild(details);
        box.appendChild(warn);
        box.appendChild(closeBtn);
        overlay.appendChild(box);
        overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };
        document.body.appendChild(overlay);
    }

    // ── Cache helpers ─────────────────────────────────────────────────────────
    async function getCache(url) {
        try {
            const key = 'c_' + btoa(unescape(encodeURIComponent(url))).slice(0, 40);
            const r = await chrome.storage.local.get(key);
            const v = r[key];
            return v && Date.now() - v.ts < CACHE_TTL ? v.result : null;
        } catch { return null; }
    }

    async function setCache(url, result) {
        try {
            const key = 'c_' + btoa(unescape(encodeURIComponent(url))).slice(0, 40);
            await chrome.storage.local.set({ [key]: { result, ts: Date.now() } });
        } catch { }
    }

    // ── Gmail Scraper ─────────────────────────────────────────────────────────
    function scrapeGmail() {
        // 1. Get Subject
        const subjectEl = document.querySelector('h2.hP');
        const subject = subjectEl ? subjectEl.innerText : '';

        // 2. Get Sender details (sender's active element is span.gD)
        const senderEls = document.querySelectorAll('span.gD');
        let senderEmail = '';
        let senderName = '';
        if (senderEls.length > 0) {
            // Get the last visible/expanded one in the message thread
            const activeSender = senderEls[senderEls.length - 1];
            senderEmail = activeSender.getAttribute('email') || '';
            senderName = activeSender.innerText || '';
        }

        // 3. Get Email body/content and links
        const bodyEls = document.querySelectorAll('div.a3s');
        let emailContent = '';
        let links = [];
        if (bodyEls.length > 0) {
            const activeBody = bodyEls[bodyEls.length - 1];
            emailContent = activeBody.innerText || '';
            
            // Extract attached links
            const aEls = activeBody.querySelectorAll('a[href]');
            aEls.forEach(a => {
                const href = a.getAttribute('href');
                if (href && !href.startsWith('mailto:') && !href.startsWith('javascript:')) {
                    if (!links.includes(href)) {
                        links.push(href);
                    }
                }
            });
        }

        return {
            subject,
            sender: senderEmail ? `${senderName} <${senderEmail}>` : senderName,
            senderEmail,
            senderName,
            content: emailContent,
            links
        };
    }

    // Message listener for popup communication
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        if (request.type === 'SCRAPE_GMAIL') {
            const data = scrapeGmail();
            sendResponse(data);
        }
        return true;
    });

})();
