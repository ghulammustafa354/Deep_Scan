// Background service worker for Chrome extension
chrome.runtime.onInstalled.addListener(() => {
    chrome.action.setBadgeBackgroundColor({ color: '#555555' });
    chrome.action.setBadgeText({ text: '' });
});

chrome.runtime.onStartup.addListener(() => {
    chrome.action.setBadgeBackgroundColor({ color: '#555555' });
    chrome.action.setBadgeText({ text: '' });
});

// Handle messages from content script and popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    switch (message.type) {
        case 'PHISHING_DETECTED':
            handlePhishingDetected(message.url, message.result, sender.tab);
            break;
            
        case 'UPDATE_BADGE':
            updateBadge(message.result, sender.tab);
            break;
            
        case 'GET_TAB_INFO':
            sendResponse({ tabId: sender.tab?.id, url: sender.tab?.url });
            break;
    }
    
    return true; // Keep message channel open for async response
});

// Handle phishing detection
async function handlePhishingDetected(url, result, tab) {
    try {
        // Update badge to show warning
        if (tab) {
            chrome.action.setBadgeText({ 
                text: '!', 
                tabId: tab.id 
            });
            chrome.action.setBadgeBackgroundColor({ 
                color: '#e53e3e', 
                tabId: tab.id 
            });
        }
        
        // Send notification
        await sendPhishingNotification(url, result);
        
        // Log the detection
        console.log('Phishing detected:', {
            url: url,
            confidence: result.confidence,
            timestamp: new Date().toISOString()
        });
        
        // Store detection in storage for statistics
        await storeDetection(url, result);
        
    } catch (error) {
        console.error('Error handling phishing detection:', error);
    }
}

// Update extension badge
function updateBadge(result, tab) {
    if (!tab) return;
    
    if (result.prediction === 'Phishing') {
        chrome.action.setBadgeText({ 
            text: '!', 
            tabId: tab.id 
        });
        chrome.action.setBadgeBackgroundColor({ 
            color: '#e53e3e', 
            tabId: tab.id 
        });
    } else {
        chrome.action.setBadgeText({ 
            text: 'OK', 
            tabId: tab.id 
        });
        chrome.action.setBadgeBackgroundColor({ 
            color: '#38a169', 
            tabId: tab.id 
        });
        
        // Clear badge after 3 seconds for legitimate sites
        setTimeout(() => {
            chrome.action.setBadgeText({ 
                text: '', 
                tabId: tab.id 
            });
        }, 3000);
    }
}

// Send phishing notification
async function sendPhishingNotification(url, result) {
    try {
        const domain = new URL(url).hostname;
        
        const notificationId = await chrome.notifications.create({
            type: 'basic',
            iconUrl: chrome.runtime.getURL('icons/icon48.png'),
            title: 'Deep Scan: Phishing Detected!',
            message: `Malicious site: ${domain}\nConfidence: ${(result.confidence * 100).toFixed(1)}%`,
            priority: 2
        });
        
        // Auto-clear notification after 10 seconds
        setTimeout(() => {
            chrome.notifications.clear(notificationId);
        }, 10000);
        
    } catch (error) {
        console.error('Error sending notification:', error);
    }
}

// Store detection for statistics
async function storeDetection(url, result) {
    try {
        const detection = {
            url: url,
            domain: new URL(url).hostname,
            prediction: result.prediction,
            confidence: result.confidence,
            timestamp: Date.now(),
            riskLevel: result.risk_level
        };
        
        // Get existing detections
        const storage = await chrome.storage.local.get(['detections', 'stats']);
        const detections = storage.detections || [];
        const stats = storage.stats || {
            totalDetections: 0,
            phishingDetected: 0,
            legitimateDetected: 0,
            lastUpdated: Date.now()
        };
        
        // Add new detection
        detections.push(detection);
        
        // Update stats
        stats.totalDetections++;
        if (result.prediction === 'Phishing') {
            stats.phishingDetected++;
        } else {
            stats.legitimateDetected++;
        }
        stats.lastUpdated = Date.now();
        
        // Keep only last 100 detections
        if (detections.length > 100) {
            detections.splice(0, detections.length - 100);
        }
        
        // Save to storage
        await chrome.storage.local.set({
            detections: detections,
            stats: stats
        });
        
    } catch (error) {
        console.error('Error storing detection:', error);
    }
}

// Handle notification clicks
chrome.notifications.onClicked.addListener((notificationId) => {
    // Clear the notification
    chrome.notifications.clear(notificationId);
    
    // Focus on the extension popup or open it
    chrome.action.openPopup().catch(() => {
        // If popup can't be opened, just clear the notification
        console.log('Notification clicked, popup already open or unavailable');
    });
});

// Clear badge when tab is updated (navigation)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'loading' && changeInfo.url) {
        // Clear badge when navigating to new URL
        chrome.action.setBadgeText({ text: '', tabId: tabId });
    }
});

// Handle tab activation (switching tabs)
chrome.tabs.onActivated.addListener(async (activeInfo) => {
    try {
        // Get tab info
        const tab = await chrome.tabs.get(activeInfo.tabId);
        
        // Check if we have recent analysis for this tab
        const cacheKey = `tab_${activeInfo.tabId}`;
        const storage = await chrome.storage.local.get(cacheKey);
        const tabData = storage[cacheKey];
        
        if (tabData && tabData.url === tab.url) {
            // Update badge based on cached result
            updateBadge(tabData.result, tab);
        } else {
            // Clear badge for new/unknown tabs
            chrome.action.setBadgeText({ text: '', tabId: activeInfo.tabId });
        }
        
    } catch (error) {
        console.error('Error handling tab activation:', error);
    }
});

// Cleanup old cache entries periodically
setInterval(async () => {
    try {
        const storage = await chrome.storage.local.get();
        const now = Date.now();
        const maxAge = 24 * 60 * 60 * 1000; // 24 hours
        
        const keysToRemove = [];
        
        for (const [key, value] of Object.entries(storage)) {
            if (key.startsWith('cache_') && value.timestamp) {
                if (now - value.timestamp > maxAge) {
                    keysToRemove.push(key);
                }
            }
        }
        
        if (keysToRemove.length > 0) {
            await chrome.storage.local.remove(keysToRemove);
            console.log(`Cleaned up ${keysToRemove.length} old cache entries`);
        }
        
    } catch (error) {
        console.error('Error cleaning up cache:', error);
    }
}, 60 * 60 * 1000); // Run every hour

