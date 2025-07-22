// extension/background.js - FINAL DEFINITIVE VERSION

const API_ENDPOINT = 'https://phishguard-api-ahuj.onrender.com/analyze';

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "allow_url") {
        chrome.storage.session.get({allowedUrls: []}, (data) => {
            let allowedUrls = data.allowedUrls;
            if (!allowedUrls.includes(request.url)) { allowedUrls.push(request.url); }
            chrome.storage.session.set({allowedUrls: allowedUrls});
            sendResponse({status: "success"});
        });
        return true;
    }
});

chrome.alarms.onAlarm.addListener((alarm) => {
    chrome.notifications.clear(alarm.name);
});

function handleTabUpdate(tabId, changeInfo, tab) {
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
        if (tab.url.includes('warning.html')) return;

        chrome.storage.session.get({allowedUrls: []}, (data) => {
            if (data.allowedUrls.includes(tab.url)) {
                return;
            }

            chrome.storage.sync.get({
                isTtsEnabled: true,
                isSafeSitePopupEnabled: true
            }, (settings) => {
                fetch(API_ENDPOINT, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ url: tab.url })
                })
                .then(response => response.json())
                .then(apiData => {
                  const hostname = new URL(apiData.url).hostname;
                  
                  if (apiData.result === 'phishing') {
                    // --- THIS IS THE CRITICAL FIX ---
                    // 1. Save the full result with evidence to session storage.
                    chrome.storage.session.set({ lastPhishingResult: apiData }, () => {
                        // 2. Only redirect AFTER the data has been saved.
                        const warningPageUrl = chrome.runtime.getURL('warning.html') + `?url=${encodeURIComponent(apiData.url)}`;
                        chrome.tabs.update(tabId, { url: warningPageUrl });
                    });
                    
                    if (settings.isTtsEnabled) {
                        chrome.tts.speak(`Warning: Phishing site detected. The blocked domain is ${hostname}.`, {'rate': 1.0});
                    }
                  } else if (apiData.result === 'safe') {
                    if (settings.isSafeSitePopupEnabled) {
                        const notificationId = `safe-notif-${Date.now()}`;
                        chrome.notifications.create(notificationId, {
                          type: 'basic',
                          iconUrl: 'icon-safe.png',
                          title: 'Site is Safe',
                          message: `PhishGuard has determined ${hostname} is safe.`,
                          priority: 1
                        });
                        chrome.alarms.create(notificationId, { delayInMinutes: 5 / 60 });
                    }
                    if (settings.isTtsEnabled) {
                        chrome.tts.speak(`This site is safe. Domain is ${hostname}.`, {'rate': 1.0});
                    }
                  }
                })
                .catch(error => console.error('[PhishGuard] Backend Error:', error));
            });
        });
    }
}

chrome.tabs.onUpdated.addListener(handleTabUpdate);
console.log("[PhishGuard] Final definitive version loaded.");