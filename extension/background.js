// extension/background.js

const API_ENDPOINT = 'https://phishguard-api-ahuj.onrender.com/analyze';

// --- Event Listeners ---
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

// Main function triggered when a tab is updated
function handleTabUpdate(tabId, changeInfo, tab) {
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
        
        if (tab.url.includes('warning.html')) return;

        chrome.storage.session.get({allowedUrls: []}, (sessionData) => {
            if (sessionData.allowedUrls.includes(tab.url)) {
                return; // Skip analysis if on the session allow list
            }

       
            // 1. First, get the user's saved settings from storage.
            chrome.storage.sync.get({
                isTtsEnabled: true, // Default to 'on' if no setting is saved yet
                isSafeSitePopupEnabled: true // Default to 'on'
            }, (settings) => {

                // 2. Perform the fetch to our API.
                fetch(API_ENDPOINT, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ url: tab.url })
                })
                .then(response => response.json())
                .then(apiData => {
                  const hostname = new URL(apiData.url).hostname;
                  
                  if (apiData.result === 'phishing') {
                    chrome.storage.session.set({ lastPhishingResult: apiData });
                    const warningPageUrl = chrome.runtime.getURL('warning.html') + `?url=${encodeURIComponent(apiData.url)}`;
                    chrome.tabs.update(tabId, { url: warningPageUrl });
                    
                    // 3. ONLY speak if the setting is enabled.
                    if (settings.isTtsEnabled) {
                        chrome.tts.speak(`Warning: Phishing site detected. The blocked domain is ${hostname}.`, {'rate': 1.0});
                    }

                  } else if (apiData.result === 'safe') {
                    // 4. ONLY show the notification if the setting is enabled.
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
                    
                    // 5. ONLY speak if the setting is enabled.
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

console.log("[PhishGuard] Final version loaded. Ready to protect.");