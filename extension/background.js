// extension/background.js - Final Version

// IMPORTANT: Replace this with your actual live Render API URL
const API_ENDPOINT = 'https://phishguard-api-ahuj.onrender.com/analyze';

// This listener handles the "Proceed Anyway" action from our warning page
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "allow_url") {
        chrome.storage.session.get({allowedUrls: []}, (data) => {
            let allowedUrls = data.allowedUrls;
            if (!allowedUrls.includes(request.url)) {
                allowedUrls.push(request.url);
            }
            chrome.storage.session.set({allowedUrls: allowedUrls});
            sendResponse({status: "success"});
        });
        return true; // Indicates we will send a response asynchronously
    }
});

// This listener handles clearing the notification after the alarm fires
chrome.alarms.onAlarm.addListener((alarm) => {
    chrome.notifications.clear(alarm.name);
});

// Main function triggered when a tab is updated
function handleTabUpdate(tabId, changeInfo, tab) {
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
        
        if (tab.url.includes('warning.html')) return;

        chrome.storage.session.get({allowedUrls: []}, (data) => {
            if (data.allowedUrls.includes(tab.url)) {
                return; // Skip analysis if on allow list
            }

            fetch(API_ENDPOINT, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ url: tab.url })
            })
            .then(response => {
              if (!response.ok) { throw new Error(`Server Error: ${response.status}`); }
              return response.json();
            })
            .then(apiData => {
              const hostname = new URL(apiData.url).hostname;
              
              if (apiData.result === 'phishing') {
                // Save the full result to session storage so the popup can read it.
                chrome.storage.session.set({ lastPhishingResult: apiData });
                
                const warningPageUrl = chrome.runtime.getURL('warning.html') + `?url=${encodeURIComponent(apiData.url)}`;
                chrome.tabs.update(tabId, { url: warningPageUrl });
                chrome.tts.speak(`Warning: Phishing site detected. The blocked domain is ${hostname}.`, {'rate': 1.0});

              } else if (apiData.result === 'safe') {
                const notificationId = `safe-notif-${Date.now()}`;
                chrome.notifications.create(notificationId, {
                  type: 'basic',
                  iconUrl: 'icon.png',
                  title: 'Site is Safe',
                  message: `PhishGuard has determined ${hostname} is safe.`,
                  priority: 1
                });
                chrome.alarms.create(notificationId, { delayInMinutes: 5 / 60 });
                chrome.tts.speak(`This site is safe. Domain is ${hostname}.`, {'rate': 1.0});
              }
            })
            .catch(error => console.error('[PhishGuard] Backend Error:', error));
        });
    }
}

chrome.tabs.onUpdated.addListener(handleTabUpdate);

console.log("[PhishGuard] Final version loaded. Ready to protect.");