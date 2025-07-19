// extension/background.js - FINAL POLISHED VERSION

const API_ENDPOINT = 'https://phishguard-api-ahuj.onrender.com/analyze'; // Replace with your live URL

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
    // We only need to act when the page has finished loading.
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
        
        if (tab.url.includes('warning.html')) return;

        // Re-enable the popup for this tab, in case it was a page that disabled it.
        chrome.action.setPopup({ popup: 'popup.html', tabId: tab.id });

        chrome.storage.session.get({allowedUrls: []}, (data) => {
            if (data.allowedUrls.includes(tab.url)) {
                // Set the icon to safe if the user has allowed this site
                chrome.action.setIcon({ path: "icon-safe.png", tabId: tab.id });
                return;
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
                const warningPageUrl = chrome.runtime.getURL('warning.html') + `?url=${encodeURIComponent(apiData.url)}`;
                chrome.tabs.update(tabId, { url: warningPageUrl });
                // We disable the popup on our warning page
                chrome.action.setPopup({ popup: '', tabId: tab.id });
                chrome.tts.speak(`Warning: Phishing site detected. The blocked domain is ${hostname}.`, {'rate': 1.0});

              } else if (apiData.result === 'safe') {
                // For safe sites, set the icon to green.
                chrome.action.setIcon({ path: "icon-safe.png", tabId: tab.id });
                
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
            .catch(error => {
              // If the API call fails, disable the popup as we can't get a status.
              chrome.action.setPopup({ popup: '', tabId: tab.id });
              console.error('[PhishGuard] Backend Error:', error);
            });
        });
    }
}

chrome.tabs.onUpdated.addListener(handleTabUpdate);

console.log("[PhishGuard] Polished version loaded. Ready to protect.");