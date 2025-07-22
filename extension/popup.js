// extension/popup.js - FINAL DEFINITIVE VERSION

document.addEventListener('DOMContentLoaded', () => {
    const API_ENDPOINT = 'https://phishguard-api-ahuj.onrender.com/analyze';

    const statusText = document.getElementById('status-text');
    const detailsArea = document.getElementById('details-area');
    const loader = document.querySelector('.loader');
    const settingsBtn = document.getElementById('settings-btn');
    const mainView = document.getElementById('main-view');
    const settingsView = document.getElementById('settings-view');
    const backBtn = document.getElementById('back-btn');
    const ttsToggle = document.getElementById('tts-toggle');
    const safeSiteToggle = document.getElementById('safe-site-toggle');
    const statusMessage = document.getElementById('status-message');

    // --- VIEW SWITCHING ---
    settingsBtn.addEventListener('click', () => {
        mainView.classList.add('hidden');
        settingsView.classList.remove('hidden');
    });
    backBtn.addEventListener('click', () => {
        settingsView.classList.add('hidden');
        mainView.classList.remove('hidden');
    });

    // --- SETTINGS LOGIC ---
    chrome.storage.sync.get(['isTtsEnabled', 'isSafeSitePopupEnabled'], (settings) => {
        ttsToggle.checked = settings.isTtsEnabled ?? true;
        safeSiteToggle.checked = settings.isSafeSitePopupEnabled ?? true;
    });
    ttsToggle.addEventListener('change', () => {
        chrome.storage.sync.set({ isTtsEnabled: ttsToggle.checked });
        showStatusMessage();
    });
    safeSiteToggle.addEventListener('change', () => {
        chrome.storage.sync.set({ isSafeSitePopupEnabled: safeSiteToggle.checked });
        showStatusMessage();
    });
    function showStatusMessage() {
        statusMessage.style.opacity = 1;
        setTimeout(() => { statusMessage.style.opacity = 0; }, 1500);
    }

    // --- MAIN ANALYSIS LOGIC ---
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const currentTab = tabs[0];
        if (currentTab?.url?.includes('warning.html')) {
            loader.style.display = 'none';
            chrome.storage.session.get('lastPhishingResult', (data) => {
                if (data.lastPhishingResult) { updatePopup(data.lastPhishingResult); }
            });
            return;
        }
        if (currentTab?.url?.startsWith('http')) {
            fetch(API_ENDPOINT, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: currentTab.url })
            })
            .then(response => response.json())
            .then(data => {
                loader.style.display = 'none';
                updatePopup(data);
            })
            .catch(error => {
                loader.style.display = 'none';
                statusText.textContent = 'Error connecting to server.';
            });
        } else {
            loader.style.display = 'none';
            statusText.textContent = 'This page cannot be analyzed.';
        }
    });

    function updatePopup(data) {
        const hostname = new URL(data.url).hostname;
        statusText.textContent = data.result === 'safe' ? 'This site is Safe' : 'This site is Dangerous';
        statusText.className = data.result === 'safe' ? 'status-safe' : 'status-phishing';

        let ageString = "Unknown (new or private)";
        if (data.domain_age > 0) {
            ageString = `${data.domain_age} days old`;
        }

        // --- THIS IS THE CORRECTED LOGIC ---
        let evidenceHtml = '<ul class="evidence-list">';
        if (data.evidence && data.evidence.safe_signals && data.evidence.safe_signals.length > 0) {
            data.evidence.safe_signals.forEach(item => {
                evidenceHtml += `<li class="safe">✅ <strong>${item.signal}</strong><div class="evidence-explanation">${item.explanation}</div></li>`;
            });
        }
        if (data.evidence && data.evidence.risk_factors && data.evidence.risk_factors.length > 0) {
            data.evidence.risk_factors.forEach(item => {
                evidenceHtml += `<li class="risk">🔴 <strong>${item.risk}</strong><div class="evidence-explanation">${item.explanation}</div></li>`;
            });
        }
        evidenceHtml += '</ul>';
        // ------------------------------------

        detailsArea.innerHTML = `
            <div class="detail-item"><span>Domain:</span><span>${hostname}</span></div>
            <div class="detail-item"><span>Domain Age:</span><span>${ageString}</span></div>
            ${evidenceHtml}
        `;
    }
});