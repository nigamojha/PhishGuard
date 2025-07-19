

document.addEventListener('DOMContentLoaded', () => {
    const API_ENDPOINT = 'https://phishguard-api-ahuj.onrender.com/analyze'; // Replace with your live URL

    const statusText = document.getElementById('status-text');
    const detailsArea = document.getElementById('details-area');
    const loader = document.querySelector('.loader');

    // Get the currently active tab
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const currentTab = tabs[0];

        if (currentTab?.url?.includes('warning.html')) {
            loader.style.display = 'none';
            chrome.storage.session.get('lastPhishingResult', (data) => {
                if (data.lastPhishingResult) {
                    updatePopup(data.lastPhishingResult);
                }
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

        let evidenceHtml = '<ul class="evidence-list">';
        if (data.evidence?.safe_signals?.length > 0) {
            data.evidence.safe_signals.forEach(signal => {
                evidenceHtml += `<li class="safe">✅ ${signal}</li>`;
            });
        }
        if (data.evidence?.risk_factors?.length > 0) {
            data.evidence.risk_factors.forEach(risk => {
                evidenceHtml += `<li class="risk">🔴 ${risk}</li>`;
            });
        }
        evidenceHtml += '</ul>';

        detailsArea.innerHTML = `
            <div class="detail-item">
                <span>Domain:</span>
                <span>${hostname}</span>
            </div>
            <div class="detail-item">
                <span>Domain Age:</span>
                <span>${ageString}</span>
            </div>
            ${evidenceHtml}
        `;
    }
});