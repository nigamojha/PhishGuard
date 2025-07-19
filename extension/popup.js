
document.addEventListener('DOMContentLoaded', () => {
    // IMPORTANT: Make sure this is your live Render API URL
    const API_ENDPOINT = 'https://phishguard-api-ahuj.onrender.com/analyze';

    const statusText = document.getElementById('status-text');
    const detailsArea = document.getElementById('details-area');
    const loader = document.querySelector('.loader');

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const currentTab = tabs[0];

        // Case 1: We are on our own warning page
        if (currentTab?.url?.includes('warning.html')) {
            loader.style.display = 'none';
            chrome.storage.session.get('lastPhishingResult', (data) => {
                if (data.lastPhishingResult) {
                    updatePopup(data.lastPhishingResult);
                } else {
                    statusText.textContent = 'Phishing Site Blocked';
                    statusText.className = 'status-phishing';
                }
            });
            return;
        }
        
        // Case 2: We are on a normal website
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

    // This is our single, unified function to update the popup's HTML
    function updatePopup(data) {
        const hostname = new URL(data.url).hostname;
        let statusMessage = 'Status Unknown';
        let statusClass = '';

        if (data.result === 'safe') {
            statusMessage = 'This site is Safe';
            statusClass = 'status-safe';
        } else if (data.result === 'phishing') {
            statusMessage = 'This site is Dangerous';
            statusClass = 'status-phishing';
        }

        statusText.textContent = statusMessage;
        statusText.className = statusClass;

        // Create a user-friendly string for the domain age
        let ageString = "Not available";
        if (data.domain_age === -1) {
            ageString = "Unknown (new or private)";
        } else if (data.domain_age !== undefined) {
            ageString = `${data.domain_age} days old`;
        }

        // Build the evidence list HTML
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

        // --- THIS IS THE FIX ---
        // Display the Domain, its Age, AND the new Evidence list
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