// extension/popup.js - Updated to display Domain Age

document.addEventListener('DOMContentLoaded', () => {
    const API_ENDPOINT = 'https://phishguard-api.onrender.com/analyze'; // Replace with your live URL

    const statusText = document.getElementById('status-text');
    const detailsArea = document.getElementById('details-area');
    const loader = document.querySelector('.loader');

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const currentTab = tabs[0];

        if (currentTab && currentTab.url && currentTab.url.includes('warning.html')) {
            loader.style.display = 'none';
            statusText.textContent = 'Phishing Site Blocked';
            statusText.className = 'status-phishing';
            const urlParams = new URLSearchParams(new URL(currentTab.url).search);
            const originalUrl = urlParams.get('url');
            if (originalUrl) {
                detailsArea.innerHTML = `<div class="detail-item"><span>Blocked Domain:</span><span>${new URL(originalUrl).hostname}</span></div>`;
            }
            return;
        }
        
        if (currentTab && currentTab.url && currentTab.url.startsWith('http')) {
            fetch(API_ENDPOINT, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: currentTab.url })
            })
            .then(response => response.json())
            .then(data => {
                loader.style.display = 'none';
                updatePopup(data); // Call the updated function
            })
            .catch(error => {
                loader.style.display = 'none';
                statusText.textContent = 'Error connecting to server.';
                console.error("API Error:", error);
            });
        } else {
            loader.style.display = 'none';
            statusText.textContent = 'This page cannot be analyzed.';
        }
    });

    // --- THIS FUNCTION IS NOW UPDATED ---
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
            ageString = "Unknown (new or private domain)";
        } else if (data.domain_age !== undefined) {
            ageString = `${data.domain_age} days old`;
        }

        // Display the Domain and its Age!
        detailsArea.innerHTML = `
            <div class="detail-item">
                <span>Domain:</span>
                <span>${hostname}</span>
            </div>
            <div class="detail-item">
                <span>Domain Age:</span>
                <span>${ageString}</span>
            </div>
        `;
    }
});