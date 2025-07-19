document.addEventListener('DOMContentLoaded', () => {
    // Get references to all three buttons
    const goBackBtn = document.getElementById('go-back-btn');
    const reportBtn = document.getElementById('report-btn');
    const proceedBtn = document.getElementById('proceed-btn');
    const urlSpan = document.getElementById('blocked-url');

    // Get the blocked URL from the page's query parameter
    const urlParams = new URLSearchParams(window.location.search);
    const blockedUrl = urlParams.get('url');

    // Display the blocked URL
    if (blockedUrl) {
        urlSpan.textContent = new URL(blockedUrl).hostname;
    }

    // NEW "Go Back" logic: Navigate to google.com
    goBackBtn.addEventListener('click', () => {
        window.location.href = 'https://www.google.com';
    });
    
    // NEW "Report Phishing" logic: Open PhishTank in a new tab
    reportBtn.addEventListener('click', () => {
        const phishTankUrl = `https://phishtank.org/submit_phish.php?url=${encodeURIComponent(blockedUrl)}`;
        // This asks the Chrome extension system to create a new tab
        chrome.tabs.create({ url: phishTankUrl });
    });

    // "Proceed" logic: Whitelist the URL for the session and navigate there
    proceedBtn.addEventListener('click', () => {
        if (blockedUrl) {
            chrome.runtime.sendMessage({ action: "allow_url", url: blockedUrl }, () => {
                window.location.href = blockedUrl;
            });
        }
    });
});