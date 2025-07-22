// extension/warning.js
document.addEventListener('DOMContentLoaded', () => {
    const goBackBtn = document.getElementById('go-back-btn');
    const reportBtn = document.getElementById('report-btn');
    const proceedBtn = document.getElementById('proceed-btn');
    const urlSpan = document.getElementById('blocked-url');

    const urlParams = new URLSearchParams(window.location.search);
    const blockedUrl = urlParams.get('url');

    if (blockedUrl) {
        urlSpan.textContent = new URL(blockedUrl).hostname;
    }

    goBackBtn.addEventListener('click', () => {
        window.location.href = 'https://www.google.com';
    });
    
    reportBtn.addEventListener('click', () => {
        const phishTankUrl = `https://phishtank.org/submit_phish.php?url=${encodeURIComponent(blockedUrl)}`;
        chrome.tabs.create({ url: phishTankUrl });
    });

    proceedBtn.addEventListener('click', () => {
        if (blockedUrl) {
            chrome.runtime.sendMessage({ action: "allow_url", url: blockedUrl }, () => {
                window.location.href = blockedUrl;
            });
        }
    });
});