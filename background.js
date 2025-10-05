const apiKey = '3df84a119bff4dd712e303db66300d95a487f83364842d780a753f884c36bc64';
const virusTotalUrl = 'https://www.virustotal.com/api/v3/urls';

const processedTabUrls = new Map();

function safeBase64EncodedUrl(url) {
    return btoa(url).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function checkUrlWithVirusTotal(url) {
    const encodedUrl = safeBase64EncodedUrl(url);
    try {
        const response = await fetch(`${virusTotalUrl}/${encodedUrl}`, {
            method: "GET",
            headers: {
            "x-apikey": apiKey
            }
        });
        if (response.ok) {
            const result = await response.json();
            return result.data.attributes.last_analysis_stats.malicious > 0;
        }
    } catch (error) {
        console.error('VirusTotal API error:', error);
        return false;
    }
}

// Update dynamic blocking rules
async function handleRequest(url) {
    const isMalicious = await checkUrlWithVirusTotal(url);
    if (isMalicious) {
        // Check if the rule already exists
        chrome.declarativeNetRequest.getDynamicRules((existingRules) => {
            const existingRule = existingRules.find(rule => rule.condition.urlFilter === url);
            if (!existingRule) {
                // Create the blocking rule
                const newRule = {
                    id: existingRules.length + 1, 
                    priority: 1,
                    action: { type: "block" },
                    condition: {
                        urlFilter: url,
                        resourceTypes: ["main_frame"]
                    }
                };
                chrome.declarativeNetRequest.updateDynamicRules({
                    addRules: [newRule],
                    removeRuleIds: []
                }, () => {
                    // for debugging 
                    if (chrome.runtime.lastError) {
                        console.error(`Failed to add rule: ${chrome.runtime.lastError.message}`);
                    } else {
                        console.log(`Added rule for malicious URL: ${url}`);
                    }
                });
            // for debugging 
            } else {
                console.log(`Rule already exists for URL: ${url}`);
            }
        });
        chrome.notifications.create({
            type: "basic",
            iconUrl: "hand.png",
            title: "Blocked Malicious Website",
            message: `The website ${url} was identified as malicious and has been blocked.`
        });
    }
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.url) {
        processedTabUrls.set(tabId, changeInfo.url); //runs over old url 
    }
});

chrome.tabs.onRemoved.addListener((tabId) => {
    processedTabUrls.delete(tabId);
    console.log('deleted processed url'); // for debugging 
});

chrome.webRequest.onBeforeRequest.addListener(
    async (details) => {
        const url = details.url;
        const tabId = details.tabId;

        if (processedTabUrls.get(tabId) === url) {
            console.log('already processed this URL:', url); // for debugging 
            return;
        }
        processedTabUrls.set(tabId, url);
        await handleRequest(url);     
    },
    { urls: ["<all_urls>"], types: ['main_frame'] }
);
