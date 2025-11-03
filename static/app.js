// Security Alert Enrichment Bot - Frontend JavaScript

const API_BASE = window.location.origin;

// DOM Elements
const enrichBtn = document.getElementById('enrichBtn');
const indicatorInput = document.getElementById('indicator');
const typeSelect = document.getElementById('type');
const loadingDiv = document.getElementById('loading');
const errorDiv = document.getElementById('error');
const resultsDiv = document.getElementById('results');

// Event Listeners
enrichBtn.addEventListener('click', enrichAlert);
indicatorInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        enrichAlert();
    }
});

// Main enrichment function
async function enrichAlert() {
    const indicator = indicatorInput.value.trim();
    const type = typeSelect.value;

    // Validation
    if (!indicator) {
        showError('Please enter an IP address or domain');
        return;
    }

    // Basic validation
    if (type === 'ip' && !isValidIP(indicator)) {
        showError('Please enter a valid IP address');
        return;
    }

    if (type === 'domain' && !isValidDomain(indicator)) {
        showError('Please enter a valid domain name');
        return;
    }

    // Show loading, hide error and results
    loadingDiv.classList.remove('hidden');
    errorDiv.classList.add('hidden');
    resultsDiv.classList.add('hidden');
    enrichBtn.disabled = true;

    try {
        const response = await fetch(`${API_BASE}/api/enrich`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ indicator, type })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to enrich alert');
        }

        displayResults(data);
    } catch (error) {
        showError(error.message);
    } finally {
        loadingDiv.classList.add('hidden');
        enrichBtn.disabled = false;
    }
}

// Display enrichment results
function displayResults(data) {
    // Show results section
    resultsDiv.classList.remove('hidden');

    // Display indicator info
    document.getElementById('result-indicator').textContent = data.indicator;
    document.getElementById('result-type').textContent = data.type.toUpperCase();

    // Display VirusTotal results
    displayVirusTotalResults(data.results.virustotal);

    // Display AbuseIPDB results (only for IPs)
    if (data.type === 'ip' && data.results.abuseipdb) {
        document.getElementById('abuseipdb-section').classList.remove('hidden');
        displayAbuseIPDBResults(data.results.abuseipdb);
    } else {
        document.getElementById('abuseipdb-section').classList.add('hidden');
    }

    // Display Shodan results (only for IPs)
    if (data.type === 'ip' && data.results.shodan) {
        document.getElementById('shodan-section').classList.remove('hidden');
        displayShodanResults(data.results.shodan);
    } else {
        document.getElementById('shodan-section').classList.add('hidden');
    }

    // Scroll to results
    resultsDiv.scrollIntoView({ behavior: 'smooth' });
}

// Display VirusTotal results
function displayVirusTotalResults(data) {
    const content = document.getElementById('vt-content');
    
    if (data.error) {
        content.innerHTML = `<p class="error">Error: ${data.error}</p>`;
        return;
    }

    if (data.status === 'not_found') {
        content.innerHTML = `<p>${data.message}</p>`;
        return;
    }

    const malicious = data.malicious || 0;
    const suspicious = data.suspicious || 0;
    const harmless = data.harmless || 0;
    const undetected = data.undetected || 0;

    let threatLevel = 'success';
    if (malicious > 0) threatLevel = 'danger';
    else if (suspicious > 0) threatLevel = 'warning';

    content.innerHTML = `
        <div class="result-row">
            <span class="result-label">Detection Status:</span>
            <span class="result-value">
                <span class="badge badge-${threatLevel}">
                    ${malicious > 0 ? 'MALICIOUS' : suspicious > 0 ? 'SUSPICIOUS' : 'CLEAN'}
                </span>
            </span>
        </div>
        <div class="result-row">
            <span class="result-label">Malicious Detections:</span>
            <span class="result-value">${malicious}</span>
        </div>
        <div class="result-row">
            <span class="result-label">Suspicious Detections:</span>
            <span class="result-value">${suspicious}</span>
        </div>
        <div class="result-row">
            <span class="result-label">Harmless:</span>
            <span class="result-value">${harmless}</span>
        </div>
        <div class="result-row">
            <span class="result-label">Undetected:</span>
            <span class="result-value">${undetected}</span>
        </div>
        <div class="result-row">
            <span class="result-label">Reputation Score:</span>
            <span class="result-value">${data.reputation || 0}</span>
        </div>
        <div class="result-row">
            <span class="result-label">Country:</span>
            <span class="result-value">${data.country || 'Unknown'}</span>
        </div>
        <div class="result-row">
            <span class="result-label">AS Owner:</span>
            <span class="result-value">${data.as_owner || 'Unknown'}</span>
        </div>
    `;
}

// Display AbuseIPDB results
function displayAbuseIPDBResults(data) {
    const content = document.getElementById('abuseipdb-content');
    
    if (data.error) {
        content.innerHTML = `<p class="error">Error: ${data.error}</p>`;
        return;
    }

    const score = data.abuse_confidence_score || 0;
    let scoreLevel = 'success';
    if (score > 75) scoreLevel = 'danger';
    else if (score > 25) scoreLevel = 'warning';

    content.innerHTML = `
        <div class="result-row">
            <span class="result-label">Abuse Confidence Score:</span>
            <span class="result-value">
                <span class="badge badge-${scoreLevel}">${score}%</span>
            </span>
        </div>
        <div class="result-row">
            <span class="result-label">Total Reports:</span>
            <span class="result-value">${data.total_reports || 0}</span>
        </div>
        <div class="result-row">
            <span class="result-label">Country:</span>
            <span class="result-value">${data.country_code || 'Unknown'}</span>
        </div>
        <div class="result-row">
            <span class="result-label">ISP:</span>
            <span class="result-value">${data.isp || 'Unknown'}</span>
        </div>
        <div class="result-row">
            <span class="result-label">Domain:</span>
            <span class="result-value">${data.domain || 'Unknown'}</span>
        </div>
        <div class="result-row">
            <span class="result-label">Usage Type:</span>
            <span class="result-value">${data.usage_type || 'Unknown'}</span>
        </div>
        <div class="result-row">
            <span class="result-label">Whitelisted:</span>
            <span class="result-value">${data.is_whitelisted ? 'Yes' : 'No'}</span>
        </div>
        <div class="result-row">
            <span class="result-label">Last Reported:</span>
            <span class="result-value">${data.last_reported || 'Never'}</span>
        </div>
    `;
}

// Display Shodan results
function displayShodanResults(data) {
    const content = document.getElementById('shodan-content');
    
    if (data.error) {
        content.innerHTML = `<p class="error">Error: ${data.error}</p>`;
        return;
    }

    if (data.status === 'not_found') {
        content.innerHTML = `<p>${data.message}</p>`;
        return;
    }

    let portsHTML = '';
    if (data.ports && data.ports.length > 0) {
        portsHTML = `
            <div class="result-row">
                <span class="result-label">Open Ports:</span>
                <span class="result-value">
                    <div class="port-list">
                        ${data.ports.map(port => `<span class="port-badge">${port}</span>`).join('')}
                    </div>
                </span>
            </div>
        `;
    }

    let servicesHTML = '';
    if (data.services && data.services.length > 0) {
        servicesHTML = `
            <div class="result-row">
                <span class="result-label">Services:</span>
                <span class="result-value">
                    <ul class="service-list">
                        ${data.services.map(service => `
                            <li class="service-item">
                                Port ${service.port}: ${service.service} (${service.protocol})
                            </li>
                        `).join('')}
                    </ul>
                </span>
            </div>
        `;
    }

    let hostnamesHTML = '';
    if (data.hostnames && data.hostnames.length > 0) {
        hostnamesHTML = `
            <div class="result-row">
                <span class="result-label">Hostnames:</span>
                <span class="result-value">${data.hostnames.join(', ')}</span>
            </div>
        `;
    }

    content.innerHTML = `
        <div class="result-row">
            <span class="result-label">Organization:</span>
            <span class="result-value">${data.organization || 'Unknown'}</span>
        </div>
        <div class="result-row">
            <span class="result-label">ISP:</span>
            <span class="result-value">${data.isp || 'Unknown'}</span>
        </div>
        <div class="result-row">
            <span class="result-label">Operating System:</span>
            <span class="result-value">${data.operating_system || 'Unknown'}</span>
        </div>
        <div class="result-row">
            <span class="result-label">Location:</span>
            <span class="result-value">${data.city || 'Unknown'}, ${data.country || 'Unknown'}</span>
        </div>
        ${hostnamesHTML}
        ${portsHTML}
        ${servicesHTML}
        <div class="result-row">
            <span class="result-label">Last Update:</span>
            <span class="result-value">${data.last_update || 'Unknown'}</span>
        </div>
    `;
}

// Show error message
function showError(message) {
    errorDiv.textContent = message;
    errorDiv.classList.remove('hidden');
    resultsDiv.classList.add('hidden');
}

// Validation helpers
function isValidIP(ip) {
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipPattern.test(ip)) return false;
    
    const parts = ip.split('.');
    return parts.every(part => {
        const num = parseInt(part, 10);
        return num >= 0 && num <= 255;
    });
}

function isValidDomain(domain) {
    // Simple domain validation without ReDoS vulnerability
    // Check basic format: alphanumeric with dots and hyphens
    if (domain.length > 253) return false;
    
    const domainPattern = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;
    
    // Additional check: no consecutive dots or hyphens at start/end of labels
    if (domain.includes('..') || domain.includes('-.') || domain.includes('.-')) {
        return false;
    }
    
    return domainPattern.test(domain);
}
