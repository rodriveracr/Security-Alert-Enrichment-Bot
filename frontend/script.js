document.getElementById('enrich-form').addEventListener('submit', async function(e) {
  e.preventDefault();
  const type = document.getElementById('input-type').value;
  const value = document.getElementById('input-value').value.trim();
  const resultDiv = document.getElementById('result');
  resultDiv.innerHTML = '';

  // Basic validation
  if (!value) {
    showError(resultDiv, 'Please enter an indicator value.');
    return;
  }

  const BACKEND_URL = 'http://127.0.0.1:5001/enrich';

  // Validate format (skip for mock)
  if (value.toLowerCase() !== 'mock') {
    if (type === 'ip' && !/^([0-9]{1,3}\.){3}[0-9]{1,3}$/.test(value)) {
      showError(resultDiv, 'Invalid IP address format.');
      return;
    }
    if (type === 'domain' && !/^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/.test(value)) {
      showError(resultDiv, 'Invalid domain format.');
      return;
    }
  }

  resultDiv.innerHTML = '<div class="loading"><i class="fas fa-spinner fa-spin"></i> Analyzing indicator</div>';

  try {
    // Mock mode
    if (value.toLowerCase() === 'mock') {
      const mockData = {
        input_type: type,
        value: 'mock-data',
        results: {
          virustotal: { detected_urls: 5, reputation: 45 },
          abuseipdb: type === 'ip' ? { score: 25, reports: 3 } : null,
          shodan: type === 'ip' ? { open_ports: [22, 80, 443, 8080], org: 'Demo ISP Inc.' } : null
        }
      };
      resultDiv.innerHTML = renderResults(mockData, true);
      return;
    }

    // Real query
    const response = await fetch(BACKEND_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type, value })
    });

    if (!response.ok) {
      let errorText = await response.text();
      throw new Error('Query error: ' + errorText);
    }

    const data = await response.json();
    if (data && typeof data === 'object') {
      resultDiv.innerHTML = renderResults(data, false);
    } else {
      showError(resultDiv, 'No data returned.');
    }
  } catch (err) {
    if (err.name === 'TypeError' && err.message.includes('Failed to fetch')) {
      showError(resultDiv, `Network error: Cannot connect to backend at ${BACKEND_URL}. Make sure the backend is running.`);
    } else {
      showError(resultDiv, `Error: ${err.message}`);
    }
  }
});

function showError(container, message) {
  container.innerHTML = `<div class="error"><i class="fas fa-exclamation-circle"></i> ${message}</div>`;
}

function resetForm() {
  document.getElementById('enrich-form').reset();
  document.getElementById('result').innerHTML = '';
}

// Render enriched results
function renderResults(data, isMock) {
  const icon = isMock ? '<i class="fas fa-vial"></i>' : '<i class="fas fa-check-circle"></i>';
  const statusClass = isMock ? 'mock' : 'real';
  const statusText = isMock ? 'Demo Data' : 'Real Data';

  let html = `
    <div class="result-card">
      <div class="result-header">
        ${icon} Analysis Results
        <span class="result-status ${statusClass}">${statusText}</span>
      </div>
      <p><strong>Type:</strong> ${data.input_type === 'ip' ? 'IP Address' : 'Domain'}</p>
      <p><strong>Indicator:</strong> <code>${data.value}</code></p>
    </div>
  `;

  if (data.results) {
    // VirusTotal Results
    if (data.results.virustotal) {
      const vt = data.results.virustotal;
      html += `
        <div class="result-card">
          <h3><i class="fas fa-virus"></i> VirusTotal</h3>
          <p><strong>Detected URLs:</strong> ${vt.detected_urls || 'N/A'}</p>
          <p><strong>Reputation Score:</strong> ${vt.reputation || 'N/A'}</p>
          ${vt.detected_urls > 0 ? '<p style="color: #dc2626;"><strong>⚠️ Warning:</strong> Malicious URLs detected!</p>' : ''}
        </div>
      `;
    }

    // AbuseIPDB Results
    if (data.results.abuseipdb) {
      const abuse = data.results.abuseipdb;
      const riskLevel = abuse.score > 75 ? 'Critical' : abuse.score > 50 ? 'High' : abuse.score > 25 ? 'Medium' : 'Low';
      const riskColor = riskLevel === 'Critical' ? '#dc2626' : riskLevel === 'High' ? '#f59e0b' : riskLevel === 'Medium' ? '#eab308' : '#22c55e';
      
      html += `
        <div class="result-card">
          <h3><i class="fas fa-flag"></i> AbuseIPDB</h3>
          <p><strong>Abuse Score:</strong> <span style="color: ${riskColor}; font-weight: bold;">${abuse.score}/100 (${riskLevel} Risk)</span></p>
          <p><strong>Total Reports:</strong> ${abuse.reports || 0}</p>
          ${abuse.score > 50 ? `<p style="color: ${riskColor};"><strong>⚠️ Alert:</strong> This IP has a high abuse score!</p>` : ''}
        </div>
      `;
    }

    // Shodan Results
    if (data.results.shodan) {
      const shodan = data.results.shodan;
      const ports = Array.isArray(shodan.open_ports) ? shodan.open_ports.join(', ') : (shodan.open_ports || 'N/A');
      
      html += `
        <div class="result-card">
          <h3><i class="fas fa-server"></i> Shodan</h3>
          <p><strong>Open Ports:</strong> ${ports}</p>
          <p><strong>Organization:</strong> ${shodan.org || 'N/A'}</p>
          ${shodan.open_ports && shodan.open_ports.length > 5 ? `<p style="color: #f59e0b;"><strong>ℹ️ Note:</strong> Multiple open ports detected</p>` : ''}
        </div>
      `;
    }
  }

  return html;
}