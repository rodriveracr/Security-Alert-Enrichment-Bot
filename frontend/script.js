document.getElementById('enrich-form').addEventListener('submit', async function(e) {
  e.preventDefault();
  const type = document.getElementById('input-type').value;
  const value = document.getElementById('input-value').value.trim();
  const resultDiv = document.getElementById('result');
  resultDiv.textContent = '';

  // Validación básica
  if (!value) {
    resultDiv.textContent = 'Por favor ingresa un valor.';
    return;
  }
  // Permitir mock sin validar formato
    const BACKEND_URL = 'http://127.0.0.1:5001/enrich'; // Cambia aquí si usas otra IP/puerto
    if (value.toLowerCase() !== "mock") {
    if (type === 'ip' && !/^([0-9]{1,3}\.){3}[0-9]{1,3}$/.test(value)) {
      resultDiv.textContent = 'Formato de IP inválido.';
      return;
    }
    if (type === 'domain' && !/^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/.test(value)) {
      resultDiv.textContent = 'Formato de dominio inválido.';
      return;
    }
  }

  resultDiv.textContent = 'Consultando...';
  try {
    // Modo mock: si el valor es "mock", mostrar datos simulados
    if (value.toLowerCase() === "mock") {
      const mockData = {
        input_type: type,
        value: value,
        results: {
          virustotal: { detected_urls: 2, reputation: "malicious" },
          abuseipdb: type === "ip" ? { score: 85, reports: 12 } : null,
          shodan: type === "ip" ? { open_ports: [22, 80], org: "Mock ISP" } : null
        }
      };
      resultDiv.innerHTML = renderResults(mockData, true);
      return;
    }
    // ...consulta real...
      const response = await fetch(BACKEND_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type, value })
    });
    if (!response.ok) {
        let errorText = await response.text();
        throw new Error('Error en la consulta: ' + errorText);
    }
    const data = await response.json();
    // Formatear resultado visual
    if (data && typeof data === 'object') {
      resultDiv.innerHTML = renderResults(data, false);
    } else {
      resultDiv.textContent = 'Sin datos para mostrar.';
    }
  } catch (err) {
      if (err.name === 'TypeError' && err.message.includes('Failed to fetch')) {
        resultDiv.textContent = 'Error de red o CORS: No se pudo conectar al backend. Verifica que el backend esté activo y accesible en ' + BACKEND_URL;
      } else {
        resultDiv.textContent = 'Error: ' + err.message;
      }
  }
});

// Renderizador visual de resultados enriquecidos
function renderResults(data, isMock) {
  let html = `<b>Resultado${isMock ? ' (Mock)' : ''}:</b><br>`;
  html += `<div class="result-card"><b>Tipo:</b> ${data.input_type}<br><b>Valor:</b> ${data.value}</div>`;
  if (data.results) {
    if (data.results.virustotal) {
      html += `<div class="result-card"><b>VirusTotal</b><br>`;
      html += `<b>Detected URLs:</b> ${data.results.virustotal.detected_urls}<br>`;
      html += `<b>Reputation:</b> ${data.results.virustotal.reputation}</div>`;
    }
    if (data.results.abuseipdb) {
      html += `<div class="result-card"><b>AbuseIPDB</b><br>`;
      html += `<b>Score:</b> ${data.results.abuseipdb.score}<br>`;
      html += `<b>Reports:</b> ${data.results.abuseipdb.reports}</div>`;
    }
    if (data.results.shodan) {
      html += `<div class="result-card"><b>Shodan</b><br>`;
      html += `<b>Open Ports:</b> ${Array.isArray(data.results.shodan.open_ports) ? data.results.shodan.open_ports.join(', ') : ''}<br>`;
      html += `<b>Org:</b> ${data.results.shodan.org}</div>`;
    }
  }
  return html;
}