# Security Alert Enrichment Bot

A powerful web application that enriches security alerts by gathering threat intelligence from multiple sources. The tool provides instant analysis of IP addresses and domains using VirusTotal, AbuseIPDB, and Shodan APIs.

## Features

- 🔍 **Multi-Source Enrichment**: Aggregates data from VirusTotal, AbuseIPDB, and Shodan
- 🎯 **IP & Domain Support**: Analyze both IP addresses and domain names
- 🛡️ **Modular Architecture**: Easy-to-extend enricher system
- 🌐 **User-Friendly Interface**: Clean, responsive web UI
- 🔐 **Secure Configuration**: API keys managed via environment variables
- ⚡ **Fast & Efficient**: RESTful API with CORS support

## Architecture

```
Security-Alert-Enrichment-Bot/
├── app.py                  # Flask backend application
├── enrichers/              # Modular enricher classes
│   ├── __init__.py
│   ├── base.py            # Base enricher interface
│   ├── virustotal.py      # VirusTotal enricher
│   ├── abuseipdb.py       # AbuseIPDB enricher
│   └── shodan.py          # Shodan enricher
├── static/                 # Frontend assets
│   ├── index.html         # Main HTML page
│   ├── styles.css         # Styling
│   └── app.js             # Frontend JavaScript
├── requirements.txt        # Python dependencies
├── .env.example           # Environment variable template
└── README.md              # This file
```

## Prerequisites

- Python 3.8 or higher
- API keys from:
  - [VirusTotal](https://www.virustotal.com/gui/my-apikey)
  - [AbuseIPDB](https://www.abuseipdb.com/account/api)
  - [Shodan](https://account.shodan.io/)

## Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/rodriveracr/Security-Alert-Enrichment-Bot.git
   cd Security-Alert-Enrichment-Bot
   ```

2. **Create a virtual environment** (recommended)
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure API keys**
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` and add your API keys:
   ```
   VIRUSTOTAL_API_KEY=your_actual_virustotal_key
   ABUSEIPDB_API_KEY=your_actual_abuseipdb_key
   SHODAN_API_KEY=your_actual_shodan_key
   ```

## Usage

1. **Start the Flask server**
   ```bash
   python app.py
   ```

2. **Access the web interface**
   
   Open your browser and navigate to:
   ```
   http://localhost:5000
   ```

3. **Enrich a security alert**
   - Enter an IP address (e.g., `8.8.8.8`) or domain (e.g., `example.com`)
   - Select the indicator type
   - Click "Enrich Alert"
   - View comprehensive threat intelligence data

## API Endpoints

### `POST /api/enrich`
Enrich an IP address or domain with threat intelligence.

**Request Body:**
```json
{
  "indicator": "8.8.8.8",
  "type": "ip"
}
```

**Response:**
```json
{
  "indicator": "8.8.8.8",
  "type": "ip",
  "results": {
    "virustotal": { ... },
    "abuseipdb": { ... },
    "shodan": { ... }
  }
}
```

### `GET /api/health`
Check API health and configuration status.

**Response:**
```json
{
  "status": "healthy",
  "apis": {
    "virustotal": "configured",
    "abuseipdb": "configured",
    "shodan": "configured"
  }
}
```

## Enricher Details

### VirusTotal Enricher
- Provides detection statistics from 70+ antivirus engines
- Shows reputation scores
- Includes geolocation and AS information
- Works for both IPs and domains

### AbuseIPDB Enricher
- Reports abuse confidence scores (0-100%)
- Shows number of abuse reports
- Provides ISP and geolocation data
- IP addresses only

### Shodan Enricher
- Lists open ports and services
- Shows organization and ISP information
- Provides operating system detection
- Includes hostname information
- IP addresses only

## Extending the Bot

To add a new enricher:

1. Create a new file in the `enrichers/` directory
2. Inherit from `BaseEnricher`
3. Implement the `enrich()` method
4. Import and initialize in `app.py`
5. Update the `/api/enrich` endpoint to call your enricher

Example:
```python
from enrichers.base import BaseEnricher

class MyEnricher(BaseEnricher):
    def enrich(self, indicator, indicator_type=None):
        # Your enrichment logic here
        return {"data": "enriched"}
```

## Security Considerations

- Never commit the `.env` file with actual API keys
- Use environment variables for all sensitive data
- API keys have rate limits - implement caching if needed
- Consider implementing authentication for production use
- Run behind a reverse proxy (nginx) in production

## Troubleshooting

**Issue**: `Invalid API key` errors
- Verify your API keys are correct in `.env`
- Check that you've activated the keys on the respective platforms

**Issue**: `Request timeout` errors
- Check your internet connection
- API services may be temporarily unavailable
- Consider increasing timeout values in enricher files

**Issue**: `Module not found` errors
- Ensure you've activated the virtual environment
- Run `pip install -r requirements.txt` again

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is open source and available under the MIT License.

## Disclaimer

This tool is for security research and authorized investigation purposes only. Always ensure you have proper authorization before investigating IP addresses or domains. Respect API rate limits and terms of service.
