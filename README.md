# Security Alert Enrichment Bot

## Purpose

This project enriches security alerts (IPs and domains) by querying external sources to obtain reputation, reports, and technical details. The goal is to facilitate rapid and visual investigation and prioritization of security incidents.

## Main Idea

- Receive a suspicious IP or domain.
- Query external APIs (VirusTotal, AbuseIPDB, Shodan) for relevant information.
- Display results in a simple and visual web interface.
- Allow "mock" mode for testing without consuming real APIs.

## Secondary Ideas

- Input format validation (IP/Domain).
- Error handling and clear user messages.
- Card-style visualization for each enrichment source.
- Modular backend, easy to extend with new enrichers.
- Use environment variables for API keys.

## Use Cases

- For SOC analysts, Blue Team, or anyone investigating security alerts.
- To automate reputation and technical detail queries for IPs and domains.
- To centralize and visualize information from multiple sources in one place.

## Why?

- Reduces manual investigation time.
- Avoids human errors when consulting multiple sources.
- Enables better incident prioritization with more context.
- Facilitates integration into security workflows.

## Features

- Web form to enter IP or domain.
- Input validation and friendly error messages.
- Real queries to external APIs (VirusTotal, AbuseIPDB, Shodan).
- Enriched results visualization.
- Mock mode for testing and demos.
- Flask backend with CORS enabled.
- HTML/CSS/JS frontend, easy to modify.

## Technologies Used

- **Backend:** Python 3.11, Flask, Flask-CORS, requests, python-dotenv
- **Frontend:** HTML5, CSS3, JavaScript
- **External APIs:** VirusTotal, AbuseIPDB, Shodan
- **DevOps:** VS Code, Windows, PowerShell

## Project Structure

```bash
Security Alert Enrichment Bot/
├── src/
│   ├── app.py
│   ├── enrichers/
│   └── ...
├── frontend/
│   ├── index.html
│   ├── script.js
│   └── style.css
├── .env
├── requirements.txt
└── README.md
```

## Installation & Usage

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/Security-Alert-Enrichment-Bot.git
   cd Security-Alert-Enrichment-Bot
   ```

2. Install dependencies:

   ```bash
   python -m venv venv
   venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. Set your API keys in the `.env` file:

   ```env
   VT_API_KEY=your_virustotal_key
   ABUSEIPDB_API_KEY=your_abuseipdb_key
   SHODAN_API_KEY=your_shodan_key
   ```

4. Start the backend:

   ```bash
   python src/app.py
   ```

5. Start the frontend:

   ```bash
   cd frontend
   python -m http.server 8080
   ```

6. Open your browser at `http://localhost:8080` and use the form.

## Customization

- Add new enrichers in `src/enrichers/`.
- Modify the frontend in `frontend/index.html`, `script.js`, and `style.css`.
- Change the port or IP in the backend and frontend as needed.

## Contribution

- Pull requests and suggestions are welcome.
- Document your changes and follow the modular structure.

## License

MIT

---
**Ready to use and improve!**
