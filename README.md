# Security Alert Enrichment Bot

## Espanol

### Proposito

Este proyecto enriquece alertas de seguridad, como IPs y dominios, consultando fuentes externas para obtener reputacion, reportes y detalles tecnicos. El objetivo es acelerar la investigacion y ayudar a priorizar incidentes de forma visual.

### Que hace

- Recibe una IP o dominio sospechoso.
- Consulta APIs externas como VirusTotal, AbuseIPDB y Shodan.
- Muestra los resultados en una interfaz web simple y visual.
- Incluye modo mock para probar sin consumir APIs reales.

### Funcionalidades

- Validacion de entrada para IP y dominio.
- Mensajes de error claros.
- Vista tipo tarjeta para cada fuente de enriquecimiento.
- Backend modular y facil de extender.
- Uso de variables de entorno para las claves de API.

### Casos de uso

- Analistas SOC, equipos Blue Team o cualquier persona que investigue alertas de seguridad.
- Automatizar consultas de reputacion y contexto tecnico para IPs y dominios.
- Centralizar y visualizar informacion de varias fuentes en un solo lugar.

### Tecnologias

- Backend: Python 3.11, Flask, Flask-CORS, requests, python-dotenv
- Frontend: HTML5, CSS3, JavaScript
- APIs externas: VirusTotal, AbuseIPDB, Shodan
- Entorno: VS Code, Windows, PowerShell

### Estructura del proyecto

```bash
Security Alert Enrichment Bot/
├── src/
│   ├── app.py
│   ├── main.py
│   ├── enrichers/
│   └── ...
├── frontend/
│   ├── index.html
│   ├── script.js
│   └── style.css
├── data/
├── reports/
├── requirements.txt
├── dev-requirements.txt
└── README.md
```

### Instalacion y uso

1. Clona el repositorio:

   ```bash
   git clone https://github.com/rodriveracr/Security-Alert-Enrichment-Bot.git
   cd Security-Alert-Enrichment-Bot
   ```

2. Crea el entorno e instala dependencias:

   ```bash
   python -m venv venv
   venv\Scripts\activate
   pip install -r requirements.txt
   ```

   If you want to run tests or linting, also install the development dependencies:

   ```bash
   pip install -r dev-requirements.txt
   ```

3. Configura tus claves en `.env`:

   ```env
   VT_API_KEY=your_virustotal_api_key_here
   ABUSEIPDB_KEY=your_abuseipdb_api_key_here
   SHODAN_KEY=your_shodan_api_key_here
   ```

4. Inicia el backend:

   ```bash
   python src/app.py
   ```

5. Inicia el frontend:

   ```bash
   cd frontend
   python -m http.server 8080
   ```

6. Abre `http://localhost:8080` en tu navegador.

### Personalizacion

- Agrega nuevos enrichers en `src/enrichers/`.
- Modifica la interfaz en `frontend/index.html`, `frontend/script.js` y `frontend/style.css`.
- Ajusta puertos o rutas segun lo necesites.

### Contribucion

- Se aceptan pull requests y sugerencias.
- Mantén la estructura modular y documenta los cambios.

### Licencia

MIT

## English

### Purpose

This project enriches security alerts, such as IPs and domains, by querying external sources to collect reputation, reports, and technical details. The goal is to speed up investigations and help teams prioritize incidents visually.

### What it does

- Accepts a suspicious IP or domain.
- Queries external APIs such as VirusTotal, AbuseIPDB, and Shodan.
- Displays results in a simple, visual web interface.
- Includes a mock mode for testing without consuming real APIs.

### Features

- Input validation for IPs and domains.
- Clear error messages.
- Card-style visualization for each enrichment source.
- Modular backend that is easy to extend.
- Environment variables for API keys.

### Use cases

- SOC analysts, Blue Teams, or anyone investigating security alerts.
- Automating reputation and technical context checks for IPs and domains.
- Centralizing and visualizing information from multiple sources in one place.

### Technologies

- Backend: Python 3.11, Flask, Flask-CORS, requests, python-dotenv
- Frontend: HTML5, CSS3, JavaScript
- External APIs: VirusTotal, AbuseIPDB, Shodan
- Environment: VS Code, Windows, PowerShell

### Project structure

```bash
Security Alert Enrichment Bot/
├── src/
│   ├── app.py
│   ├── main.py
│   ├── enrichers/
│   └── ...
├── frontend/
│   ├── index.html
│   ├── script.js
│   └── style.css
├── data/
├── reports/
├── requirements.txt
├── dev-requirements.txt
└── README.md
```

### Installation and usage

1. Clone the repository:

   ```bash
   git clone https://github.com/rodriveracr/Security-Alert-Enrichment-Bot.git
   cd Security-Alert-Enrichment-Bot
   ```

2. Create the virtual environment and install dependencies:

   ```bash
   python -m venv venv
   venv\Scripts\activate
   pip install -r requirements.txt
   ```

   If you want to run tests or linting, also install the development dependencies:

   ```bash
   pip install -r dev-requirements.txt
   ```

3. Set your API keys in `.env`:

   ```env
   VT_API_KEY=your_virustotal_api_key_here
   ABUSEIPDB_KEY=your_abuseipdb_api_key_here
   SHODAN_KEY=your_shodan_api_key_here
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

6. Open `http://localhost:8080` in your browser.

### Customization

- Add new enrichers in `src/enrichers/`.
- Update the UI in `frontend/index.html`, `frontend/script.js`, and `frontend/style.css`.
- Adjust ports or paths as needed.

### Contributing

- Pull requests and suggestions are welcome.
- Keep the modular structure and document your changes.

### License

MIT
