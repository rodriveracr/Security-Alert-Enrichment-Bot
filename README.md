
# Security Alert Enrichment Bot

## Propósito

Este proyecto permite enriquecer alertas de seguridad (IPs y dominios) consultando fuentes externas para obtener reputación, reportes y detalles técnicos. El objetivo es facilitar la investigación y priorización de incidentes de seguridad de forma rápida y visual.

## Idea principal


## Ideas secundarias


## ¿Para qué sirve?


## ¿Por qué?


## Funcionalidades


## Tecnologías utilizadas


## Estructura del proyecto

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

## Instalación y uso

1. Clona el repositorio:

   ```bash
   git clone https://github.com/tuusuario/Security-Alert-Enrichment-Bot.git
   cd Security-Alert-Enrichment-Bot
   ```

2. Instala dependencias:

   ```bash
   python -m venv venv
   venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. Configura tus API keys en el archivo `.env`:

   ```env
   VT_API_KEY=tu_key_virustotal
   ABUSEIPDB_API_KEY=tu_key_abuseipdb
   SHODAN_API_KEY=tu_key_shodan
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

6. Abre el navegador en `http://localhost:8080` y usa el formulario.

## Personalización


## Contribución


## Licencia

MIT


**¡Listo para usar y mejorar!**
=======
# Security-Alert-Enrichment-Bot
Security Alert Enrichment Bot: Enriches security alerts (IP/domain) using external APIs (VirusTotal, AbuseIPDB, Shodan) for rapid investigation and prioritization. Includes a Flask backend and HTML/JS frontend.
>>>>>>> 0702c99452dca4f5223d5724a6031330dbe4da3a
