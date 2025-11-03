# Security Alert Enrichment Bot

## Propósito

Este proyecto permite enriquecer alertas de seguridad (IPs y dominios) consultando fuentes externas para obtener reputación, reportes y detalles técnicos. El objetivo es facilitar la investigación y priorización de incidentes de seguridad de forma rápida y visual.

## Idea principal

- Recibir una IP o dominio sospechoso.
- Consultar APIs externas (VirusTotal, AbuseIPDB, Shodan) para obtener información relevante.
- Mostrar los resultados en una interfaz web sencilla y visual.
- Permitir el uso de "mock" para pruebas sin consumir APIs reales.

## Ideas secundarias

- Validación de formato de entrada (IP/Dominio).
- Manejo de errores y mensajes claros para el usuario.
- Visualización tipo "cards" para cada fuente de enriquecimiento.
- Backend modular y fácil de extender con nuevos enriquecedores.
- Uso de variables de entorno para las API keys.

## ¿Para qué sirve?

- Para analistas SOC, Blue Team, o cualquier persona que investiga alertas de seguridad.
- Para automatizar la consulta de reputación y detalles técnicos de IPs y dominios.
- Para centralizar y visualizar información de múltiples fuentes en un solo lugar.

## ¿Por qué?

- Reduce el tiempo de investigación manual.
- Evita errores humanos al consultar múltiples fuentes.
- Permite priorizar incidentes con mejor contexto.
- Facilita la integración en flujos de trabajo de seguridad.

## Funcionalidades

- Formulario web para ingresar IP o dominio.
- Validación de formato y mensajes de error amigables.
- Consulta real a APIs externas (VirusTotal, AbuseIPDB, Shodan).
- Visualización de resultados enriquecidos.
- Modo mock para pruebas y demostraciones.
- Backend en Flask con CORS habilitado.
- Frontend en HTML/CSS/JS, fácil de modificar.

## Tecnologías utilizadas

- **Backend:** Python 3.11, Flask, Flask-CORS, requests, python-dotenv
- **Frontend:** HTML5, CSS3, JavaScript
- **APIs externas:** VirusTotal, AbuseIPDB, Shodan
- **DevOps:** VS Code, Windows, PowerShell

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

- Puedes agregar nuevos enriquecedores en `src/enrichers/`.
- Modifica el frontend en `frontend/index.html`, `script.js` y `style.css`.
- Cambia el puerto o IP en el backend y frontend según tu entorno.

## Contribución

- Pull requests y sugerencias son bienvenidas.
- Documenta tus cambios y sigue la estructura modular.

## Licencia

MIT

---

**¡Listo para usar y mejorar!**
