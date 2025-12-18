

from flask import Flask, request, jsonify, send_from_directory
from dotenv import load_dotenv
import os
from pathlib import Path
from src.enrichers.virustotal import vt_lookup
from src.enrichers.abuseipdb import abuse_lookup
from src.enrichers.shodan_api import shodan_lookup
from flask_cors import CORS

# Obtener la ruta base del proyecto
BASE_DIR = Path(__file__).resolve().parents[1]
FRONTEND_DIR = BASE_DIR / "frontend"

app = Flask(__name__, static_folder=str(FRONTEND_DIR), static_url_path='')
CORS(app)
load_dotenv()

@app.route("/")
def home():
    return send_from_directory(str(FRONTEND_DIR), 'index.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory(str(FRONTEND_DIR), path)

@app.route('/enrich', methods=['POST'])
def enrich():
    data = request.get_json()
    input_type = data.get('type')
    value = data.get('value')
    results = {}

    if input_type == 'ip' or input_type == 'domain':
        results['virustotal'] = vt_lookup(value)
        results['abuseipdb'] = abuse_lookup(value) if input_type == 'ip' else None
        results['shodan'] = shodan_lookup(value) if input_type == 'ip' else None
        return jsonify({
            'input_type': input_type,
            'value': value,
            'results': results
        })
    else:
        return jsonify({'error': 'Tipo de entrada inválido'}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
