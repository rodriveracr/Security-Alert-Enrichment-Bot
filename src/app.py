

from flask import Flask, request, jsonify
from dotenv import load_dotenv
import os
from enrichers.virustotal import enrich_virustotal
from enrichers.abuseipdb import enrich_abuseipdb
from enrichers.shodan_api import enrich_shodan
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
load_dotenv()

@app.route("/")
def home():
    return "Security Alert Enrichment Bot backend activo. Usa el endpoint /enrich con POST."

@app.route('/enrich', methods=['POST'])
def enrich():
    data = request.get_json()
    input_type = data.get('type')
    value = data.get('value')
    results = {}

    if input_type == 'ip' or input_type == 'domain':
        results['virustotal'] = enrich_virustotal(value)
        results['abuseipdb'] = enrich_abuseipdb(value) if input_type == 'ip' else None
        results['shodan'] = enrich_shodan(value) if input_type == 'ip' else None
        return jsonify({
            'input_type': input_type,
            'value': value,
            'results': results
        })
    else:
        return jsonify({'error': 'Tipo de entrada inválido'}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
