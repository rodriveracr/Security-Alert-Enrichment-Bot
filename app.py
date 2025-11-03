"""
Flask Backend for Security Alert Enrichment Bot
Provides API endpoints to enrich security alerts using multiple threat intelligence sources.
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
from dotenv import load_dotenv
from enrichers.virustotal import VirusTotalEnricher
from enrichers.abuseipdb import AbuseIPDBEnricher
from enrichers.shodan import ShodanEnricher

# Load environment variables
load_dotenv()

app = Flask(__name__, static_folder='static')
CORS(app)

# Initialize enrichers
vt_enricher = VirusTotalEnricher(os.getenv('VIRUSTOTAL_API_KEY'))
abuseipdb_enricher = AbuseIPDBEnricher(os.getenv('ABUSEIPDB_API_KEY'))
shodan_enricher = ShodanEnricher(os.getenv('SHODAN_API_KEY'))


@app.route('/')
def index():
    """Serve the main HTML page"""
    return send_from_directory('static', 'index.html')


@app.route('/<path:filename>')
def serve_static(filename):
    """Serve static files"""
    return send_from_directory('static', filename)


@app.route('/api/enrich', methods=['POST'])
def enrich_alert():
    """
    Enrich a security alert (IP address or domain)
    
    Request body:
    {
        "indicator": "8.8.8.8" or "example.com",
        "type": "ip" or "domain"
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'indicator' not in data or 'type' not in data:
            return jsonify({'error': 'Missing required fields: indicator and type'}), 400
        
        indicator = data['indicator']
        indicator_type = data['type']
        
        if indicator_type not in ['ip', 'domain']:
            return jsonify({'error': 'Type must be either "ip" or "domain"'}), 400
        
        # Collect enrichment data from all sources
        enrichment_data = {
            'indicator': indicator,
            'type': indicator_type,
            'results': {}
        }
        
        # VirusTotal enrichment
        try:
            vt_data = vt_enricher.enrich(indicator, indicator_type)
            enrichment_data['results']['virustotal'] = vt_data
        except Exception as e:
            enrichment_data['results']['virustotal'] = {'error': str(e)}
        
        # AbuseIPDB enrichment (only for IPs)
        if indicator_type == 'ip':
            try:
                abuseipdb_data = abuseipdb_enricher.enrich(indicator)
                enrichment_data['results']['abuseipdb'] = abuseipdb_data
            except Exception as e:
                enrichment_data['results']['abuseipdb'] = {'error': str(e)}
        
        # Shodan enrichment (only for IPs)
        if indicator_type == 'ip':
            try:
                shodan_data = shodan_enricher.enrich(indicator)
                enrichment_data['results']['shodan'] = shodan_data
            except Exception as e:
                enrichment_data['results']['shodan'] = {'error': str(e)}
        
        return jsonify(enrichment_data), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'apis': {
            'virustotal': 'configured' if os.getenv('VIRUSTOTAL_API_KEY') else 'not configured',
            'abuseipdb': 'configured' if os.getenv('ABUSEIPDB_API_KEY') else 'not configured',
            'shodan': 'configured' if os.getenv('SHODAN_API_KEY') else 'not configured'
        }
    }), 200


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)
