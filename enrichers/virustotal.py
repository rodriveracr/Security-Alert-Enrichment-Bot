"""
VirusTotal enricher for IP addresses and domains.
"""

import requests
from .base import BaseEnricher


class VirusTotalEnricher(BaseEnricher):
    """Enricher for VirusTotal API"""
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def enrich(self, indicator, indicator_type):
        """
        Enrich an IP address or domain using VirusTotal
        
        Args:
            indicator (str): IP address or domain to enrich
            indicator_type (str): Type of indicator ('ip' or 'domain')
            
        Returns:
            dict: Enrichment data from VirusTotal
        """
        if not self.api_key:
            return {'error': 'VirusTotal API key not configured'}
        
        headers = {
            'x-apikey': self.api_key
        }
        
        try:
            if indicator_type == 'ip':
                url = f"{self.BASE_URL}/ip_addresses/{indicator}"
            elif indicator_type == 'domain':
                url = f"{self.BASE_URL}/domains/{indicator}"
            else:
                return {'error': f'Unsupported indicator type: {indicator_type}'}
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                last_analysis = attributes.get('last_analysis_stats', {})
                
                return {
                    'status': 'success',
                    'malicious': last_analysis.get('malicious', 0),
                    'suspicious': last_analysis.get('suspicious', 0),
                    'harmless': last_analysis.get('harmless', 0),
                    'undetected': last_analysis.get('undetected', 0),
                    'reputation': attributes.get('reputation', 0),
                    'country': attributes.get('country', 'Unknown'),
                    'as_owner': attributes.get('as_owner', 'Unknown')
                }
            elif response.status_code == 404:
                return {'status': 'not_found', 'message': 'Indicator not found in VirusTotal'}
            elif response.status_code == 401:
                return {'error': 'Invalid API key'}
            else:
                return {'error': f'API error: {response.status_code}'}
                
        except requests.exceptions.Timeout:
            return {'error': 'Request timeout'}
        except requests.exceptions.RequestException as e:
            return {'error': f'Request failed: {str(e)}'}
        except Exception as e:
            return {'error': f'Unexpected error: {str(e)}'}
