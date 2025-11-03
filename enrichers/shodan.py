"""
Shodan enricher for IP addresses.
"""

import requests
from .base import BaseEnricher


class ShodanEnricher(BaseEnricher):
    """Enricher for Shodan API"""
    
    BASE_URL = "https://api.shodan.io"
    MAX_SERVICES_DISPLAY = 5  # Limit number of services shown
    
    def enrich(self, indicator, indicator_type=None):
        """
        Enrich an IP address using Shodan
        
        Args:
            indicator (str): IP address to enrich
            indicator_type (str, optional): Type of indicator (not used, only IPs supported)
            
        Returns:
            dict: Enrichment data from Shodan
        """
        if not self.api_key:
            return {'error': 'Shodan API key not configured'}
        
        params = {
            'key': self.api_key
        }
        
        try:
            url = f"{self.BASE_URL}/shodan/host/{indicator}"
            response = requests.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                # Extract open ports
                ports = data.get('ports', [])
                
                # Extract services
                services = []
                for item in data.get('data', []):
                    service_info = {
                        'port': item.get('port'),
                        'protocol': item.get('transport', 'unknown'),
                        'service': item.get('product', item.get('_shodan', {}).get('module', 'unknown'))
                    }
                    services.append(service_info)
                
                return {
                    'status': 'success',
                    'organization': data.get('org', 'Unknown'),
                    'operating_system': data.get('os', 'Unknown'),
                    'country': data.get('country_name', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'hostnames': data.get('hostnames', []),
                    'ports': ports,
                    'services': services[:self.MAX_SERVICES_DISPLAY],
                    'last_update': data.get('last_update', 'Unknown')
                }
            elif response.status_code == 401:
                return {'error': 'Invalid API key'}
            elif response.status_code == 404:
                return {'status': 'not_found', 'message': 'No information available'}
            else:
                return {'error': f'API error: {response.status_code}'}
                
        except requests.exceptions.Timeout:
            return {'error': 'Request timeout'}
        except requests.exceptions.RequestException as e:
            return {'error': f'Request failed: {str(e)}'}
        except Exception as e:
            return {'error': f'Unexpected error: {str(e)}'}
