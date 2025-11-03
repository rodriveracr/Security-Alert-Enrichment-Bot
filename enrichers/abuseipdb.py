"""
AbuseIPDB enricher for IP addresses.
"""

import requests
from .base import BaseEnricher


class AbuseIPDBEnricher(BaseEnricher):
    """Enricher for AbuseIPDB API"""
    
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    MAX_AGE_DAYS = 90  # Maximum age for report history
    
    def enrich(self, indicator, indicator_type=None):
        """
        Enrich an IP address using AbuseIPDB
        
        Args:
            indicator (str): IP address to enrich
            indicator_type (str, optional): Type of indicator (not used, only IPs supported)
            
        Returns:
            dict: Enrichment data from AbuseIPDB
        """
        if not self.api_key:
            return {'error': 'AbuseIPDB API key not configured'}
        
        headers = {
            'Key': self.api_key,
            'Accept': 'application/json'
        }
        
        params = {
            'ipAddress': indicator,
            'maxAgeInDays': self.MAX_AGE_DAYS,
            'verbose': ''
        }
        
        try:
            url = f"{self.BASE_URL}/check"
            response = requests.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                result = data.get('data', {})
                
                return {
                    'status': 'success',
                    'abuse_confidence_score': result.get('abuseConfidenceScore', 0),
                    'country_code': result.get('countryCode', 'Unknown'),
                    'usage_type': result.get('usageType', 'Unknown'),
                    'isp': result.get('isp', 'Unknown'),
                    'domain': result.get('domain', 'Unknown'),
                    'total_reports': result.get('totalReports', 0),
                    'is_whitelisted': result.get('isWhitelisted', False),
                    'last_reported': result.get('lastReportedAt', 'Never')
                }
            elif response.status_code == 401:
                return {'error': 'Invalid API key'}
            elif response.status_code == 422:
                return {'error': 'Invalid IP address'}
            else:
                return {'error': f'API error: {response.status_code}'}
                
        except requests.exceptions.Timeout:
            return {'error': 'Request timeout'}
        except requests.exceptions.RequestException as e:
            return {'error': f'Request failed: {str(e)}'}
        except Exception as e:
            return {'error': f'Unexpected error: {str(e)}'}
