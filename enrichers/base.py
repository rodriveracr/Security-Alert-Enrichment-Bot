"""
Base enricher class that defines the interface for all enrichers.
"""

from abc import ABC, abstractmethod


class BaseEnricher(ABC):
    """Abstract base class for all enrichers"""
    
    def __init__(self, api_key):
        """
        Initialize the enricher with an API key
        
        Args:
            api_key (str): API key for the threat intelligence service
        """
        self.api_key = api_key
        if not self.api_key:
            raise ValueError(f"{self.__class__.__name__} requires an API key")
    
    @abstractmethod
    def enrich(self, indicator, indicator_type=None):
        """
        Enrich the given indicator
        
        Args:
            indicator (str): IP address or domain to enrich
            indicator_type (str, optional): Type of indicator ('ip' or 'domain')
            
        Returns:
            dict: Enrichment data
        """
        pass
