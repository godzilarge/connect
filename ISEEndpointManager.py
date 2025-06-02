#!/usr/bin/env python3
"""
Script to delete an endpoint from Cisco ISE using ERS API
"""

import requests
import urllib3
import sys
import json
import base64

# Disable SSL warnings (use only in test environments)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ISEEndpointManager:
    def __init__(self, ise_server, auth_token=None, username=None, password=None, verify_ssl=False):
        """
        Initialize ISE connection parameters
        
        Args:
            ise_server (str): ISE server FQDN or IP
            auth_token (str): Base64 encoded Basic Auth token (username:password)
            username (str): ISE admin username (alternative to auth_token)
            password (str): ISE admin password (alternative to auth_token)
            verify_ssl (bool): Whether to verify SSL certificates
        """
        self.ise_server = ise_server
        self.verify_ssl = verify_ssl
        self.base_url = f"https://{ise_server}:9060/ers/config/endpoint"
        
        # Set up session with authentication
        self.session = requests.Session()
        
        if auth_token:
            # Use provided Basic Auth token
            self.session.headers.update({
                'Authorization': f'Basic {auth_token}',
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            })
        elif username and password:
            # Generate Basic Auth token from username/password
            credentials = f"{username}:{password}"
            encoded_credentials = base64.b64encode(credentials.encode()).decode()
            self.session.headers.update({
                'Authorization': f'Basic {encoded_credentials}',
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            })
        else:
            raise ValueError("Either auth_token or both username and password must be provided")
        
        self.session.verify = verify_ssl

    def get_endpoint_by_mac(self, mac_address):
        """
        Get endpoint details by MAC address
        
        Args:
            mac_address (str): MAC address of the endpoint
            
        Returns:
            dict: Endpoint details or None if not found
        """
        try:
            # Format MAC address (remove separators and convert to uppercase)
            formatted_mac = mac_address.replace(':', '').replace('-', '').replace('.', '').upper()
            
            # Search for endpoint by MAC address
            search_url = f"{self.base_url}?filter=mac.EQ.{formatted_mac}"
            response = self.session.get(search_url)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('SearchResult', {}).get('total', 0) > 0:
                    return data['SearchResult']['resources'][0]
                else:
                    print(f"Endpoint with MAC {mac_address} not found")
                    return None
            else:
                print(f"Error searching for endpoint: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            print(f"Error getting endpoint: {str(e)}")
            return None

    def delete_endpoint_by_id(self, endpoint_id):
        """
        Delete endpoint by ID
        
        Args:
            endpoint_id (str): ISE endpoint ID
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            delete_url = f"{self.base_url}/{endpoint_id}"
            response = self.session.delete(delete_url)
            
            if response.status_code == 204:
                print(f"Endpoint {endpoint_id} deleted successfully")
                return True
            else:
                print(f"Error deleting endpoint: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            print(f"Error deleting endpoint: {str(e)}")
            return False

    def delete_endpoint_by_mac(self, mac_address):
        """
        Delete endpoint by MAC address
        
        Args:
            mac_address (str): MAC address of the endpoint to delete
            
        Returns:
            bool: True if successful, False otherwise
        """
        # First, find the endpoint
        endpoint = self.get_endpoint_by_mac(mac_address)
        if not endpoint:
            return False
        
        # Extract the endpoint ID from the URL
        endpoint_id = endpoint['id']
        
        # Delete the endpoint
        return self.delete_endpoint_by_id(endpoint_id)

    def list_all_endpoints(self, limit=20):
        """
        List all endpoints (for reference)
        
        Args:
            limit (int): Maximum number of endpoints to retrieve
            
        Returns:
            list: List of endpoints
        """
        try:
            list_url = f"{self.base_url}?size={limit}"
            response = self.session.get(list_url)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('SearchResult', {}).get('resources', [])
            else:
                print(f"Error listing endpoints: {response.status_code} - {response.text}")
                return []
                
        except Exception as e:
            print(f"Error listing endpoints: {str(e)}")
            return []

def main():
    """
    Main function - example usage
    """
    # Configuration - UPDATE THESE VALUES
    ISE_SERVER = "your-ise-server.domain.com"  # ISE FQDN or IP
    
    # Option 1: Use pre-encoded Basic Auth token
    AUTH_TOKEN = "eW91ci1lcnMtYWRtaW46eW91ci1wYXNzd29yZA=="  # Base64 encoded "username:password"
    
    # Option 2: Use username/password (will be encoded automatically)
    # USERNAME = "your-ers-admin"
    # PASSWORD = "your-password"
    
    # MAC address of endpoint to delete
    MAC_TO_DELETE = "00:11:22:33:44:55"  # Update with actual MAC address
    
    # Create ISE manager instance using auth token
    ise_manager = ISEEndpointManager(ISE_SERVER, auth_token=AUTH_TOKEN)
    
    # Alternative: Create using username/password
    # ise_manager = ISEEndpointManager(ISE_SERVER, username=USERNAME, password=PASSWORD)
    
    # Delete by MAC address
    print(f"Attempting to delete endpoint with MAC: {MAC_TO_DELETE}")
    success = ise_manager.delete_endpoint_by_mac(MAC_TO_DELETE)
    
    if success:
        print("Endpoint deleted successfully!")
    else:
        print("Failed to delete endpoint")
    
    # Option: List endpoints first, then delete by ID
    # print("Listing first 10 endpoints:")
    # endpoints = ise_manager.list_all_endpoints(10)
    # for endpoint in endpoints:
    #     print(f"ID: {endpoint['id']}, Name: {endpoint['name']}")
    
    # To delete by ID directly:
    # endpoint_id = "your-endpoint-id-here"
    # ise_manager.delete_endpoint_by_id(endpoint_id)

def generate_auth_token(username, password):
    """
    Helper function to generate Basic Auth token
    
    Args:
        username (str): Username
        password (str): Password
        
    Returns:
        str: Base64 encoded Basic Auth token
    """
    credentials = f"{username}:{password}"
    return base64.b64encode(credentials.encode()).decode()

# Example usage to generate token:
# print("Generated token:", generate_auth_token("admin", "password123"))

if __name__ == "__main__":
    main()
