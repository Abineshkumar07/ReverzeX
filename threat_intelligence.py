import requests
import logging


class ThreatIntelligence:
    def __init__(self):
        self.api_key = "dc8e63c9afd662789c40128eb0f5bc1cc0c93bd7b55713b046bc8f0df844a2ba"
        if not self.api_key:
            raise ValueError("API key is missing.")

    def query_service(self, file_hash):
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {
            "x-apikey": self.api_key
        }
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                print(f"File '{file_hash}' not found in Threat Intelligence Service.")
                logging.warning(f"File '{file_hash}' not found in Threat Intelligence Service.")
                return None
            else:
                print(f"Error querying Threat Intelligence Service: {response.status_code} {response.text}")
                logging.error(f"Error querying Threat Intelligence Service: {response.status_code} {response.text}")
                return None
        except requests.RequestException as e:
            print(f"An error occurred: {e}")
            logging.error(f"An error occurred: {e}")
            return None
