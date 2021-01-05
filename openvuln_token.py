import requests
from requests.auth import HTTPBasicAuth
import os
KEY = os.getenv('KEY')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')

def get_auth_token():
    """
    Building out Auth request. Using requests.post to make a call to the Auth Endpoint
    """
    url = 'https://cloudsso.cisco.com/as/token.oauth2?grant_type=client_credentials'       # Endpoint URL
    resp = requests.post(url, auth=HTTPBasicAuth(KEY, CLIENT_SECRET))  # Make the POST Request
    access_token = resp.json()['access_token']    # Retrieve the Token from the returned JSON
    print("Token Retrieved: Bearer {}".format(access_token))  # Print out the Token
    return access_token    # Create a return statement to send the token back for later use

if __name__ == "__main__":
    get_auth_token()
