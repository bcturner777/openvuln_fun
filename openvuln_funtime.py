import requests
from pick import pick
from requests.auth import HTTPBasicAuth
import os
KEY = os.getenv('KEY')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')

def pick_version():
    title = 'Please pick a currently used ios-xe version'
    options = ['17.3.1', '16.12.1', '16.9.1']
    option, index = pick(options, title)
    version = option
    return(version)

def get_vuln_iosxe():
    """
    Building out function to retrieve list of devices. Using requests.get to make a call to the network device Endpoint
    """
    access_token = get_auth_token() # Get Token
    version = pick_version()
    url = "https://api.cisco.com/security/advisories/iosxe?version=" + version
    hdr = {'Authorization': access_token, 'content-type' : 'application/json'}
    resp = requests.get(url, headers=hdr)  # Make the Get Request
    vuln_data = resp.json()
    print_vuln(vuln_data)

def get_auth_token():
    """
    Building out Auth request. Using requests.post to make a call to the Auth Endpoint
    """
    url = 'https://cloudsso.cisco.com/as/token.oauth2?grant_type=client_credentials'       # Endpoint URL
    resp = requests.post(url, auth=HTTPBasicAuth(KEY, CLIENT_SECRET))  # Make the POST Request
    access_token = resp.json()['access_token']
    access_token = 'Bearer ' + access_token    # Retrieve the Token from the returned JSON
    #print("Token Retrieved: {}".format(access_token))  # Print out the Token
    return access_token    # Create a return statement to send the token back for later use

def print_vuln(vuln_json):
    for vuln in vuln_json['advisories']:
        print('\n')
        print(vuln['advisoryTitle'])
        print('Impact Rating = ', vuln['sir'])
        print('Bug IDs = ', vuln['bugIDs'])

if __name__ == "__main__":
    get_vuln_iosxe()
