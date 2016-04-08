#!/usr/bin/python

# This module exposes methods that can be used to query AzureKeyVault using REST API
import requests
import os
import sys
import ConfigParser

# Azure KeyVault manager class
class AzureKeyVaultManager(object):

    section_name="KeyVaultSection"

    # Constructor
    def __init__(self, fileName="private.properties"):
        prop_file=os.path.dirname(os.path.realpath(sys.argv[0])) + "/" + fileName
        config = ConfigParser.RawConfigParser()
        config.read(prop_file)
        self.client_id=config.get(self.section_name,'client.id')
        self.client_secret=config.get(self.section_name,'client.secret')
        self.tenant_id=config.get(self.section_name,'tenant.id')
        self.resource=config.get(self.section_name,'resource')
        self.key_vault=config.get(self.section_name,'key.vault')

    # Authenticate
    def initialize(self):
        if self.client_id and self.client_secret and self.tenant_id and self.resource and self.key_vault:
            print "Got all the properties from file "
            token_url="https://login.windows.net/{0}/oauth2/token".format(self.tenant_id)
            payload = {'client_id':self.client_id, 'client_secret':self.client_secret, 'resource':self.resource, 'grant_type':'client_credentials'}
            response=requests.post(token_url, data=payload).json()
            self.access_token=response['access_token']
        else:
            raise ValueError("Couldn't get the key vault properties from properties file")

    # Get secret from a specific keyvault
    def getSecretFromKeyVault(self, secretName, keyVault=None):
        if keyVault is None:
            keyVault=self.key_vault

        endpoint = 'https://{0}.vault.azure.net/secrets/{1}?api-version=2015-06-01'.format(keyVault, secretName)
        headers = {"Authorization": 'Bearer ' + self.access_token}
        response = requests.get(endpoint,headers=headers).json()

        if 'value' in response:
            return response['value']
        else:
            raise ValueError("Value not found in response")