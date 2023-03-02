import requests, json, pickle, ast
import os

import sys
sys.path.append("..") # Adds higher directory to python modules path.
from config.config import *
from helper import login
#from PyLog import *
from loguru import logger
import re


#dbgPrint = PyLog(__name__, level=logging.INFO)

logger.add(f"./logs/{__name__}.log", backtrace=True, diagnose=True, filter="MSGraphApi")
dbgPrint = logger
#dbgPrint.disable(__name__)

class MSGraphApi:
    def __init__(self, email=None, **kwargs):
        self._session = requests.Session()
#        self.auth_page = 'https://portal.azure.com/api/DelegationToken'
        self.auth_page = 'https://endpoint.microsoft.com/api/DelegationToken'
#        self.auth_page = 'https://portal.azure.com/api/DelegationToken?feature.cacheextensionapp=true&feature.internalgraphapiversion=true&feature.tokencaching=true'
        self.headers = kwargs.get('headers', {'content-type' : 'application/json'})
        self.cookies = kwargs.get('cookies', {})
#        self.auth_folder = kwargs.get('output', "")
        self.body = kwargs.get('json', '')

        self.users_auth = ""
        self.mfa_stats_auth = ""
        self.devices_auth = ""
        self.email = email

        self._portalAuthorization = {}
        self._altPortalAuthorization = {}
        self._session.cookies.update(self.cookies)
        self._session.headers.update(self.headers)
        if self.cookies:
            self._authorization = json.loads(self.tryrequest(self.auth_page, json=self.body).text)
#            self._authorization = json.loads(self._session.post(self.auth_page, json=self.body).text)

       #     self._authorization = json.loads(self._session.post(self.auth_page, json=self.body).text)
   
   
    def tryrequest(self, arg, **kwargs):
        dbgPrint.debug("sending request...")
        headers = kwargs.pop('headers', {})  
        params = kwargs.pop('params', {})
        data  = kwargs.pop('json', {})

        if kwargs:
            dbgPrint.error("Unexpected argument")
            raise("Unexpected **kwargs argument")
#        response = requests.models.Response
        for i in range(3):
            try:
                if params:
                    response = self._session.get(arg, headers=headers, params=params, verify=False)
                    if response.status_code == 440 or response.status_code == 401:
                        login.Login().delete_session()
                        login.Login(self.email).login()
                        self.load_session()
                        continue
                    elif response.status_code == 200:
                        break
                    elif response.status_code == 500:
                        message = json.loads(response.text)
                        dbgPrint.error(message["Message"])
                    elif response.status_code == 504:
                        dbgPrint.error("Gateway Time-out")
                    if response.status_code == 429:
                        message = json.loads(response.text)
                        dbgPrint.error(message["error"]["message"])
                        continue
                else:
                    response = self._session.post(arg, headers=headers, json=data, verify=False)
                    if response.status_code == 440 or response.status_code == 404 or response.status_code== 400:
                        login.Login().delete_session()
                        login.Login(self.email).login()
                        log.load_session()
                        continue
                    elif response.status_code == 200:
                        break
                    elif response.status_code == 500:
                        message = json.loads(response.text)
                        dbgPrint.error(message["Message"])

                    elif response.status_code == 504:
                        dbgPrint.error("Gateway Time-out")
      
            except:
                continue
        return response            

    def get_aad_authorization(self):
        
        json_data = {
        'extensionName': 'Microsoft_AAD_UsersAndTenants',
        'resourceName': 'microsoft.graph',
        'tenant': TENANT_ID,
        'portalAuthorization': self._authorization['portalAuthorization'],
        'altPortalAuthorization': self._authorization['altPortalAuthorization']
        }

        response = self._session.post(self.auth_page, json=json_data, verify=False)

        for _ in range(5):
            if response.status_code == 440:
#                raise Exception("Reset")
                Login.Login().delete_session()
                Login.Login(self.email).login()
                self.load_session()
                response = self._session.post(self.auth_page, json=json_data, verify=False)                      #Need exception handling
                if response.status_code == 200:
                    break
            elif response.status_code == 200:
                break

            elif response.status_code == 500:
                message = json.loads(response.text)
                dbgPrint.error(message["Message"])
                sys.exit()

        bearer = json.loads(response.text)
        users_auth = bearer["value"]["authHeader"]

        return users_auth

    def get_intune_authorization(self):

        json_data = {
        'extensionName': 'Microsoft_Intune_DeviceSettings',
        'resourceName': 'microsoft.graph',
        'tenant': TENANT_ID,
        'portalAuthorization': self._authorization['portalAuthorization'],
        'altPortalAuthorization': self._authorization['altPortalAuthorization']
        }

        response = self._session.post(self.auth_page, json=json_data, verify=False)
        bearer = json.loads(response.text)
        intune_auth = bearer["value"]["authHeader"]
        return intune_auth

    def get_iam_authorization(self):
        json_data = {
        'extensionName': 'Microsoft_AAD_IAM',
        'resourceName': 'microsoft.graph',
        'tenant': TENANT_ID,
        'portalAuthorization': self._authorization['portalAuthorization'],
        'altPortalAuthorization': self._authorization['altPortalAuthorization']
        }

        response = self._session.post(self.auth_page, json=json_data, verify=False)
        bearer = json.loads(response.text)
        iam_auth = bearer["value"]["authHeader"]
        return iam_auth

    def save_session(self):
        if not os.path.exists("./session"):
            os.makedirs("./session")
        with open('./session/msgraph.pkl', 'wb') as f:
            pickle.dump(self.cookies, f)
            pickle.dump(self.body, f)


    def load_session(self):

        if os.path.exists("./session/msgraph.pkl"):
            with open("./session/msgraph.pkl", 'rb') as f:
                cookies = pickle.load(f)
                json_data = pickle.load(f)
            self.cookies = cookies
            self.body = json_data
            self.__init__(self.email, cookies=cookies, json=json_data)
            self.users_auth = self.get_aad_authorization()
            self.devices_auth = self.get_intune_authorization()
            self.mfa_stats_auth = self.get_iam_authorization()
        else:
            login.Login().delete_session()
            login.Login(self.email).login()
            self.load_session()
        return self

    def search_user(self, username):

        microsoft_graph = 'https://graph.microsoft.com/beta/$batch'

        query = "(\"displayName:" + username + "\" OR \"mail:" + username + "\" OR \"userPrincipalName:" + username + "\" OR \"givenName:" + username +"\")"

        headers = {
        'Authorization': self.users_auth,
        'content-type': 'application/json'
        }

        json_data = {
        'requests': [
            {
            'id': "searched_user",
            'method': "GET",
            'url': "/users?$select=id," 
            "displayName,"
            "givenName,"
            "surname,"
            "userPrincipalName,"
            "userType,"
            "country,"
            "usageLocation,"
            "companyName"
            "&$search=" + query + "&$top=1&$count=true",
            
            'headers': {
                'ConsistencyLevel': "eventual",
                'x-ms-command-name': "UserManagement - ListUsers",
                        }
                    }
                ]
            }

        response = self.tryrequest(microsoft_graph, headers=headers, json=json_data)
#        response = self._session.post(microsoft_graph, headers=headers, json=json_data, verify=False)
        
        return (json.loads(response.text)['responses'][0]['body']['value'])

    def search_device_by_name_beta(self,  device_name):
        microsoft_graph = 'https://graph.microsoft.com/beta/$batch'

        query = "/devices?$search=(\"displayName:" + device_name + "\")&$top=1&$count=true"

        json_data = {
        "requests": [
            {
            "id": "device_name",
            "method": "GET",
            "url": query,
            "headers": {
                "ConsistencyLevel": "eventual",
                "x-ms-command-name": "DeviceManagement - ListDevices",
                        }
                    }
                ]
            }

        headers = {
        'Authorization': self.devices_auth,
        'content-type': 'application/json'
        }

        response = self.tryrequest(microsoft_graph, headers=headers, json=json_data)
#        response = self._session.post(microsoft_graph, headers=headers, json=json_data, verify=False)

        return (json.loads(response.text)['responses'][0]['body']['value'])

    def search_device_by_name(self, device_name):

        microsoft_graph_device = 'https://graph.microsoft.com/beta/deviceManagement/managedDevices'

        query = "(Notes eq 'bc3e5c73-e224-4e63-9b2b-0c36784b7e80') and (contains(activationlockbypasscode, '" + device_name + "'))"

#        query = "(deviceName eq '" + device_name + "')"


        params = {
        '$filter'   :  query,
        '$Skip'     : '0',
        '$top'      : 25,           #Removing $top will result in undefined behavior
        '$select'   : "deviceName,managementAgent,ownerType,complianceState,deviceType,userId,userPrincipalName,osVersion,lastSyncDateTime,userPrincipalName,id,deviceRegistrationState,managementState,exchangeAccessState,exchangeAccessStateReason,deviceActionResults,deviceEnrollmentType"
        }

        headers = {
        'Authorization': self.devices_auth,
        'content-type': 'application/json'
        }

        
        response = self._session.get(microsoft_graph_device, headers=headers, params=params, verify=False)

        return (json.loads(response.text))['value']

    def check_mfa_status(self, userPrincipalName):
        mfa_status = 'https://graph.microsoft.com/beta/reports/credentialUserRegistrationDetails'
        params = {'$filter' : "userPrincipalName eq '" + userPrincipalName + "'"}
        headers = {
        'Authorization': self.mfa_stats_auth,
        'content-type': 'application/json'
        }
        response = self.tryrequest(mfa_status, headers=headers, params=params)

#        response = self._session.get(mfa_status, headers=headers, params=params, verify=False)
        return json.loads(response.text).get('value', {})

    def get_user_groups(self, userPrincipalName):
        user_object = self.search_user(userPrincipalName)

        user_groups = 'https://graph.microsoft.com/beta/users/' + user_object[0]["id"] + '/memberOf/$/microsoft.graph.group'



        params = {
            '$select' : "id, displayName, securityEnabled",
            '$top'    : 5,
            '$filter' : "(mailEnabled eq false and securityEnabled eq true)",
            '$count'  : "true"
            }
        
        headers = {
            'Authorization' : self.users_auth,
            'content-type' : 'application/json',
            'ConsistencyLevel' : 'eventual'
            }

        response = self.tryrequest(user_groups, headers=headers, params=params)

        return [i['displayName'] for i in json.loads(response.text)['value'] if re.search("[A-Z]{3,5}\_",i['displayName'])]

    #Need exception