import requests
import xmltodict
import os, sys
import pickle
from loguru import logger



logger.add(f"./logs/{__name__}.log", backtrace=True, diagnose=True, filter=__name__)
dbgPrint = logger
dbgPrint.disable(__name__)

sys.path.append("..") # Adds higher directory to python modules path.
from helper import login

class MultiFactor:
    def __init__(self, email=None, **kwargs):
        self._email = email
        self._cookies = kwargs.pop('cookies', {})                         #dictionary
        self._headers = kwargs.pop('headers', {'content-type' : 'application/json'})
        self._session = requests.Session()
        self._session.cookies.update(self._cookies)
        self._session.headers.update(self._headers)
        pass

    def save_session(self):
        if not os.path.exists("./session"):
            os.makedirs("./session")
        else:
            with open('./session/mfa.pkl', 'wb') as f:
                pickle.dump(self._cookies, f)
                pickle.dump(self._headers, f)

    def load_session(self):

        if os.path.exists('./session/mfa.pkl'):
            dbgPrint.debug("[+] Loading mfa.pkl...")
            with open('./session/mfa.pkl', 'rb') as f:
                cookies = pickle.load(f)
                headers = pickle.load(f)
            self.__init__(self._email, cookies=cookies, headers=headers)
            return self
        else:
            login.Login().delete_session()
            login.Login(self.email).login()
            self.load_session()
            return self

    def query_user(self, user):
        mfa_page = 'https://account.activedirectory.windowsazure.com/usermanagement/GenericFetchData.ajax'

        data = {
            "p0":"Microsoft.Online.BOX.Admin.UI.UserManagement.MultifactorVerification.FetchUsers",
            "p1":"",
            "p2":"{\"SortProperty\":\"\",\"SortOrder\":0}",
            "p3":"1",
            "p4":"{\"FilterID\":null,\"FilterType\":\"10\",\"SearchText\":\"" + user + "\",\"MfaState\":\"Any\"}",
            "assembly":"BOX.UI, Version=2.0.0.0, Culture=neutral, PublicKeyToken=null",
            "class":"Microsoft.Online.BOX.UI.WebControls.ListGrid"
        }

        response = self._session.get(mfa_page, data=data, verify=False)
        if "SessionValid" in response.text:
            object = xmltodict.parse(response.text.strip("SessionValid"))['response']['Items']
            if object.get('Item'): 
                if isinstance(object['Item'], list):
                    for i in object['Item']:
                        print(i['Properties'])
                else:
                    return {
                    "displayName" : [i['Value'] for i in object['Item']['Properties']['Item'] if i['Name']=='DisplayName'][0],
                    "principalName" : [i['Value'] for i in object['Item']['Properties']['Item'] if i['Name']=='UserPrincipalName'][0],
                    "status" : [i['Value'] for i in object['Item']['Properties']['Item'] if i['Name']=='Status'][0],
                    "mfaStatusCode" : [i['Value'] for i in object['Item']['Properties']['Item'] if i['Name']=='MfaStatusCode'][0],
                        }
            else:
                return {}
        else:
            return {}