import json
from pathlib import Path
import re
import requests, json, pickle, ast
import pprint as pp
import os, sys
import time

KEY = "1797a0dc6f3f4bdf7f8387f189e384e8e8feb824234941f49ff45fde5eb9df7d091cef8c5f7731a5"
check = "https://api.abuseipdb.com/api/v2/check"
class ipdb:
    def __init__(self, key):
        self.__key__ = key
        self.headers = {
            "Key"       : self.__key__ ,
            "Accept"    : "application/json"
            }
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def check_endpoint(self, ip):
        check = "https://api.abuseipdb.com/api/v2/check"

        params = {
            "maxAgeInDays" : 90,
            "verbose"      : "",
            "ipAddress"    : ip
            }

        response = self.session.get(check, params=params, verify=False)
        result = json.loads(response.text)["data"]

        return {
            "ip" : result["ipAddress"],
            "isWhitelisted" : result["isWhitelisted"] if result["isWhitelisted"] else "No",
            "abuseConfidenceScore" : result["abuseConfidenceScore"],
            "countryCode"   :   result["countryCode"],
            "usageType"     :   result["usageType"],
            "isp"           :   result["isp"],
            "domain"        :   result["domain"],
            "totalReports"  :   result["totalReports"],
            "lastReportedAt":   result["lastReportedAt"]
            }

ipquery = ipdb(KEY)

