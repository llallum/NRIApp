import json
from pathlib import Path
import re
import requests, json, pickle, ast
import pprint as pp
import os, sys
import time

import sys
sys.path.append("..") # Adds higher directory to python modules path.

from helper import login
from config.config import *

from urllib.parse import unquote
from urllib.parse import urlencode
from urllib.parse import urlparse
#import login
#from PyLog import *
from loguru import logger
from tldextract import extract
from datetime import datetime, timedelta
from dateutil import parser


import pytz

tz = pytz.timezone('Asia/Hong_Kong')

SOURCE_MDE     = 1
SOURCE_OATP    = 2
SOURCE_AADIP   = 3
SOURCE_MCAS    = 4
SOURCE_MDATP   = 5
SOURCE_MS365D  = 6
SOURCE_MANUAL  = 7
SOURCE_APPGOV  = 8

filter_list = ["eDiscovery"]
#dbgPrint = PyLog(__name__, level=logging.INFO, store=False, consolePrint=True)


logger.add(f"./logs/{__name__}.log" ,mode="w", backtrace=True, diagnose=True, level="ERROR", filter="MSSentinelApi")
#logger.disable(__name__)
dbgPrint = logger

class MSSentinelApi:
    def __init__(self, email=None, **kwargs):
        self.email = email
        self._cookies = kwargs.pop('cookies', {})                         #dictionary
        self._headers = kwargs.pop('headers', {'content-type' : 'application/json'})
        if kwargs:
            dbgPrint.error('Unexpected kwargs provided: %s' % list(kwargs.keys()))
            raise TypeError('Unexpected kwargs provided: %s' % list(kwargs.keys()))
        if self._cookies:
            self._xsrf_token = unquote(self._cookies['XSRF-TOKEN'])
            self._headers = {
            'x-xsrf-token' : self._xsrf_token,
            'content-type' : 'application/json'
            }
        self._session = requests.Session()
        self._session.cookies.update(self._cookies)
        self._session.headers.update(self._headers)

#list alertStatus = ['New', 'InProgress', 'Resolved']
#severity = list [256, 128, 64, 32] 
#   256 = high
#   128 = Medium
#   64 = Low
#   32 = Informational
#pageIndex = int
#pageSize = int
#lookBackInDays = str



    def tryrequest(self, arg, **kwargs):

        headers = kwargs.pop('headers', {})  
        params = kwargs.pop('params', {})
        data  = kwargs.pop('json', {})
        if kwargs:
            dbgPrint.error("Unexpected argument")
            raise("Unexpected **kwargs argument")
        response = requests.models.Response
        for i in range(5):
            try:
                if params:
                    dbgPrint.info("Sending GET request")
                    response = self._session.get(arg, headers=headers, params=params, verify=False)
                    if response.status_code == 440:
                        login.Login().delete_session()
                        login.Login(self.email).login()
                        self.load_session()
                    elif response.status_code == 200:
                        break
                    elif response.status_code == 500:
                        message = json.loads(response.text)
                        dbgPrint.error(message["Message"])
                        sys.exit()
                    elif response.status_code == 504:
                        dbgPrint.error("Gateway Time-out")
                        sys.exit()  
                    break
                else:
                    dbgPrint.info("Sending POST request")
                    response = self._session.post(arg, headers=headers, json=data, verify=False)
                    if response.status_code == 440:
                        login.login().delete_session()
                        login.login(self.email).login()
                        self.load_session()
                    elif response.status_code == 200:
                        break
                    elif response.status_code == 500:
                        message = json.loads(response.text)
                        dbgPrint.error(message["Message"])
                        sys.exit()
                    elif response.status_code == 504:
                        dbgPrint.error("Gateway Time-out")
                        sys.exit()      
            except:
                continue
        return response

    def get_incidents(self, incidentId = 0, alertStatus=['New','InProgress', 'Resolved'], severity=[256, 128, 64, 32], pageIndex= 1, lookBackInDays = 60, pageSize = 50, sourceFilter=[], titleFilter=["eDiscovery"]):

        incident_alerts = 'https://security.microsoft.com/apiproxy/mtp/incidentQueue/incidents/alerts'
        json_data = {
            'pageSize': pageSize,
            'lookBackInDays': str(lookBackInDays),
            'isMultipleIncidents': True,
            'alertStatus': alertStatus,
            'severity': severity,
            'pageIndex': pageIndex,
            }
        response = self._session.post(incident_alerts, json=json_data, verify=False)

        for _ in range(5):
            if response.status_code == 440:
#                raise Exception("Reset")
                login.Login().delete_session()
                login.Login(self.email).login()
                self.load_session()
                response = self._session.post(incident_alerts, json=json_data, verify=False)                      #Need exception handling
                if response.status_code == 200:
                    break
            elif response.status_code == 200:
                break

            elif response.status_code == 500:
                message = json.loads(response.text)
                dbgPrint.error(message["Message"])
                sys.exit()
            elif response.status_code == 504:
                dbgPrint.error("Gateway Time-out")
                sys.exit()

        #Need exception here
        if incidentId:
            return [i for i in json.loads(response.text) if i["IncidentId"] == int(incidentId)]
        else:
            temp = []

            for i in json.loads(response.text):
                for b in i["DetectionSources"]:
                    if b in sourceFilter:
                        continue
                    for a in titleFilter:
                        if a not in i["Title"]:
                            temp.append(i)
            return temp
#            return [i for i in json.loads(response.text) if i["DetectionSources"][0] not in sourceFilter and ]

    def search_incident(self, query, pageSize=3):
        incident_search = 'https://security.microsoft.com/apiproxy/mtp/incidentSearch'

        params = {
            'term': query,
            'pageSize': pageSize
            }

        response = self.tryrequest(incident_search, params=params)
#        response = self._session.get(incident_search, params=params, verify=False)
        return json.loads(response.text)

    def save_session(self):
        if not os.path.exists("./session"):
            os.makedirs("./session")
        if not os.path.exists('./session/ms365.pkl'):
            with open('./session/ms365.pkl', 'wb') as f:
                pickle.dump(self._cookies, f)   

    def load_session(self):

        if os.path.exists('./session/ms365.pkl'):
            dbgPrint.debug("[+] Loading ./session/ms365.pkl...")
            with open('./session/ms365.pkl', 'rb') as f:
                cookies = pickle.load(f)
            self.__init__(cookies=cookies)
            return self
        else:
            login.Login().delete_session()
            login.Login(self.email).login()
            self.load_session()
            return self

    def get_incident_info(self, incidentId):
        incident_page = 'https://security.microsoft.com/apiproxy/mtp/incidentQueue/incidents/'

        if str(incidentId).isdigit() and self.search_incident(incidentId):
#            response = self.search_incident(incidentId)
            incident_page += str(incidentId)
            
            response = self._session.get(incident_page)
            return json.loads(response.text)
        else:
            return {}

    def get_associated_alerts(self, incidentId, pageSize=30, pageIndex=1, lookBackInDays=7, filter=[]):


#        associated_alerts = 'https://security.microsoft.com/apiproxy/mtp/threatIntel/AssociatedAlerts'
        associated_alerts = 'https://security.microsoft.com/apiproxy/mtp/alertsApiService/alerts'

        json_data = {
            "pageNumber": pageIndex,
            "pageSize": pageSize,
            "daysAgo": lookBackInDays,
            "IncidentIds": [incidentId],
            "sorByField": "lastEventTime"
            }

        response = type('obj', (object,), {'status_code' : None, 'text' : None})

        response = self.tryrequest(associated_alerts, json=json_data)

      
        value = []   
        for f in filter:
            for i in json.loads(response.text)['entities']:
                if f not in i["alertDisplayName"]:
                    value.append(
                    {"AlertId":             i['alertId'],
                        "Title":               i['alertDisplayName'],
                        "ThreatFamilyName":    i['threatName'],
                        "Status":              i['status'],
                        "Severity":            i['severity']
                    })

        return value


#        return [{"AlertId":             i["AlertId"],
#                "Title":                i["Title"], 
#                "ThreatFamilyName":     i["ThreatFamilyName"], 
#                "ComputerDnsName":      i["ComputerDnsName"],
#                "InvestigationState":   i["InvestigationState"],
#                "Severity":             i["Severity"]
#                } for i in json.loads(response.text)['Items']]


    def get_mail_metadata(self, startUtc, endUtc, networkMessageId):

        metadata_search = "https://security.microsoft.com/apiproxy/di/Find/MailMetaData"

        start = parser.parse(startUtc)
        start = start - timedelta(days=1)
        startUtc = start.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        end = parser.parse(endUtc)
        end = end + timedelta(days=1)
        endUtc = end.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        params = {
            'tenantId'  : TENANT_ID,
            'startTime' : startUtc,
            'endTime'   : endUtc,
            'Filter'    : "NetworkMessageId eq '" + networkMessageId + "'"
            }

        response = self.tryrequest(metadata_search, params=params)

        object = json.loads(response.text)
        if object["ResultData"] != None:
            resultData = json.loads(object["ResultData"][0])
            attachmentsFilters = resultData["XmiInfo"]["AttachmentFilterInfos"]
            urlFilters = resultData["XmiInfo"]["UrlFilterInfos"]

            return {
            "attachments" : attachmentsFilters,
            "urls"        : urlFilters
            }
        else:
            {}

    def get_alert_story(self, alertId):
        
        class Alert:
            def __init__(self, item, source=0, parent=None, parentClass=None):
                self.alertId = alertId
                self.source = source
                if item["type"] == "AlertStory":
                    self.id = item.get("id", "")
                    self.type = "AlertStory"
                    self.items = item["items"]
                    self.description = item["description"]
                elif item["type"] == "AutomatedInvestigation":
                    self.type = "AutomatedInvestigation"
                    self.description = item["description"]
                elif item["type"] == "ManualDetection":
                    self.type = "ManualDetection"
                    self.title = item["alertDisplayName"]
                    self.description = item["description"]
                    self.provider_name = item["providerName"]
                    self.first_seen = item["firstSeen"]
                elif item["type"] == "UnsupportedType":
                    self.type = "UnsupportedType"
                    self.description = item["description"]
                elif item["type"] == "mailMessage":
                    self.parentClass = parentClass
                    self.type = "mailMessage"
                    self.provider_name = item["providerName"]
                    self.display_name = item["alertDisplayName"]
                    self.description = item["description"]
                    self.start_time_utc = item["startTimeUtc"]
                    self.end_time_utc = item["endTimeUtc"]
                    self.impacted_entities = item["impactedEntities"]
                    self.related_entities = item["relatedEntities"]
                else:
                    self.id = item["id"]
                    self.children = [Alert(i, parent=self) for i in item["children"]] if item["children"] else []               #1/22/2023 3:35:08 AM
                    self.type = item["type"]
                    self.title = item["title"]
                    self.details = item["details"]
                    self.nested_item = [Alert(i, parent=self) for i in item["nestedItems"]] if item["nestedItems"] else []      #1/22/2023 3:35:08 AM
                    self.additional_details = item["additionalDetails"]
                    self.hidden_alerts = item.get("hiddenAlerts", None)
                    self.associated_alerts = item["associatedAlerts"]               #Usually, it is empty rather than None type
                    self.action_type = item.get("actionType", "")
                    self.parent = parent
    #                self.action_type = item["actionType"]
                    if item.get("entity"):
                        self.entity = item["entity"]

            def parse_manual_alert_story(self, queue=None):

                title = self.title
                description = self.description

#                dbgPrint.info("Title: %s" % self.title)
#                dbgPrint.info("Description: %s" % self.description)

                data = {}
                if queue is not None:
                    queue.put(data)

                manualAlert = {
                    "title"         : title,
                    "description"   : description
                    }

                data["manualAlert"] = manualAlert



            def parse_mdatp_alert_story(self, queue=None):
                dbgPrint.info("Title: %s" % self.description)


            def parse_mde_alert_story(self, queue=None):
                if hasattr(self, "associated_alerts") and self.associated_alerts == None:
                    data = {}
                    if queue is not None:
                        queue.put(data)
                    if self.type == "emailEvent":

                        title = self.title["main"]
                        sender = [i["value"] for i in self.details if i["key"] == "Sender from address"][0] if [i for i in self.details if i["key"]== "Sender from address"] else ""
                        recipient = [i["value"] for i in self.details if i["key"] == "Recipient email address"][0] if [i for i in self.details if i["key"]== "Recipient email address"] else ""
                        filename = [i["value"] for i in self.details if i["key"] == "File name"][0] if [i for i in self.details if i["key"]== "File name"] else ""
                        sha256 = [i["value"] for i in self.details if i["key"] == "SHA256"][0] if [i for i in self.details if i["key"]== "SHA256"] else ""
                        senderIp = [i["value"] for i in self.details if i["key"] == "Sender ipv4"][0] if [i for i in self.details if i["key"]== "Sender ipv4"] else ""
                        deliveryAction = [i["value"] for i in self.details if i["key"] == "Delivery action"][0] if [i for i in self.details if i["key"]== "Delivery action"] else ""
                        deliveryLocation = [i["value"] for i in self.details if i["key"] == "Delivery location"][0] if [i for i in self.details if i["key"]== "Delivery location"] else ""
                        threatTypes = [i["value"] for i in self.details if i["key"] == "Threat types"][0] if [i for i in self.details if i["key"]== "Threat types"] else ""

#                        dbgPrint.info("Title: %s" % title)
#                        dbgPrint.info("Sender from address: %s " % sender)
#                        dbgPrint.info("Recipient email address: %s" % recipient)
#                        dbgPrint.info("File name: %s" % filename)
#                        dbgPrint.info("SHA256: %s " % sha256)
#                        dbgPrint.info("Sender IP: %s" % senderIp)
#                        dbgPrint.info("Delivery Action: %s" % deliveryAction)
#                        dbgPrint.info("Delivery Location: %s" % deliveryLocation)
#                        dbgPrint.info("Threat Types: %s" % threatTypes)

                        data["title"]            = title
                        data["sender"]           = sender
                        data["recipient"]        = recipient
                        data["filename"]         = filename
                        data["sha256"]           = sha256
                        data["senderIP"]         = senderIp
                        data["deliveryAction"]   = deliveryAction
                        data["deliveryLocation"] = deliveryLocation
                        data["threatTypes"]      = threatTypes
                        data["type"]             = "mdeEmail"


                    elif self.type == "url":
                        title  = self.title["main"]
                        url = [i["value"] for i in self.details if i["key"] == "Url"][0] if [i for i in self.details if i["key"]== "Url"] else ""
#                        dbgPrint.info("Title: %s" % title)
#                        dbgPrint.info("Url: %s " % url)

                        moreInfo = [a["details"] for a in [i for i in self.additional_details] if a.get("details")][0]

                        data["accountUpn"] = [i["value"] for i in moreInfo if i["key"] == "Account upn"][0]
                        data["timestamp"] = [i["value"] for i in moreInfo if i["key"] == "Timestamp"][0]
                        data["actionType"] = [i["value"] for i in moreInfo if i["key"] == "Action type"][0]
                        data["ip"] = [i["value"] for i in moreInfo if i["key"] == "IPAddress"][0]
                        data["clickThru"] = [i["value"] for i in moreInfo if i["key"] == "Is clicked through"][0]
                        data["netMsgId"] = [i["value"] for i in moreInfo if i["key"] == "Network message id"][0]


                        data["title"] = title
                        data["url"] = url
                        data["type"] = "mdeUrl"

                    elif self.type == "appCloudEvent":                  #7481 Multi-stage incident involving Initial access & Collection involving multiple users reported by multiple sources
                        title = self.title["main"]
                        displayName = [i["value"] for i in self.details if i["key"] == "Account display name"][0] if [i for i in self.details if i["key"]== "Account display name"] else ""
                        objectId = [i["value"] for i in self.details if i["key"] == "Account object id"][0] if [i for i in self.details if i["key"]== "Account object id"] else ""
                        ipAddress = [i["value"] for i in self.details if i["key"] == "IPAddress"][0] if [i for i in self.details if i["key"]== "IPAddress"] else ""
                        isp = [i["value"] for i in self.details if i["key"] == "ISP"][0] if [i for i in self.details if i["key"]== "ISP"] else ""
                        objectName = [i["value"] for i in self.details if i["key"] == "Object name"][0] if [i for i in self.details if i["key"]== "Object name"] else ""
#                        dbgPrint.info("Title: %s" % title)
#                        dbgPrint.info("Account display name: %s" % displayName)
#                        dbgPrint.info("Object Id: %s " % objectId)
#                        dbgPrint.info("Object Name: %s" % objectName)
#                        dbgPrint.info("IP Address: %s" % ipAddress)
#                        dbgPrint.info("ISP: %s" % isp)

                        
                        data["title"] = title
                        data["displayName"] = displayName
                        data["objectId"]  =  objectId
                        data["ipAddress"] = ipAddress
                        data["isp"] =  isp
                        data["objectName"] = objectName
                        data["type"] = "appCloud"
                       

                    else:
                        dbgPrint.error("Error: Unhandled Type (MDE) with type %s " % self.type)
                        raise Exception("Error: Unhandled Type (MDE) with type %s " % self.type)
                else:
                    dbgPrint.error("Error: Unhandled Type (MDE) with type %s " % self.type)
                    raise Exception("Error: Unhandled Type (MDE) with type %s " % self.type)


            def parse_mdo_alert_story(self, queue=None):
                if hasattr(self, "items"):
                    if self.items:
                        for i in self.items:
                            if i["type"] == "mailMessage":
                                data = {}                               
                                if queue is not None:
                                    queue.put(data)
                                recipient = i["entity"]["recipient"]
                                subject = i["entity"]["subject"]
                                p2sender = i["entity"]["p2Sender"]
                                senderIp = i["entity"]["senderIP"]

                                emailInfo = {
                                    "recipient" : recipient,
                                    "subject"   : subject,
                                    "p2sender"  : p2sender,
                                    "senderIp"  : senderIp
                                }

                                data["emailInfo"] = emailInfo

#                                dbgPrint.info("Recipient: %s " % recipient)
#                                dbgPrint.info("Subject: %s " % subject)
#                                dbgPrint.info("P2Sender: %s " % p2sender)
#                                dbgPrint.info("SenderIP: %s" % senderIp)
                                attachments = []
                                emailInfo["attachments"] = attachments
                                if i["entity"]["files"]:
#                                    dbgPrint.info("Attachment:")
                                    for item in i["entity"]["files"]:
                                        fullpath = item["fullPath"]
                                        name = item["name"]
                                        fileHashes = item["fileHashes"][0]
                                        sha256 = fileHashes.get("value", "")
                                        attachments.append({"fullpath": fullpath, "name": name, "sha256": sha256})

#                                        dbgPrint.info("\tFullPath: %s " %  fullpath)
#                                        dbgPrint.info("\tName: %s" % name)
#                                        dbgPrint.info("\tSha256: %s" % sha256)
                                urls = []
                                emailInfo["urls"] = urls
                                if i["entity"]["urls"]:
#                                    dbgPrint.info("URLs:")
                                    for item in i["entity"]["urls"]:
                                        urls.append(item)
#                                        dbgPrint.info("\t%s" % item)

                            elif i["type"] == "AlertStoryItem":             #10616

                                data = {}                               
                                if queue is not None:
                                    queue.put(data)
                               
                                if i.get("ip"):
                                    

                                    ip = i["ip"]["address"]
                                    city = i["ip"]["location"]["city"]
                                    state = i["ip"]["location"]["state"]
                                    countryCode = i["ip"]["location"]["countryCode"]
#                                    dbgPrint.info("IP Address: %s" % i["ip"]["address"])
#                                    dbgPrint.info("Location: %s, %s, %s" % (city, state, countryCode))

                                    data["ip"] = ip
                                    location = {}
                                    location["city"] = city
                                    location["state"] = state
                                    location["countryCode"] = countryCode

                                    data["location"] = location
                                    data["type"] = "ip_mdo"

                                if i.get("cloudLogonSession"):
                                    userAgent = i["cloudLogonSession"]["userAgent"]
#                                    dbgPrint.info("User Agent: %s " % userAgent)

                                    LogonSession = {}
                                    LogonSession["userAgent"] = userAgent

                                userName = i["entity"]["name"]
                                domainName = i["entity"].get("ntDomain","")
#                                dbgPrint.info("User name: %s" % userName)
#                                dbgPrint.info("Domain name: %s" % domainName)

                                AlertStoryItem["userName"] = userName
                                AlertStoryItem["domainName"] = domainName

                            else:
                                raise Exception("Error: Unhandled type (OATP).")
                    
                    else: 
                        if self.type == "AlertStory":

                            data = {}
                            if queue is not None:
                                queue.put(data)

                            alertStory = {}
                            data["alertStory"] = alertStory

                            title = self.description["title"]
                            description = self.description["text"]

#                            dbgPrint.info("Title: %s" % title)
#                            dbgPrint.info("Description: %s" % description)

                            alertStory["title"] = title
                            alertStory["description"] = description

                else:
                    if self.type == "mailMessage":
                        data = {}

                        if queue is not None:
                            queue.put(data)

                        data["alertId"] = "https://security.microsoft.com/alerts/" + self.alertId
                        data["description"] = self.description
                        data["displayName"] = self.display_name
                        data["providerName"] = self.provider_name
                        data["type"] = "mailMessage"
                        impacted_entities = []
                        data["impactedEntities"] = impacted_entities
                        for i in self.impacted_entities:
                            user = {}
                            if i["type"] == "mailbox":
                                user["displayName"] = i.get("displayName", "")
                                user["mailboxAddress"] = i["mailboxPrimaryAddress"]
                                user["lastVerdict"] = i.get("lastVerdict", "")
                                user["firstSeen"] = i.get("FirstSeen", "")
                                user["type"] = "mailbox"
                                impacted_entities.append(user)

                        
                        related_entities  = []
                        data["relatedEntities"] = related_entities
                        for i in self.related_entities:
                            mailMessage = {}
                            if i["type"] == "mailMessage":
                                mailMessage["recipient"] = i["recipient"]


                                mailMessage["urls"] = [{"url": _, "verdict": None} for _ in i.get("urls", [])]
                                file_list = i.get("files", [])
                                

                                networkMessageId = i.get("networkMessageId")
                                urls = self.parentClass.get_mail_metadata(i["receivedDate"], i["receivedDate"], i["networkMessageId"])

                                if urls:
                                    urls = urls["urls"] if urls else {}
                                for x in urls:
                                    uri = x["Url"]
#                                    if x["Verdict"] != None:
                                        
                                    verdict  = x["Verdict"]  if x["Verdict"] != None else None
                                    for a in mailMessage["urls"]:
                                        
                                        dom = extract(x["Url"].lower())
                                        old = "{}.{}".format(dom.domain, dom.suffix)

                                        dom2 = extract(a["url"].lower())
                                        new = "{}.{}".format(dom2.domain, dom2.suffix)
                                        if old in a["url"].lower():
                                                a["verdict"] = verdict

                                for a in mailMessage["urls"]:
                                    a["url"] = a["url"].replace("https", "hxxps").replace("http", "hxxp").replace(".", "[.]").replace(":","[:]")

                                files = []
                                for a in file_list:
                                    file = {}
                                    if a["type"] == "file":
                                        file["name"] = a["name"]
                                        file["malwareFamily"] = a["MalwareFamily"]
                                        file["type"] = "file"
                                        file["hash"] = [i["value"] for i in a["fileHashes"] if i["algorithm"] == "SHA256"][0] if [i for i in a["fileHashes"] if i.get("$id")] else ""
                                       # file["hash"] = hash["value"]
                                        if file["hash"]:
                                            files.append(file)
                                mailMessage["lastRemediationState"] = i.get("lastRemediationState", "")
                                mailMessage["files"] = files        
                                mailMessage["senderIP"] = [i.get("senderIP", "")]
                                mailMessage["sender"] = [i.get("sender", "").replace(".", "[.]").replace("@", "[@]")]

                                mailMessage["p2SenderDisplayName"] = [i.get("p2SenderDisplayName", "")]
                                mailMessage["subject"] = [i.get("subject", "")]
                                mailMessage["threats"] = i.get("threats", [])
                                mailMessage["type"] = "email"
                                related_entities.append(mailMessage)

                        


            def parse_mcas_alert_story(self, queue=None):
                if hasattr(self, "items"):
                    data = {}
                    data["type"] = "mcasAlert"
                    if self.description["type"] == "ITPAlertStoryDescription":

                        if queue is not None:
                            queue.put(data)

                        summary = self.description["description"]
                        dbgPrint.info("Description: %s" % summary)
                        desArguments = self.description["descriptionArguments"]
                        localizedKey = self.description["descriptionLocalizedKey"]
                        
                        data["summary"] = summary

                        if "ANUBIS_VELOCITY_DETECTION_INCIDENT_DESCRIPTION_SINGLE_INCIDENT_V3" in localizedKey:                     #Impossible travel activity involving one user
                            info = desArguments["ANUBIS_VELOCITY_DETECTION_INCIDENT_DESCRIPTION_SINGLE_INCIDENT_V3"]["value"]
                            timeResolution = info["time_resolution"]
                            timeFrame = info["time_frame"]
                            
                            data["title"] = "Impossible travel activity involving one user"
                            data["timeResolution"] = timeResolution
                            data["timeFrame"] = timeFrame

                            ips = []

                            for item in info:
                                if "ips_list" in item:
                                    count = item[-1]
                                    ip = "ips_list_"  + count
                                    loc = "location_" + count
                                    addIp = "num_additional_ips_" + count
                                    iplist = info[ip]
                                    location = info[loc]
                                    additionalIp = info[addIp]   
                                    ips.append({"ip":iplist, "location" : location, "additionalIp": additionalIp}) 
                            data["ip"] = ips        
                            
                        elif "{ANUBIS_REPEATED_ACTIVITY_DOWNLOAD_PASSED_THRESHOLD_OVER_VALUE}" in localizedKey:                     #Collection incident involving one user reported by multiple sources
                            info = desArguments["ANUBIS_REPEATED_ACTIVITY_DOWNLOAD_PASSED_THRESHOLD_OVER_VALUE"]["value"]

                            threshold = info["threshold"]
                            currentValue = info["value"]
                            user = info["user"]
                            
                            data["title"] = "Collection incident involving one user reported by multiple sources"
                            data["threshold"] = threshold
                            data["user"] = user
                            data["value"] = currentValue

                        elif "CABINET_DISCOVERY_ALERT_BUILDER_SINGLE_DESCRIPTION" in localizedKey:                                  #Unofficial Cloud Storage Check
                            dbgPrint.info("Unofficial Cloud Storage Check")
                            data["title"] = "Unofficial Cloud Storage Check"
                            pass
                        elif "ANUBIS_SUSPICIOUS_IP_DETECTION_DESCRIPTION" in localizedKey:                                           #Activity from a password-spray associated IP address involving one user  
                            info = desArguments["ANUBIS_SUSPICIOUS_IP_DETECTION_DESCRIPTION"]["value"]            
                            ip = info["ips"]
                            riskType = info["risk_type"]
                            user = info["username"]

                            data["title"] = "Activity from a password-spray associated IP address involving one user"
                            data["ip"] = ip
                            data["riskType"] = riskType
                            data["user"] = user


                        elif "ANUBIS_REPEATED_ACTIVITY_DOWNLOAD_PASSED_THRESHOLD_OVER_VALUE_NEW_WITH_DOMINANT_EXTENSION" in localizedKey:           #Mass download involving one user
                            info = desArguments["ANUBIS_REPEATED_ACTIVITY_DOWNLOAD_PASSED_THRESHOLD_OVER_VALUE_NEW_WITH_DOMINANT_EXTENSION"]["value"]
                            threshold = info["threshold"]
                            currentValue = info["value"]
                            user = info["user"]
                            extension = info["extension"]
                            numb_ext = info["num_ext"]

                            data["title"] = "Mass download involving one user"
                            data["threshold"] = threshold
                            data["value"] = currentValue
                            data["user"] = user
                            data["extension"] = extension
                            data["numb_ext"] = numb_ext

                        elif "{ANUBIS_REPEATED_ACTIVITY_DELETE_PASSED_THRESHOLD_OVER_VALUE_NEW_WITH_DOMINANT_EXTENSION}" in localizedKey:
                            info = desArguments["ANUBIS_REPEATED_ACTIVITY_DELETE_PASSED_THRESHOLD_OVER_VALUE_NEW_WITH_DOMINANT_EXTENSION"]["value"]         # Mass delete involving one user
                            threshold = info["threshold"]
                            currentValue = info["value"]
                            user = info["user"]
                            extension = info["extension"]
                            numb_ext = info["num_ext"]

                            data["title"] = "Mass delete involving one user"
                            data["value"] = currentValue
                            data["threshold"] = threshold
                            data["user"] = user
                            data["extension"] = extension
                            data["numb_ext"] = numb_ext

                        elif "ANUBIS_REPEATED_ACTIVITY_DELETE_PASSED_THRESHOLD_OVER_VALUE_NEW_WITH_DOMINANT_EXTENSION_DOMINANT_FOLDER" in localizedKey:       #Mass delete involving one user 
                            info = desArguments["ANUBIS_REPEATED_ACTIVITY_DELETE_PASSED_THRESHOLD_OVER_VALUE_NEW_WITH_DOMINANT_EXTENSION_DOMINANT_FOLDER"]["value"] 
                            folder = info["folder"]
                            threshold = info["threshold"]
                            currentValue = info["value"]
                            user = info["user"]
                            extension = info["extension"]
                            numb_ext = info["num_ext"]

                            data["title"] = "Mass delete involving one user"
                            data["folder"] = folder
                            data["threshold"] = threshold
                            data["value"] = currentValue
                            data["user"] = user
                            data["extension"] = extension
                            data["numb_ext"] = numb_ext


                        elif "ANUBIS_REPEATED_ACTIVITY_FAILEDLOGIN_PASSED_THRESHOLD_OVER_VALUE" in localizedKey:                    #Multiple failed login attempts involving one user
                            info = desArguments["ANUBIS_REPEATED_ACTIVITY_FAILEDLOGIN_PASSED_THRESHOLD_OVER_VALUE"]["value"]
                            threshold = info["threshold"]
                            currentValue = info["value"]
                            user = info["user"]

                            data["title"] = "Multiple failed login attempts involving one user"
                            data["threshold"] = threshold
                            data["value"] = currentValue
                            data["user"] = user

                        elif "ANUBIS_RISKY_IP_DETECTION_DESCRIPTION" in localizedKey:                                               #Anonymous IP address
                            info = desArguments["ANUBIS_RISKY_IP_DETECTION_DESCRIPTION"]["value"]                               
                            ip = info["ips"]
                            riskType = info["risk_type"]
                            user = info["username"]
                            num_ips = info["num_ips"]

                            data["title"] = "title"
                            data["ip"] = ip
                            data["riskType"] = riskType
                            data["user"] = user
                            data["num_ips"] = num_ips

                        elif "{ANUBIS_REPEATED_ACTIVITY_DELETE_PASSED_THRESHOLD_OVER_VALUE}" in localizedKey:                         #Mass delete involving one user
                            info = desArguments["ANUBIS_REPEATED_ACTIVITY_DELETE_PASSED_THRESHOLD_OVER_VALUE"]["value"]                               
                            threshold = info["threshold"]
                            user = info["user"]
                            currentValue = info["value"]

                            data["title"] = "Mass delete involving one user"
                            data["threshold"] = threshold
                            data["user"] = user
                            data["value"] = currentValue

                        elif "ANUBIS_REPEATED_ACTIVITY_DELETE_PASSED_THRESHOLD_OVER_VALUE_NEW_WITH_DOMINANT_FOLDER" in localizedKey:
                            info = desArguments["ANUBIS_REPEATED_ACTIVITY_DELETE_PASSED_THRESHOLD_OVER_VALUE_NEW_WITH_DOMINANT_FOLDER"]["value"]  
                            threshold = info["threshold"]
                            user = info["user"]
                            currentValue = info["value"]
                            num_fol = info["num_fol"]
                            folder = info["folder"]

                            data["title"] = ""
                            data["threshold"] = threshold
                            data["user"] = user
                            data["currentValue"] = currentValue
                            data["num_fol"] = num_fol
                            data["folder"] = folder

                        elif "ANUBIS_REPEATED_ACTIVITY_SHAREREPORT_PASSED_THRESHOLD_OVER_VALUE" in localizedKey:                    #Multiple Power BI report sharing activities involving one user
                            info = desArguments["ANUBIS_REPEATED_ACTIVITY_SHAREREPORT_PASSED_THRESHOLD_OVER_VALUE"]["value"]                               
                            threshold = info["threshold"]
                            user = info["user"]
                            currentValue = info["value"]

                            data["title"] = "Multiple Power BI report sharing activities involving one user"
                            data["threshold"] = threshold
                            data["user"] = user
                            data["value"] = currentValue

                        elif "ANUBIS_SUSPICIOUS_EMAIL_DELETION_DESCRIPTION" in localizedKey:                                        #Suspicious email deletion activity involving one user
                            info = desArguments["ANUBIS_SUSPICIOUS_EMAIL_DELETION_DESCRIPTION"]["value"]                               
                            user = info["user"]

                            data["title"] = "Suspicious email deletion activity involving one user"
                            data["user"] = user

                        elif "ANUBIS_ADD_SECRET_TO_APP_DESCRIPTION_V2" in localizedKey:                                             #Unusual addition of credentials to an OAuth app involving one user
                            info = desArguments["ANUBIS_ADD_SECRET_TO_APP_DESCRIPTION_V2"]["value"]                               
                            user = info["user"]
                            app = info["app"]
                            numApps = info["num_apps"]

                            data["title"] = "Unusual addition of credentials to an OAuth app involving one user"
                            data["user"] = user
                            data["app"] = app
                            data["numApps"] = numApps

                        elif "ANUBIS_NEW_COUNTRY_FOR_TENANT_DETECTION_DESCRIPTION" in localizedKey:                                 #Activity from infrequent country involving one user
                            info = desArguments["ANUBIS_NEW_COUNTRY_FOR_TENANT_DETECTION_DESCRIPTION_SPECIFIC_COUNTRY_V3"]["value"]
                            country = info["country"]
                            days = info["days"]
                            info = desArguments["ANUBIS_NEW_COUNTRY_FOR_TENANT_DETECTION_DESCRIPTION_COUNTRIES_HEADER_USER_PREFIX_V4"]["value"]
                            num_countries = info["num_countries"]
                            user = info["username"]

                            data["title"] = "Activity from infrequent country involving one user"
                            data["country"] = country
                            data["days"] = days
                            data["info"] = info
                            data["num_countries"] = num_countries
                            data["user"] = user

                        elif "UEBA_DETECTIONS_INVESTIGATION_PRIORITY_INCREASE_DETECTION_DESCRIPTION" in localizedKey:               #8814 Investigation priority score increase
                            data["title"] = "Investigation priority score increase"

                        elif "ANUBIS_RANSOMWARE_DETECTION_MULTIPLE_EXTENSION_DESCRIPTION" in localizedKey:                          #8081 Ransomware activity involving one user
                            info = desArguments["ANUBIS_RANSOMWARE_DETECTION_MULTIPLE_EXTENSION_DESCRIPTION"]["value"]
                            extension = info["extension"]
                            user = info["user"]
                            numFiles = info["numFilesManipulatedOfExtension"]

                            data["info"] = "Ransomware activity involving one user"
                            data["extension"] = extension
                            data["user"] = user
                            data["numFiles"] = numFiles

                        elif "ANUBIS_REPEATED_ACTIVITY_DOWNLOADBYOAUTHAPPLICATION_PASSED_THRESHOLD_OVER_VALUE" in localizedKey:         #7580 Suspicious OAuth app file download activities involving one user
                            info = desArguments["ANUBIS_REPEATED_ACTIVITY_DOWNLOADBYOAUTHAPPLICATION_PASSED_THRESHOLD_OVER_VALUE"]["value"]
                            appId = info["actorApplicationId"]
                            threshold = info["threshold"]
                            user = info["user"]
                            currentValue = info["value"]

                            data["title"] = "Suspicious OAuth app file download activities involving one user"
                            data["appId"] = appId
                            data["threshold"] = threshold
                            data["user"] = user
                            data["value"] = currentValue

                        elif "ANUBIS_REPEATED_ACTIVITY_SHARE_PASSED_THRESHOLD_OVER_VALUE" in localizedKey:            #6919 Mass share involving one user
                            info = desArguments["ANUBIS_REPEATED_ACTIVITY_SHARE_PASSED_THRESHOLD_OVER_VALUE"]["value"]
                            threshold = info["threshold"]
                            user = info["user"]
                            currentValue = info["value"]

                            data["title"] = "Mass share involving one user"
                            data["threshold"] = threshold
                            data["user"] = user
                            data["value"] = currentValue

                        elif "CABINET_DISCOVERY_ALERT_BUILDER_MULTIPLE_DESCRIPTION" in localizedKey:
                            pass


                        else:
                            dbgPrint.error("Description Argument Unhandled (MCAS)")
                            raise Exception("Description Argument Unhandled (MCAS)")
                        
                    elif self.description["type"] == "AlertStoryTextOnlyWhatHappened":
                        title = self.description["title"]
                        description = self.description["text"]
                        dbgPrint.info("Title: %s" % title)
                        dbgPrint.info("Description: %s" % description)

                        if queue is not None:
                            queue.put(data)

                        data["title"] = title
                        data["description"] = description
                        logonSession = self.items[0]["cloudLogonSession"]
                        data["sessionId"] = logonSession["sessionId"]
                        data["userAgent"] = logonSession["userAgent"]
                        data["startTimeUtc"] = logonSession["startTimeUtc"]
                        account = logonSession["account"]
                        data["name"] = account["name"]
                        data["ntDomain"] = account["ntDomain"]
                        ip = self.items[0]["ip"]
                        data["address"] = ip["address"]
                        data["location"] = ip["location"]
                        data["type"] = "cloudLogonSession"
                        data["time"] = self.items[0]["time"]

                    else:
                        raise Exception("Error: Unhandled error (MCAS).")


            def parse_wdatp_alert_story(self, queue=None):
                if hasattr(self, "associated_alerts"):
                    if self.associated_alerts:
                        data = {}
                        
                        if self.details:
                            if queue is not None:
                                queue.put(data)

                            alertIds = []

                            for i in self.associated_alerts:
                                providerAlertId = i["providerAlertId"]
                                alertDisplayName = i["alertDisplayName"]
#                                dbgPrint.info("Alert Id: %s" % providerAlertId)
#                                dbgPrint.info("Title: %s" % alertDisplayName)
                                alertIds.append({"AlertId": "https://security.microsoft.com/alerts/" + providerAlertId, "DisplayName": alertDisplayName})

                            if self.type == "file":
#                                fileInfo = {}
#                                data["fileInfo"] = fileInfo    
                                
                                sha1 = [i["value"] for i in self.details if i["key"] == 'SHA1'][0] if [i for i in self.details if i["key"] == 'SHA1'] else "Not available"
                                
                                data["alertIds"] = alertIds
                                data["sha1"] = sha1
                                data["type"] = "file"

#                                fileInfo["alertIds"] = alertIds
#                                fileInfo["sha1"] = sha1
#                                dbgPrint.info("SHA1: %s" % sha1)
                                if hasattr(self, "entity"):

                                    fileName = self.entity.get("FileName", "")
                                    fullPath = self.entity.get("FullPath", "")
#                                    dbgPrint.info("FileName: %s" % fileName)
#                                    dbgPrint.info("FullPath: %s" % fullPath)

                                    data["fileName"] = [fileName]
                                    data["fullPath"] = [fullPath]

#                                    fileInfo["fileName"] = [fileName]
#                                    fileInfo["fullPath"] = [fullPath]

                                    if self.entity.get("MarkOfWeb"):
                                        markOfWeb = {}
                                        zone = self.entity["MarkOfWeb"].get("Zone","")
                                        referrer = self.entity["MarkOfWeb"].get("ReferrerUrl", "")
#                                        dbgPrint.info("Zone: %s" % zone)
#                                        dbgPrint.info("Referrer URL: %s" % referrer)

                                        markOfWeb["zone"] = zone
                                        markOfWeb["referrer"] = referrer
                                        data["markOfWeb"] = markOfWeb
#                                        fileInfo["markOfWeb"] = markOfWeb

                                else:
                                    fullPath = [i["value"] for i in self.details if i["key"] == "Path"][0] if [i["value"] for i in self.details if i["key"] == "Path"] else "Not available"
                                    data["fullPath"] = [fullPath]
#                                    fileInfo["fullPath"] = [fullPath]
                                    fileName = Path(fullPath).name
                                    data["fileName"] = [fileName]
#                                    fileInfo["fileName"] = [fileName]                       #9756   No Entity 

                                detectedFile = []
                                data["detectedFile"] = detectedFile
#                                fileInfo["detectedFile"] = detectedFile
                                for i in self.nested_item:
                                    if i.title.get("intro") == "Remediation details":
                                        if i.details:
#                                            dbgPrint.info("Single Item")
#                                            dbgPrint.info(i.title["main"])
                                            title = i.title["main"]
                                            threatName = [item["value"] for item in i.details if item["key"] == "Threat name"][0] if [item["value"] for item in i.details if item["key"] == "Threat name"] else "N/A"
                                            remediationAction = [item["value"] for item in i.details if item["key"] == "Remediation action"][0] if [item["value"] for item in i.details if item["key"] == "Remediation action"] else "N/A"
                                            remediationStatus = [item["value"] for item in i.details if item["key"] == "Remediation status"][0] if [item["value"] for item in i.details if item["key"] == "Remediation status"] else "N/A"
                                            remediationTime = [item["value"] for item in i.details if item["key"] == "Remediation time"][0] if [item["value"] for item in i.details if item["key"] == "Remediation time"] else "N/A"
                                            detectionTime = [item["value"] for item in i.details if item["key"] == "Detection time"][0] if [item["value"] for item in i.details if item["key"] == "Detection time"] else "N/A"
                                            scanSource = [item["value"] for item in i.details if item["key"] == "Scan source"][0] if [item["value"] for item in i.details if item["key"] == "Scan source"] else "N/A"
#                                            dbgPrint.info("Title: %s" % title)
#                                            dbgPrint.info("Threat Name: %s" % threatName)

                                            singleFile = {
                                                "title"             : [title], 
                                                "threatName"        : [threatName], 
                                                "sha1"              : sha1,
                                                "remediationStatus" : remediationStatus,
                                                "remediationAction" : remediationAction,
                                                "remediationTime"   : remediationTime,
                                                "detectionTime"     : detectionTime,
                                                "scanSource"        : scanSource

                                                          }
                                            detectedFile.append(singleFile)
                                            

                                        elif i.nested_item:
#                                            dbgPrint.info("Nested Item")
                                            for item in i.nested_item:
                                                file = {}
                                                title = item.title["main"]
                                                threatName = [_["value"] for _ in item.details if _["key"] == "Threat name"][0]
                                                remediationAction = [i["value"] for i in item.details if i["key"] == "Remediation action"][0] if [i["value"] for i in item.details if i["key"] == "Remediation action"] else "N/A"
                                                remediationStatus = [i["value"] for i in item.details if i["key"] == "Remediation status"][0] if [i["value"] for i in item.details if i["key"] == "Remediation status"] else "N/A"
                                                remediationTime = [i["value"] for i in item.details if i["key"] == "Remediation time"][0] if [i["value"] for i in item.details if i["key"] == "Remediation time"] else "N/A"
                                                detectionTime = [i["value"] for i in item.details if i["key"] == "Detection time"][0] if [i["value"] for i in item.details if i["key"] == "Detection time"] else "N/A"
                                                scanSource = [i["value"] for i in item.details if i["key"] == "Scan source"][0] if [i["value"] for i in item.details if i["key"] == "scan source"] else "N/A"
#                                                dbgPrint.info("Title: %s "  % title)
#                                                dbgPrint.info("Threat Name: %s" % threatName)

                                                file["title"] = title
                                                file["threatName"] = threatName

                                                sha1 = ""
                                                if hasattr(item, "entity"):
                                                    sha1 = item.entity.get("id", "")
#                                                    dbgPrint.info("SHA1: %s " % sha1)
                                                
                                                singleFile = {
                                                    "title"             : [title], 
                                                    "threatName"        : [threatName] , 
                                                    "sha1"              : sha1,
                                                    "remediationStatus" : remediationStatus,
                                                    "remediationAction" : remediationAction,
                                                    "remediationTime"   : remediationTime,
                                                    "detectionTime"     : detectionTime,
                                                    "scanSource"        : scanSource
                                                    }
                                                detectedFile.append(singleFile)


                            elif self.type == "process":             
                                


                                pid = [i["value"] for i in self.details if i["key"] == "Process id"][0] if [i["value"] for i in self.details if i["key"] == "Process id"] else -1
                                commandline = [i["value"] for i in self.details if i["key"] == "Command line"][0] if [i["value"] for i in self.details if i["key"] == "Command line"] else ""
                                sha1 = [i["value"] for i in self.details if i["key"] == "Image file SHA1"][0] if [i["value"] for i in self.details if i["key"] == "Image file SHA1"] else ""
                                path = [i["value"] for i in self.details if i["key"] == "Image file path"][0] if [i["value"] for i in self.details if i["key"] == "Image file path"] else ""
                                
                                
                                data["pid"]      = [pid]
                                data["commandline"]= [commandline]
                                data["sha1"]       = sha1
                                data["path"]       = [path]
                                data["type"]       = "process"
                                data["alertIds"]   = alertIds
                                    


#                                dbgPrint.info("Process Id: %s" % pid)
#                                dbgPrint.info("Sha1: %s" % sha1)
#                                dbgPrint.info("Command Line: %s " % commandline)
#                                dbgPrint.info("Path: %s" % path)
                                

                            elif self.type == "other":
                                if self.action_type == "registry-value":
                                  
#                                    dbgPrint.info("Activity: %s " % self.title.get("prefix", ""))
#                                    dbgPrint.info("Key: %s " % self.title.get("main", ""))
                                    value = [i["value"] for i in self.details if i["key"]== "Value name"][0] if  [i for i in self.details if i["key"]== "Value name"] else ""
                                    set_value = [i["value"] for i in self.details if i["key"]== "Set value data"][0] if [i for i in self.details if i["key"] == "Set value data"] else ""
                                    orig_value = [i["value"] for i in self.details if i["key"]== "Original value data"][0] if [i for i in self.details if i["key"] == "Original value data"] else ""


                                    data["value"] = value
                                    data["set_value"] = [set_value]
                                    data["orig_value"] = [orig_value]
                                    data["alertIds"] = alertIds
                                    data["type"] = "registry"

#                                    dbgPrint.info("Value: %s" % value)
#                                    dbgPrint.info("Set value data: %s "% set_value)
#                                    dbgPrint.info("Original value data: %s" % orig_value)


                                else:
                                    

                                    threatName = [i["value"] for i in self.details if i["key"]== "Threat name"][0] if [i["value"] for i in self.details if i["key"]== "Threat name"] else "Suspicious Activity"
#                                    dbgPrint.info("Threat name: %s" % threatName)
                                    parent = self.parent
                                    title = self.title.get("main", "")
#                                    dbgPrint.info("Alert: %s " % title)

                                    pid = ""
                                    sha1 = ""
                                    commandline = ""
                                    path = ""
                                  

                                    if self.parent is not None:
                                        
                                        pid = [i["value"] for i in parent.details if i["key"]== "Process id"][0] if [i for i in parent.details if i["key"]== "Process id"] else -1
                                        sha1 = [i["value"] for i in parent.details if i["key"] == "Image file SHA1"][0] if [i for i in parent.details if i["key"] == "Image file SHA1"] else ""
                                        commandline = [i["value"] for i in parent.details if i["key"] == "Command line"][0] if [i for i in parent.details if i["key"] == "Command line"] else ""
                                        path = [i["value"] for i in parent.details if i["key"] == "Image file path"][0] if [i["value"] for i in parent.details if i["key"] == "Image file path"] else ""

                                        
#                                        dbgPrint.info("Process Id: %s" % pid)
#                                        dbgPrint.info("Sha1: %s" % sha1)
#                                        dbgPrint.info("Command Line: %s " % commandline)
#                                        dbgPrint.info("Path: %s" % path)

                                        parent_process = {
                                        "pid"        : pid,
                                        "commandline": commandline,
                                        "sha1"       : sha1,
                                        "path"       : path
                                        }
                                    else:
                                        dbgPrint.error("No parent process")
                                        raise("No parent process")
#                                        dbgPrint.info("")

                                    data["sha1"] = sha1
                                    data["type"] = "others"
                                    data["parent"] = [{"pid"         : pid,
                                                      "commandline" : commandline,
                                                      "path"        : [path],
                                                      "alertIds"    : alertIds,
                                                      "title"       : [title],
                                                      "threatName"  : [threatName]
                                                      }]

                                    return data

#                                    data["threatName"] = [threatName]
#                                    data["title"]      = [title]
#                                    data["type"]       =  "others"
#                                    data["alertIds"] = alertIds
#                                    data["parent"] = parent_process



                            elif self.type == "url":
 
                                title = self.title.get("main", "")
                                url = self.entity.get("id", "")

                                data["title"] = title
                                data["url"]  = url
                                data["alertIds"] = alertIds
                                data["type"] = "url_wdatp"
                                

#                                dbgPrint.info("Alert: %s" % title)
#                                dbgPrint.info("Url: %s" % url)

                            elif self.type == "ip":
                                                                
                                title = self.title.get("main", "")
                                ip = self.entity.get("id", "") if hasattr(self, "entity") else "unknown" 

                                resolved = ""
                                for i in self.nested_item:
                                    resolved = i.title["main"]
                                
                                data["title"] = title,
                                data["ip"]    = ip,
                                data["resolved"] = resolved,
                                data["alertIds"] = alertIds
                                data["type"] = "ip_wdatp" 

#                                dbgPrint.info("\n")
#                                dbgPrint.info("Alert: %s" % title)
#                                dbgPrint.info("IP: %s" % ip)
#                                dbgPrint.info("Resolved name: %s" % resolved)
                                                                   

                            else:
                                dbgPrint.error("Error: Unhandled type")
                                raise Exception("Error: Unhandled type")
                        else:
                            if not self.children: 
                                if queue is not None:
                                    queue.put(data)
                                alertIds = []
                                for i in self.associated_alerts:
                                    providerAlertId = i["providerAlertId"]
                                    alertDisplayName = i["alertDisplayName"]
    #                                dbgPrint.info("Alert Id: %s" % providerAlertId)
    #                                dbgPrint.info("Title: %s" % alertDisplayName)
                                    alertIds.append({"AlertID": "https://security.microsoft.com/alerts/" + providerAlertId, "DisplayName": alertDisplayName})
                                data["type"] = "others"
                                data["title"] = self.title["main"]
                                data["alertIds"] = alertIds


                    elif self.children:
                        for i in self.children:
                            i.parse_wdatp_alert_story(queue)

        if re.search("da[a-f0-9]{18}_\-?[0-9]{4,}", alertId) or re.search("da[a-f0-9]{8,}\-[a-f0-9]{4,}\-[a-f0-9]{4,}\-[a-f0-9]{4,}\-[a-f0-9]{10,}\_[a-f0-9]{1,}", alertId):                                                                                   #Microsoft Defender for Endpoint (Antivirus) / SmartScreen
            alert_story = "https://security.microsoft.com/apiproxy/mtp/detectionAlerts/" + alertId + "//story"
            source = SOURCE_MDE
        elif re.search("fa[a-f0-9]{8}(\-[a-f0-9]{4}){3}\-[a-f0-9]{12}", alertId):                                                               #Microsoft Defender for Office 365
            alert_story = "https://security.microsoft.com/apiproxy/mtp/alertsApiService/alerts/" + alertId
#            alert_story = "https://security.microsoft.com/apiproxy/oatpalert/alerts/" + alertId[2:] + "//story"
            source = SOURCE_OATP
        elif re.search("ca[a-f0-9]{20,}", alertId) or re.search("ad[a-f0-9]{40,}", alertId):                                                    #ad-AAD Identity Protection (Identity Protection) / ca-Microsoft Defender for Cloud Apps
            alert_story = "https://security.microsoft.com/apiproxy/mtpalert/alerts/" + alertId + "//story"
            source = SOURCE_MCAS #or SOURCE_AADIP 
        elif re.search("ar[a-f0-9]{18}_\-?[0-9]{4,}" , alertId):                                                                                #Automated Investigation
            alert_story = "https://security.microsoft.com/apiproxy/mtpalert/alerts/" + alertId
            source = SOURCE_MDATP
        elif re.search("ra[0-9]{18}_\-?[0-9]{4,}", alertId):                                                                                       #Microsoft 365 Defender, Custom Detection , Manual 
            alert_story = "https://security.microsoft.com/apiproxy/mtp/k8s/ine/huntingservice/alerts/" + alertId + "//timeline"                 
            source = SOURCE_MS365D
        elif re.search("ea[0-9]{18}_\-?[0-9]{4,}", alertId):                                                                                  #ea637909026827169429_-943879980     #6521
            alert_story = "https://security.microsoft.com/apiproxy/mtp/alertsApiService/alerts/" + alertId
            source = SOURCE_MANUAL
#            raise Exception("Administrative action submitted by Administrator")
        elif re.search("ma[0-9a-f]{8,}-[0-9a-f]{4,}-[0-9a-f]{4,}-[0-9a-f]{4,}-[0-9a-f]{12,}" , alertId):
            source = SOURCE_APPGOV
            alert_story = "https://security.microsoft.com/apiproxy/mtp/alertsApiService/alerts/" + alertId + "?"
        else:
            dbgPrint.error("Alert Id not supported %s" % alertId)   
            raise Exception("Alert Id not supported %s" % alertId)                                                                                  #229 [9613]  'Bearfoos' detected on one endpoint reported by multiple sources

        params = {}
        
        for _ in range(5):
            try:
                response = self._session.get(alert_story, params=params, verify=False)
                if(response.status_code == 200):
                    break
            except:
                time.sleep(1)
        object = {}
        if response.status_code == 200:
            items = json.loads(response.text)
            if source == SOURCE_MDE:
                if items.get("items"):
                    object = [Alert(i, source) for i in items["items"]]

            elif source == SOURCE_OATP:
                if items.get("type"):
                    if items["type"] == "AlertStory":
                        object = [Alert(items, source)]
                else:
                    items["type"] = "mailMessage"
                    object = [Alert(items, source, parentClass=self)]


            elif source == SOURCE_AADIP or source == SOURCE_MCAS:
                if items.get("type"):
                    if items["type"] == "AlertStory":
                        object = [Alert(items, source)]
            elif source == SOURCE_MS365D:
                if items.get("items"):
                    object = [Alert(i, source) for i in items["items"]]
            elif source == SOURCE_MDATP:
                object = [Alert({"type": "AutomatedInvestigation", "description": "Automated investigation started manually."}, source)]
            elif source == SOURCE_MANUAL:
                items["type"] = "ManualDetection"
                object = [Alert(items, source)]
            else:
                dbgPrint.error("Unsupport Alert type")
                object = [Alert({"type": "UnsupportedType", "description": "Unsupport Alert type"})]
        elif response.status_code == 404 or response.status_code == 400:
#            raise Exception("Error 404")  
            dbgPrint.error("Error 40x")                              #
            object = [Alert({"type": "UnsupportedType", "description": "Error 404: Alert story is unavailable due to an issue we're experiencing. Please try again later."})]
        elif response.status_code == 500:
            object = [Alert({"type": "UnsupportedType", "description": "Error 500: " + response.reason})]
            dbgPrint.error("Error 500")
        else:
            dbgPrint.error("Bad request")
        return object

    def get_associated_evidences(self, incidentId, lookBackInDays=60, queue=None):

        for item in self.get_associated_alerts(incidentId, 30, 1, lookBackInDays, filter_list):
            story = self.get_alert_story(item["AlertId"])
            dbgPrint.info("\t" + item["AlertId"])
            if story:
#                for count, i in enumerate(story, start=1):
                for i in story:
                    if i.source == SOURCE_MDE:
                        i.parse_wdatp_alert_story(queue)
                    elif i.source == SOURCE_MCAS:
                        i.parse_mcas_alert_story(queue)
                    elif i.source == SOURCE_OATP:
                        i.parse_mdo_alert_story(queue)
                    elif i.source == SOURCE_MS365D:
                        i.parse_mde_alert_story(queue)
                    elif i.source == SOURCE_MDATP:
                        i.parse_mdatp_alert_story(queue)
                    elif i.source == SOURCE_MANUAL:
                        i.parse_manual_alert_story(queue)
                    elif i.type == "UnsupportedType":
                        dbgPrint.info(i.description)
                    else:
                        raise Exception("Unsupported Alert Type")

    def accumulate(self, q):
        id_list = {
        "file"              : [],
        "process"           : [],
        "others"            : [],
        "registry"          : [],
        "email"             : [],
        "ip_mdo"            : [],
        "url_wdatp"         : [],
        "ip_wdatp"          : [],
        "mdeUrl"            : [],
        "mdeEmail"          : [],
        "appCloud"          : [],
        "cloudLogonSession" : [],

        }
        accumulator = []
        old = {}
        while not q.empty():
            current = q.get()
#           pp.pprint(current)
            if current["type"] == "file":           
                id = current["sha1"]
                if id not in id_list["file"]:
                    id_list["file"].append(id)
                    result = []
                    temp_id = []
                    detectedFiles = current["detectedFile"]
                    for i in detectedFiles:
                        if i["sha1"] not in temp_id:
                            temp_id.append(i["sha1"])
                            result.append(i)
                        else:
                            object = [a for a in result if a["sha1"] == i["sha1"]][0]
                            if i["threatName"][0] not in object["threatName"]:
                                object["threatName"].append(i["threatName"][0])
                            if i["title"][0] not in object["title"]:
                                object["title"].append(i["title"][0])
                    current["detectedFile"] = result
                    accumulator.append(current)
                else:
                    object = [i for i in accumulator if i["type"] == "file" and i["sha1"] == id][0]
                    if current != object:
                        for i in current["alertIds"]:
                            if i not in object["alertIds"]:
                                object["alertIds"].append(i)
                        if current["fileName"][0] not in object["fileName"]:
                            object["fileName"].append(current["fileName"][0])
                        if current["fullPath"][0] not in object["fullPath"]:
                            object["fullPath"].append(current["fullPath"][0])
                        result = []
                        temp_list = []
                        object["detectedFile"].extend(current["detectedFile"])
                        for i in object["detectedFile"]:
                            if i["sha1"] not in temp_list:
                                temp_list.append(i["sha1"])
                                result.append(i)
                            else:
                                temp = [a for a in result if a["sha1"] == i["sha1"]][0]
                                if i["title"][0] not in temp["title"]:
                                    temp["title"].append(i["title"][0])
                                if i["threatName"][0] not in temp["threatName"]:
                                    temp["threatName"].append(i["threatName"][0])

                        object["detectedFile"] = result

            elif current["type"] == "url_wdatp":
                id = current["url"]
                if id not in id_list["url_wdatp"]:
                    id_list["url_wdatp"].append(id)
                    accumulator.append(current)
                else:
                    object = [i for i in accumulator if i["type"]=="url_wdatp" and i["url"]== id][0]
                    if current != object:
                        old = [i["AlertId"] for i in object["alertIds"]] if [i["AlertId"] for i in object["alertIds"]] else []
                        new = [i for i in current["alertIds"] if i["AlertId"] not in old][0]  if  [i for i in current["alertIds"] if i["AlertId"] not in old] else []
                        if new:
                            object["alertIds"].append(new)
#                           raise("URL WDATP duplicate!")

            elif current["type"] == "process":
                id = current["sha1"]
                if id not in id_list["process"]:
                    id_list["process"].append(id)
                    accumulator.append(current)
                else:
                    object = [i for i in accumulator if i["type"] == "process" and i["sha1"] == id][0]
                    if current["pid"][0] not in object["pid"]:
                        object["pid"].append(current["pid"][0])
                    if current["commandline"][0] not in object["commandline"]:
                        object["commandline"].append(current["commandline"][0])
                    if current["path"][0] not in object["path"]:
                        object["path"].append(current["path"][0])
                    for i in current["alertIds"]:
                        if i not in object["alertIds"]:
                            object["alertIds"].append(i)     
                           
            elif current["type"] == "registry":

                id = current["value"]
                if id not in id_list["registry"]:
                    id_list["registry"].append(id)
                    accumulator.append(current)
                else:
                    object = [i for i in accumulator if i["type"] == "registry" and i["value"] == id][0]
                    if object != current:
                        if object["set_value"] != current["set_value"]:
                            object["set_value"].append(current["set_value"])
                        if object["orig_value"] != current["orig_value"]:
                            object["orig_value"] != current["orig_value"]
                        displayName = [i["DisplayName"] for i in parent["alertIds"]]
                        for i in parent["alertIds"]:
                            if i["DisplayName"] not in [a["DisplayName"] for a in object["alertIds"]] :
                                object["alertIds"].append(i)

            elif current["type"] == "ip_mdo":
                id = current["ip"]
           
            elif current["type"] == "ip_wdatp":
                id = current["ip"]
                if id not in id_list["ip_wdatp"]:
                    accumulator.append(current)
                else:
                    raise("IP WDATP duplicate!")
                    
                    
            elif current["type"] == "others":
                if current.get("parent"):
                    parent = current["parent"][0]
                    id = current["sha1"]
                    if id not in id_list["others"]:
                        id_list["others"].append(id)
                        accumulator.append(current)
                    else:
                        object = [i for i in accumulator if i["type"] == "others" and i["sha1"] == id][0]
                        if [i for i in object["parent"] if i["commandline"] == parent["commandline"]]:
                            old_object = [i for i in object["parent"] if i["commandline"] == parent["commandline"]][0]
                            if old_object["pid"] == parent["pid"]:
                                if old_object["path"] != parent["path"]:
                                    old_object["path"].append(parent["path"])
                                displayName = [i["DisplayName"] for i in parent["alertIds"]]

                                for i in parent["alertIds"]:
                                    if i["DisplayName"] not in [a["DisplayName"] for a in old_object["alertIds"]] :
                                        old_object["alertIds"].append(i)
                                if parent["threatName"] and parent["threatName"][0] not in old_object["threatName"]:
                                    old_object["threatName"].append(parent["threatName"][0])
                        else:
                            object["parent"].append(parent)
                else:
                    accumulator.append(current)

            elif current["type"] == "mdeUrl":
                id = current["netMsgId"]
                if id not in id_list["mdeUrl"]:
                    id_list["mdeUrl"].append(id)
                    accumulator.append(current)
                else:
                    raise("mdeUrl dupplicate!")

            elif current["type"] == "mdeEmail":
                id = current["recipient"]
                if id not in id_list["mdeEmail"]:
                    id_list["mdeEmail"].append(id)
                    accumulator.append(current)
                else:
                    raise("MDE Email duplicate!")


            elif current["type"]  == "appCloud":
                id = current["objectId"]
                if id not in id_list["appCloud"]:
                    id_list["appCloud"].append(id)
                    accumulator.append(current)
                else:
                    raise("appCloud duplicate!")
               
            elif current["type"] == "cloudLogonSession":
                id = current["sessionId"]
                if id not in id_list["cloudLogonSession"]:
                    id_list["cloudLogonSession"].append(id)
                    accumulator.append(current)
                else:
                    dbgPrint.warning("Logon Session Duplicate")


            elif current["type"] == "mailMessage":
                if current.get("relatedEntities"):
                    for id in current["relatedEntities"]:
                        if id["recipient"] not in id_list["email"]:
                            id_list["email"].append(id["recipient"])
                            id["alertId"] = current["alertId"]
                            id["displayName"] = current["displayName"]
                            id["description"] = current["description"]
                            accumulator.append(id)
                        else:
                            object = [i for i in accumulator if i.get("type")=="email" and i["recipient"] == id["recipient"]][0]
                            if id != object:
    #                            print("Not same")
                                if id["threats"] != object["threats"]:
                                    object["threats"] = list(set(object["threats"]) | set(id["threats"]))
                                if id["urls"]:
    #                                object["urls"] = list(set(id["urls"]) | set(object["urls"]))
                                    for x in id["urls"]:
                                        if x["url"] not in [i["url"] for i in object["urls"]]:
                                            object["urls"].append(x)
    #                            if id["files"] != object["files"]:
    #                                object["files"] = list(set(id["files"]) | set(object["files"]))            #Unhashable dictionary
                                if id["senderIP"] != object["senderIP"]:
                                    for y in id["senderIP"]:
                                        if y not in object["senderIP"]:
                                            object["senderIP"].append(y)
    #                                object["senderIP"] = list(set("senderIP") | set(object["senderIP"]))
                                if id["p2SenderDisplayName"] != object["p2SenderDisplayName"]:
                                    object["p2SenderDisplayName"] = list(set(id["p2SenderDisplayName"]) | set(object["p2SenderDisplayName"]))
                                if id["subject"] != object["subject"]:
                                    object["subject"] = list(set(id["subject"]) | set(object["subject"]))
                else:
                    for id in current["impactedEntities"]:
                        temp = {}
                        temp["alertId"] = current["alertId"]
                        temp["displayName"] = current["displayName"]
                        temp["description"] = current["description"]
                        temp["impactedEntities"] = {
                            "user"      : id["displayName"],
                            "mailbox"   : id["mailboxAddress"] 
                            }
                        accumulator.append(temp)                
#            dbgPrint.info(current)
        return accumulator

    def get_audit_history(self, incidentId):

        classifications = {
            20 : "True Positive",
            10 : "False Positive",
            30 : "Informational, Expected Activity"
            }

        determinations = {
            140 : "Line of Business Application", 
            130 : "Confirmed Activity",
            120 : "Not Enough Data to Validata",
            110 : "Not Malicious",
            100 : "Malicious User Activity",
            90  : "Phishing",
            80  : "Compromised Account",
            70  : "Multi Stage Attack",
            60  : "Other",
            50  : "Unwanted Software",
            40  : "Security Testing",
            20  : "Malware",
            }

        audit_history = "https://security.microsoft.com/apiproxy/mtp/auditHistory/AuditHistory"

        params = {
            'entityType' : 'IncidentEntity',
            'id'         : incidentId,
            'pageIndex'  : 1,
            'pageSize'   : 100
            }
        response = self.tryrequest(audit_history, params=params)

        sorted_list = sorted(json.loads(response.text), key=lambda x: x["auditId"])
        #1 - Undefine   Unassigned 
        #2 - Resolved  
        #4 - Progress


        assigned_timestamp = ""
        resolved_timestamp = ""
        assignee = ""
        feedback = ""
        classification = ""
        determination = ""
        for x in range(len(sorted_list)):
            out = {k:v for k,v in [i for i in sorted_list][x].items()}
            if out["type"] == "Status" and out["newValue"] == '4':   #Changed Status to progress
                assigned_timestamp = out["timestamp"]
                assignee = out["createdBy"]
            elif out["type"] == "Status" and out["newValue"] == '2':
                resolved_timestamp = out["timestamp"]
            elif out["type"] == "Feedback":
                feedback = out["newValue"]
            elif out["type"] == "Classification":
                classification = out["newValue"]
            elif out["type"] == "Determination":
                determination = out["newValue"]

        if assigned_timestamp:
            utc_time = parser.parse(assigned_timestamp)
            utc_time = utc_time.replace(tzinfo=pytz.UTC) #replace method      
            ph_time=utc_time.astimezone(tz)        #astimezone method
            assigned_timestamp   = ph_time.strftime('%Y-%m-%d %H:%M:%S GMT+8')
        if resolved_timestamp:
            utc_time = parser.parse(resolved_timestamp)
            utc_time = utc_time.replace(tzinfo=pytz.UTC) #replace method      
            ph_time=utc_time.astimezone(tz)        #astimezone method
            resolved_timestamp   = ph_time.strftime('%Y-%m-%d %H:%M:%S GMT+8')

        audit = {
            "assignee"          : assignee,
            "assignedTimestamp" : assigned_timestamp,
            "resolvedTimestamp" : resolved_timestamp,
            "feedback"          : feedback,
            "classification"    : classifications[int(classification)] if classification else "",
            "determination"     : determinations[int(determination)] if determination else ""
            }
        
        # Determination - 0 - 69 True Positive
        # Classification - 0 - 20 Others
        # Feedback 

        return audit


    def get_file_info(self, hash):

        file_info = "https://security.microsoft.com/apiproxy/mtp/virusFileReport/VirusTotalFileReport/" 

        params = {
            "fileIdentifier" : hash
            }

        response = self.tryrequest(file_info, params=params)
        info = json.loads(response.text)

        if len(hash) != 40:
            info.update({"sha256" : hash.lower()})
        else:
            info.update({"sha1" : hash.lower()})
        
        return info