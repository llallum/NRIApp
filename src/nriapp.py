#!/usr/bin/python
#this is a test
import os, sys
import time
import requests, json, pickle, ast
import queue
import re
from core import msgraphapi as graphapi 
from core import mssentinelapi as defender
from core import multifactor as mfaauth
from core.abuseipdbapi import ipquery
from helper import requestheader as helper
from helper import login
from helper.doc import *
from helper.doc import WordDoc
from helper.excel import WorkBook
from loguru import logger
from docx import Document
import argparse
from datetime import datetime
from dateutil import parser
import pytz    
import json
from config.config import *
import configparser
import pandas as pd

requests.packages.urllib3.disable_warnings()        #Disable requests warning logs

logger.add(f"./logs/{__name__}.log", mode="w", backtrace=True, diagnose=True, level="INFO", filter="ChromeDriver")
#logger.disable(__name__)
dbgPrint = logger
#dbgPrint.disable(__name__)
dbgPrint.disable("core.mssentinelapi")
dbgPrint.disable("core.msgraphapi")
dbgPrint.disable("helper.login")

tz = pytz.timezone('Asia/Hong_Kong')

class NriApp:
    def __init__(self, args):
        self.args = args
        self.__company_name = ""
        self.__country = ""
        tracker = {}
#        self.email = self.args.get("email", "")
#        self.output = self.args.get("output",  os.path.abspath(os.path.dirname(__file__)) + "\\output")
        

       
        self.write_config()
        self.read_config()

        if self.email and not hasattr(self, "msgraph"):
            self.msgraph = graphapi.MSGraphApi(self.email).load_session()
            self.mfa = mfaauth.MultiFactor(self.email).load_session()
            self.sentinel = defender.MSSentinelApi(self.email).load_session()

            
    def write_config(self):
        self.config = configparser.ConfigParser()
        self.config.read("config.ini")
        flag = False
        if self.args.get("email"):
            if self.config.has_section("email"):
                flag = True
                self.config.set("email", "address", self.args["email"])
#                self.config['email']['address'] = self.args["email"]
#                self.email = self.args["email"]
            else:
                flag = True
                self.config.add_section("email")
                self.config["email"]["address"] = self.args["email"]
#                self.email = self.args["email"]
            

        if self.args.get("output"):
            if self.config.has_section("folder"):
                if not os.path.exists(self.args["output"]):
                    os.makedirs(self.output)     
                self.config.set("folder", "output", self.args["output"])
                flag = True
            else:
                self.config.add_section('folder')
                self.config['folder']['output'] = self.args["output"]
                self.output = self.args["output"]
                if not os.path.exists(self.output):
                    os.makedirs(self.output)
                flag = True

#        else:
#            self.config.add_section('folder')
#            self.config['folder']['output'] = os.path.abspath(os.path.dirname(__file__))
#            self.output = os.path.abspath(os.path.dirname(__file__)) + "\\output"

        if self.args.get("companytags"):
            if self.config.has_section("companyTags"): 
                if os.path.exists(self.args["companytags"]):
                    self.config.set("companyTags", "path", self.args["companytags"])
 #                   self.config["companyTags"]["path"] = self.args["companytags"]
                    flag = True
                else:
                    dbgPrint.error("No such file {sample}", sample=self.args["companytags"])
                    sys.exit()
            else:
                self.config.add_section("companyTags")
                self.config["companyTags"]["path"] = self.args["companytags"]
                if os.path.exists(self.args["companytags"]):
                    self.config["companyTags"]["path"] = self.args["companytags"]
                    flag = True
                
#        else:
#            self.config.add_section('companyTags')
#            self.config["companyTags"]["Path"] = os.path.abspath(os.path.dirname(__file__) + "\\companyTags.csv") 
        if flag:
            with open(os.path.abspath(os.path.dirname(__file__)) + '\config.ini', 'w+') as configfile:
                self.config.write(configfile)
                dbgPrint.info("Config has been setup.")
                exit(0)
           

    def read_config(self):

        if os.path.exists(os.path.abspath(os.path.dirname(__file__)) + '\\config.ini'):
            self.config.read(os.path.abspath(os.path.dirname(__file__)) + '\\config.ini')
            if self.config.has_section('email'):
                self.email = self.config['email']['address']   
            else:
                dbgPrint.error("Email required. Use -e or --email first to store your email address in config.")
                sys.exit()
            if self.config.has_section('folder'):
                self.output = self.config['folder']['output']
            else:
                dbgPrint.error("No output folder yet. Use -o or --output to store the files.")
                sys.exit()

            if self.config.has_section('companyTags'):
                if os.path.exists(self.config["companyTags"]["path"]):
                    df = pd.read_csv(self.config["companyTags"]["path"])
                    df = df.reset_index() 
                    self.tags = [{"Tag": row["Tag"], "Country": row["Country"] , "Company": row["Company"]}  for index, row in df.iterrows()]
                else:
                    dbgPrint.error("{a} does not exist", a=self.config["companyTags"]["path"])
                    sys.exit(1)
            else:
                dbgPrint.error("No company tags csv yet")
                sys.exit(1)

        else:
            dbgPrint.error("Setup configuration first. Use -h --help for help.")
            sys.exit(1)


    def user_summary(self, query):

        user_object = self.msgraph.search_user(query)[0] if self.msgraph.search_user(query) else {}
        temp = {}
        if user_object:
            if user_object["companyName"] != None:
                temp["companyName"] = user_object["companyName"]
            if user_object["country"] != None:
                temp["country"] = user_object["country"]
            if user_object["displayName"] != None:
                temp["name"] = user_object["displayName"]
            if user_object["userPrincipalName"] != None:
                temp["email"] = user_object["userPrincipalName"]
                mfa = self.msgraph.check_mfa_status(user_object["userPrincipalName"])
                if mfa:
                    temp["MFAStatus"] = mfa[0]["isMfaRegistered"]
                else:
                        temp["MFAStatus"] = "Probably not registered"
            if query != None:
                temp["groups"] = self.msgraph.get_user_groups(query)
        return temp

        def ip_summary(self, param, ip_list):
            ip = param.get("senderIP", "")
            if ip:
                return list(set(ip + ip_list))
            else:
                return ip_list

    def file_summary(self, param, hash_list):
        def walk_dict(object, list_object):
            if isinstance(object, dict):
                for k,v in object.items():
                    if isinstance(v, dict):
                        walk_dict(v, list_object)
                    elif isinstance(v, list):
                        for a in v:
                             walk_dict(a, list_object)
                    elif isinstance(v, str) or isinstance(v, int):
                        if k == "hash" or k == "sha256" or k == "sha1":
                            if v.lower() not in list_object:
                                list_object.append(v)
            elif isinstance(object, list):
                for a in object:
                    walk_dict(a, list_object)
            return list_object
      
        hash_list = walk_dict(param, hash_list)
        return hash_list

    def recipient_summary(self, param, hash_list):
        def walk_dict(object, list_object):
            if isinstance(object, dict):
                for k,v in object.items():
                    if isinstance(v, dict):
                        walk_dict(v, list_object)
                    elif isinstance(v, list):
                        for a in v:
                             walk_dict(a, list_object)
                    elif isinstance(v, str) or isinstance(v, int):
                        if k == "recipient":
                            if v.lower() not in list_object:
                                list_object.append(v)
            elif isinstance(object, list):
                for a in object:
                    walk_dict(a, list_object)
            return list_object
      
        hash_list = walk_dict(param, hash_list)
        return hash_list

    def format_userinfo(self, user_object):
        temp = {}

        if user_object["companyName"] != None:
            temp["companyName"] = user_object["companyName"]
            for i in self.tags:
                if i["Tag"].lower() == user_object["companyName"].lower():
                    self.__company_name = user_object["companyName"]
                    self.__country = i["Country"]
        if user_object["country"] != None:
            temp["country"] = user_object["country"]
        if user_object["usageLocation"] != None:
            temp["usageLocation"] = user_object["usageLocation"]
        if user_object["displayName"] != None:
            temp["name"] = user_object["displayName"] + " (" + user_object["userPrincipalName"] + ")"
        if user_object["userPrincipalName"] != None:
            temp["email"] = user_object["userPrincipalName"]
            mfa = self.msgraph.check_mfa_status(user_object["userPrincipalName"])
            if mfa:
                temp["MFAStatus"] = mfa[0]["isMfaRegistered"]
            else:
                temp["MFAStatus"] = "Probably not registered"
        return temp

    def device_country(self, device_name):
        pass

    def summary(self, param):
        data = {}
        incidentId = param["IncidentId"]
        title = param["Title"]
        severity = [k for k,v in param["AlertsSeveritiesSummary"].items()]
        categories = param["Categories"]
        firstActivity = param["FirstEventTime"]
        lastActivity = param["LastEventTime"]
        deviceTags = param["IncidentTags"]["DeviceTags"]
        machines = param["ImpactedEntities"]["Machines"]
        users = param["ImpactedEntities"]["Users"]
        mailboxes = param["ImpactedEntities"]["Mailboxes"]
        dSource = param["DetectionSources"]

        source_list = {
            1       : "Endpoint Detection and Response (EDR)",
            2       : "Antivirus", 
            4       : "SmartScreen", 
            32      : "Custom TI",
            512     : "Microsoft Defender for Office 365 (MDO)",
            16384   : "Microsoft Defender for Cloud Apps (MCAS)",
            32768   : "Microsoft 365 Defender",
            65536   : "Identity Protection",
            }

        source = []
        for i in dSource:
            try:
                source.append(source_list[i])
            except:
                dbgPrint.error("Unknown source : {value}", value=i)
                continue

#        computerName = param["ComputerDnsName"]
        users_list = []
        for i in users:
            temp = {}
            displayName = i["DisplayName"]
            userName = i["UserName"]
            userSid = i["UserSid"]
            query = ""
            if displayName != None:
                query = displayName
            elif userName != None:
                query = userName
            elif userSid != None:
                query = userSid
            user_object = self.msgraph.search_user(query)[0] if self.msgraph.search_user(query) else {}
            if user_object:
                temp = self.format_userinfo(user_object)
                if query != None:
                    temp["groups"] = self.msgraph.get_user_groups(query)
                users_list.append(temp)

        device_list = []
        for i in machines:
            temp = {}
            computerName = i["ComputerDnsName"]
            exposureScore = i["ExposureScore"]
            device_object = self.msgraph.search_device_by_name_beta(computerName.split(".")[0])
            device_object = self.msgraph.search_device_by_name(computerName.split(".")[0])[0] if self.msgraph.search_device_by_name(computerName.split(".")[0]) else {}
            if device_object:
                if device_object["deviceName"] != 'none':
                    temp["deviceName"] = device_object["deviceName"]
                    for i in self.tags:
                        if i["Tag"].lower() == device_object["deviceName"].split("-")[0].lower().rstrip('0123456789'):
                            self.__company_name = i["Tag"]
                            self.__country = i["Country"]
                if device_object["complianceState"] != 'none':
                    temp["complianceState"] = device_object["complianceState"]
                if device_object["osVersion"] != 'none':
                    temp["osVersion"] = device_object["osVersion"]
                if device_object["userPrincipalName"] != 'none':
                    user_object = self.msgraph.search_user(device_object["userPrincipalName"])[0] if self.msgraph.search_user(device_object["userPrincipalName"]) else {}
                    user = {}
#                    temp["userPrincipalName"] = user
                    if user_object:
                        user = self.format_userinfo(user_object)
    #                temp["userPrincipalName"] = device_object["userPrincipalName"]
                    user["groups"] = self.msgraph.get_user_groups(device_object["userPrincipalName"])
                    temp["Owner"] = user
                device_list.append(temp)

        mailbox_list = []
        for i in mailboxes:
            temp = {}
            userPrincipalName = i["Upn"]
            user_object = self.msgraph.search_user(userPrincipalName)[0] if self.msgraph.search_user(userPrincipalName) else {}
            if user_object:
                temp = self.format_userinfo(user_object)
                temp["groups"] = self.msgraph.get_user_groups(userPrincipalName)
                mailbox_list.append(temp)
        
        impactedAssets = {"users"       : users_list, 
                         "machines"     : device_list,
                         "mailboxes"    : mailbox_list
                         }


        if deviceTags:
            for i in self.tags:
                if i["Tag"].lower() == deviceTags[0].split("_")[0].lower():
                    self.__company_name = i["Tag"].upper()
                    self.__country = i["Country"]
                    break

        data["incidentID"]      = incidentId
        data["incidentTitle"]   = title
        data["categories"]      = categories
        data["severity"]        = severity
        data["CSIRTSeverity"]  = " "
        data["verdict"] = ""
        if source:
            data["detectionSource"] = source
        utc_time = parser.parse(firstActivity)
        utc_time = utc_time.replace(tzinfo=pytz.UTC) #replace method      
        ph_time=utc_time.astimezone(tz)        #astimezone method
        data["firstActivity"]   = ph_time.strftime('%Y-%m-%d %H:%M:%S GMT+8')
        utc_time = parser.parse(lastActivity)
        utc_time =utc_time.replace(tzinfo=pytz.UTC) #replace method      
        ph_time=utc_time.astimezone(tz)        #astimezone method
        data["lastActivity"]    = ph_time.strftime('%Y-%m-%d %H:%M:%S GMT+8')
        if self.__company_name and self.__country:
            data["companyName/Country"] = self.__company_name + " - " + self.__country
        elif self.__company_name:
            data["companyName/Country"] = self.__company_name
        else:
            data["companyName/Country"] = "N/A"
#        if computerName:
#            data["computerName"]    = computerName
        data["deviceTags"]      = deviceTags
        data["impactedAssets"]  = impactedAssets

        self.__company_name = ""
        self.__country = ""

        return data
    
    def ip_summary(self, param, ip_list):
        ip = param.get("senderIP", "")
        if ip:
            return list(set(ip + ip_list))
        else:
            return ip_list


    def excel_tracker(self, out):
        data = {}
        if out.get("firstActivity"):
            data["FirstActivity"] = out["firstActivity"]

        company = []
        if out.get("impactedAssets"):
            impacted = out["impactedAssets"]
            if impacted["users"]:
                for a in impacted["users"]:
                    for x, y in a.items():
                        if x == "userPrincipalName":
                            if y["companyName"] not in company:
                                company.append(y["companyName"])
            elif impacted["machines"]:
                for a in impacted["machines"]:
                    for x, y in a.items():
                        if x == "userPrincipalName":
                            if y["companyName"] not in company:
                                company.append(y["companyName"])
            elif impacted["mailboxes"]:
                for a in impacted["mailboxes"]:
                    for x,y in a.items():
                        if x == "userPrincipalName":
                            if y["companyName"] not in company:
                                company.append(y["companyName"])

            

    def get_full_report(self, args=None, lookBackInDays=180):
        incidents = self.sentinel.get_incidents(incidentId=args, alertStatus=['New','InProgress', 'Resolved'] , severity=[256,128,64,32], pageIndex=1, lookBackInDays=lookBackInDays, pageSize=3000, sourceFilter=[16384, 1048576], titleFilter=["eDiscovery"])       #16384 == MCAS incidents 512 = eDiscovery
        if args != None:
            all_data = {}
#            incidents = self.sentinel.get_incidents(incidentId=args, alertStatus=['New','InProgress', 'Resolved'] , severity=[256,128,64,32], pageIndex=1, lookBackInDays=180, pageSize=3000, sourceFilter=[16384, 65536, 1048576])       

# Identity Protection   65536
# MS 365 Defender       32768
# MCAS                  16384
# MDO                   512
# Custom TI             32
# SmartScreen           4
# Antivirus             2
# EDR                   1

            doc = WordDoc()
#            xls = WorkBook(self.output + "\\" + args + "xlsx")
            ip_list = []
            hash_list = []
            recipient = []
            for i in range(1):
                q = queue.Queue()    
                self.sentinel.get_associated_evidences(args, queue=q, lookBackInDays = lookBackInDays)
                out = self.summary(incidents[0])
                doc.title(out["incidentTitle"])
                doc.author(self.email)
                doc.traverse(out)
#                self.excel_tracker(out)
                all_data = self.sentinel.accumulate(q)
                for a in all_data:
                    doc.insertHR(doc.insert_paragraph())

                    doc.traverse(a)

                    ip_list = self.ip_summary(a, ip_list)
                    hash_list = self.file_summary(a, hash_list)
                    recipient = self.recipient_summary(a, recipient)

            doc.insertHR(doc.insert_paragraph())
            doc.add_run("Additional Details")
            doc.traverse([ipquery.check_endpoint(i) for i in ip_list])
            doc.insertHR(doc.insert_paragraph())
            doc.traverse([self.sentinel.get_file_info(i) for i in hash_list])
            doc.insertHR(doc.insert_paragraph())
            doc.traverse([self.user_summary(i) for i in recipient])
            doc.insertHR(doc.insert_paragraph())
            doc.traverse(self.sentinel.get_audit_history(args))
            doc.save(self.output + "\\" + args + ".docx")
            os.startfile(self.output + "\\" + args + ".docx")

        else:
            all_data = {}
            for count, i in enumerate(incidents, start=1):
                doc = WordDoc()
                ip_list = []
                hash_list = []
                recipient = []
                q = queue.Queue()
                out = self.summary(i)
                doc.title(out["incidentTitle"])
                doc.author(self.email)
                doc.traverse(out)
                self.sentinel.get_associated_evidences(i["IncidentId"], queue=q, lookBackInDays=lookBackInDays)   
                dbgPrint.info(i["IncidentId"])
                all_data = self.sentinel.accumulate(q)
                for a in all_data:
                    doc.insertHR(doc.insert_paragraph())
                    ip_list = self.ip_summary(a, ip_list)
                    hash_list = self.file_summary(a, hash_list)
                    recipient = self.recipient_summary(a, recipient)

                    doc.traverse(a)

                doc.insertHR(doc.insert_paragraph())
                doc.add_run("Additional Details")
                doc.traverse([ipquery.check_endpoint(i) for i in ip_list])
                doc.insertHR(doc.insert_paragraph())
                doc.traverse([self.sentinel.get_file_info(i) for i in hash_list])
                doc.insertHR(doc.insert_paragraph())
                doc.traverse([self.user_summary(i) for i in recipient])
                doc.insertHR(doc.insert_paragraph())
                doc.traverse(self.sentinel.get_audit_history(i["IncidentId"]))
                doc.save(self.output + "\\" + str(i["IncidentId"]) + ".docx")
            
#                os.startfile(self.output + "\\output\\" + str(i["IncidentId"]) + ".docx")    

    def dispatcher(self):
        args = self.args
        path = os.path.dirname(os.path.realpath(__file__))
        if args.get("verbose"):
            val = int(args.get("verbose"))
#            if  val == 1:
#                dbgPrint.enable(__name__)
            if val == 2:
                dbgPrint.enable("core.mssentinelapi")
            elif val == 3:
                dbgPrint.enable("core.msgraphapi")
            elif val == 4:
                dbgPrint.enable("helper.login")
            elif val == 5:
                dbgPrint.enable(__name__)
                dbgPrint.enable("core.mssentinelapi")
                dbgPrint.enable("core.msgraphapi")
                dbgPrint.enable("helper.login")
            else:
                dbgPrint.error("Unknown value")
                sys.exit()
        if args.get("clear"):
            pass
        if args.get("user"):
            self.__init__(args)
            user_info = self.msgraph.check_mfa_status(args.get("user"))
#            if user_info:
#                printTable(user_info)
#            user_info = self.msgraph.search_user(args.get("user"))
        elif args.get("incidentId"):
            self.__init__(args)
            start = time.time()
            dbgPrint.info("Processing {value}", value=args.get("incidentId"))
            self.get_full_report(args.get("incidentId"), lookBackInDays=args.get("daysgo", 30))
            end = time.time()
            dbgPrint.success("Job done (Elapsed time {value}).", value=end-start)
        elif args.get("all"):
            start = time.time()
            dbgPrint.info("Processing all incidents")
            self.get_full_report(lookBackInDays=args.get("daysago", 30))
            end = time.time()
            dbgPrint.success("Job done (Elapsed time {value}).", value=end-start)
            return

    #------------------------------------------------------

def parse_argument():

    parser = argparse.ArgumentParser(
        prog = 'ChromeDriver',
        description  = 'This tool is used to retrieve all the necessary informaation of the incident',
        epilog = '',
        formatter_class=argparse.RawTextHelpFormatter
        )
#    group = parser.add_mutually_exclusive_group(required=True)

    parser.add_argument('-id', '--incidentId',help= "Select incident ID \n")
    parser.add_argument('-a', '--all', help= "Process all incidents \n" , action='store_true')
    parser.add_argument('-v', '--verbose', help="Enable logging with specific level \n"
                                                "1 : main \n"
                                                "2 : sentinel \n"
                                                "3 : msgraph \n"
                                                "4 : login \n"
                                                "5 : enable all")
#    parser.add_argument('-r', '--reset', help="Reset the session and restart", action="store_true")
    parser.add_argument('-e', '--email', help="Set email address.")
#    parser.add_argument('-u', '--user', help = "Fetch user info")
    parser.add_argument('-o', '--output', help = "Set output folder.")
#    parser.add_argument('-c','--clear', help = "Clear cache", action="store_true")
    parser.add_argument('-d', '--daysago', help="Look back in days. Default=30")
 
    parser.add_argument('-c', '--companytags',help="CSV of company tags <Tag> <Company> <Country> to identify which country does a user belong.")

    args = parser.parse_args()

    if args.incidentId and args.all:
        parser.error("Required only one between -id/--incidentId and -a/--all.")

    if len(sys.argv)==1:
        # display help message when no args are passed.
        parser.print_help()
        sys.exit(1)

    return args 

if __name__ == "__main__":

    args = parse_argument()
    myapp = NriApp(vars(args))
    myapp.dispatcher()
#    main(args)