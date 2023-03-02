
from seleniumwire import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from webdriver_manager.chrome import ChromeDriverManager            #for ChromeDriver installation
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException


import sys, json
sys.path.append("..") # Adds higher directory to python modules path.

from config.config import *

from core import mssentinelapi as mde
from core import msgraphapi as msgraph
from core import multifactor as mfa
from helper import requestheader as helper


#import MSSentinelApi as mde
#import MSGraphAPI as msgraph
#import MSGraphApi as graphapi
#import RequestHeader as helper
#from PyLog import *
import logging
from loguru import logger

import time, os, re, pickle
from pathlib import Path

security_page = 'https://security.microsoft.com/incidents?tid=' + TENANT_ID
azuread_page = 'https://portal.azure.com/api/DelegationToken?feature.cacheextensionapp=true&feature.internalgraphapiversion=true&feature.tokencaching=true'
Endpoint_page = 'https://endpoint.microsoft.com/api/DelegationToken?feature.internalgraphapiversion=true&feature.tokencaching=true'

#dbgPrint = PyLog(__name__, level=logging.INFO, store=False, consolePrint=True)

logger.add(f"./logs/{__name__}.log",mode="w", backtrace=True, diagnose=True, level="DEBUG", filter="Login")
#logger.add(sys.stdout, backtrace=True, diagnose=True)
dbgPrint = logger
class Login(object):
    """description of class"""
    def __init__(self, email=None):
        if email != None:
            self.email = email

    def delete_session(self):
        for p in Path("./session").glob("*.pkl"):
            os.remove(p)


    def wait(self, driver, timeout, type, element):
        while True:
            try:
                WebDriverWait(driver, 20).until(EC.visibility_of_element_located((type, element)))
                break
            except TimeoutException:
                dbgPrint.warning("[-] Loading took too much time!!!")
        dbgPrint.debug("[+] Your webpage is ready...")

    def login(self):

        dbgPrint.info("[+] Checking session...")

        if not os.path.exists('./session/ms365.pkl'):
            dbgPrint.debug("[-] Session does not exists...")
            options = webdriver.ChromeOptions()
            options.add_argument('--disable-logging')
            options.add_experimental_option('excludeSwitches', ['enable-logging'])          #Disable logging of webdriver
            driver = webdriver.Chrome(ChromeDriverManager().install(), options=options)

            dbgPrint.info("[-] ./session/MS365Dheaders.pkl and ./session/MS365Dcookies.pkl does not exist")
            time.sleep(1)
            dbgPrint.debug("[+] Starting new session...")
            #options = webdriver.EdgeOptions()
            #driver = webdriver.Edge(options=options)
            dbgPrint.debug("[+] Logging in...")
            driver.get(security_page)
            
            dbgPrint.debug("[+] Enter your One-Time Code...")
            self.wait(driver, 20, By.NAME, 'loginfmt')
            driver.find_element(By.NAME, 'loginfmt').send_keys(self.email)
            driver.find_element(By.ID, 'idSIButton9').click()

            override = False
            current_URL = driver.current_url
            while True:
                one_time_code = WebDriverWait(driver, 20).until(EC.visibility_of_element_located((By.XPATH, "//input[@id='idTxtBx_OTC_Password']"))).get_attribute("value")
                while len(one_time_code) < 8:
                    time.sleep(2)                      
                    try:
                        one_time_code = WebDriverWait(driver, 20).until(EC.visibility_of_element_located((By.XPATH, "//input[@id='idTxtBx_OTC_Password']"))).get_attribute("value")
                    except:
                        if "https://security.microsoft.com" in driver.current_url:
                            dbgPrint.debug("[+] Button override")
                            override = True
                            break
                if not override:
                    driver.find_element(By.ID, "idSIButton9").click()
                    time.sleep(3)                           
                    dbgPrint.debug("[+] Your one time code is : %s" % one_time_code)
                if "https://security.microsoft.com" in driver.current_url:
                    break

            self.wait(driver, 20, By.XPATH, "//div[@class='ms-List-page']")

            time.sleep(10)             
            alerts = helper.RequestHeader(driver, "incidents/alerts")
            cookie = alerts.get_param("cookie")

            dbgPrint.debug("[+] Retrieving current cookie...\n")

            mde.MSSentinelApi(cookies=cookie).save_session()

            driver.execute_script('''window.open("https://endpoint.microsoft.com", "_blank")''')
            driver.switch_to.window(driver.window_handles[1])
            self.wait(driver, 20, By.XPATH, "//div[contains(text(),'Sign-in options')]")
            driver.find_element(By.XPATH, "//div[contains(text(),'Sign-in options')]").click()
            self.wait(driver, 20, By.XPATH, "//div[@data-test-cred-id='organization']")
            driver.find_element(By.XPATH, "//div[@data-test-cred-id='organization']").click()
            self.wait(driver, 20, By.ID, "searchOrganizationInput")
            driver.find_element(By.ID, "searchOrganizationInput").send_keys("kwijp.onmicrosoft.com")
            driver.find_element(By.ID, "idSIButton9").click()
            self.wait(driver, 20, By.XPATH, "//div[@class='ext-FlexColumn']//div//div[@data-bind='pcControl: card']")


            time.sleep(10)

            http_rqst = helper.RequestHeader(driver, "api/DelegationToken")         #1/27/2023 5:00:48 PM 
            cookie = http_rqst.get_param("cookie")

            json_data = json.loads(http_rqst.body)

            msgraph.MSGraphApi(cookies=cookie, json=json_data, verify=False).save_session()

            driver.execute_script('''window.open("https://account.activedirectory.windowsazure.com/usermanagement/multifactorverification.aspx?", "_blank")''')
            driver.switch_to.window(driver.window_handles[2])

            self.wait(driver, 20, By.XPATH, "//div[contains(text(),'Sign-in options')]")
            driver.find_element(By.XPATH, "//div[contains(text(),'Sign-in options')]").click()
            self.wait(driver, 20, By.XPATH, "//div[@data-test-cred-id='organization']")
            driver.find_element(By.XPATH, "//div[@data-test-cred-id='organization']").click()
            self.wait(driver, 20, By.ID, "searchOrganizationInput")
            driver.find_element(By.ID, "searchOrganizationInput").send_keys("kwijp.onmicrosoft.com")
            driver.find_element(By.ID, "idSIButton9").click()
            self.wait(driver, 20, By.ID, "UserListGrid_ActionBarContainer")
#            self.wait(driver, 20, By.XPATH, "//img[@boxtype='Image' and @title='Search']")

            time.sleep(2)
            http_rqst = helper.RequestHeader(driver, "/GenericGetAvailableFilters.ajax")         #1/27/2023 5:00:48 PM 
            cookies = http_rqst.get_param("Cookie")
            headers = dict(http_rqst.headers._headers)

            page = mfa.MultiFactor(cookies=cookies, headers=headers)            

            page.save_session()

            driver.quit()



