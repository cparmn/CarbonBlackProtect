#! /usr/bin/env python
import requests, json, time, re, logging
from datetime import datetime,date,timedelta
##Moves computers in Visibility into Enforcement Policy
def cbapicall():
    global pol, comps, apiUrl, authJson, b9StrongCert, LogFile
    #
    LDATE= str(datetime.today()).split()[0]
    LFILE="-Enforcement.log"
    LogFile=LDATE + LFILE
    logging.basicConfig(filename=LogFile,level=logging.INFO)    
    # --- Prepare our request header and url ---
    authJson ={
    'X-Auth-Token': 'ThisISANAIPCODE',  # Token Code Goes here, this defines the user permissions that is running this.
    'content-type': 'application/json'
    }
    apiUrl = 'https://FQDN/api/bit9platform' #This is the Carbon Black Server URL.
    b9StrongCert = True  # This will need to be changed to false unless CA certificates are trusted by the computer.
    #Get All Policies
    pol = requests.get(apiUrl + '/v1/policy',headers =authJson).json()
    # Get all Windows computers which are connected, not initilizing and 100% synced
    comps = requests.get(apiUrl + '/v1/Computer?q=policyId:9&q=connected:True&q=initializing:False&q=syncPercent:100', headers=authJson).json()

def defpolicy(): #This is where we're getting the policy informtion.  We will change this when we move into higher enforcement. 
    for p in pol:
        if p['name'] == 'Computers_High_Enforcement_Device_Control':  #This is the policy that we're looking for this is currently set staticly then the ID is pulled.
            global policy, pname 
            policy = p['id']
            pname = p['name']

def movecomps():      
    for c in comps:
        insertion_date = re.search('^.*?(?=T)',c['dateCreated'])
        time_between_insertion = datetime.today() - datetime.strptime(insertion_date.group(0), '%Y-%m-%d')
        if  time_between_insertion.days<30:
            if c['connected'] == True and re.match('.*\CFG.*',c['name']) is not None:
                c['policyId'] = policy  # Move to policy All_Computers_Low_Enforcement
                c['automaticPolicy'] = False # Move away from autopolicy
                r =requests.post(apiUrl+'/v1/computer?',json.dumps(c), headers =authJson, verify =b9StrongCert)  #Submit new information to Protect
                if r.status_code == requests.codes.ok:
                    #print "Computer", c['name'], "has been moved from", pname 
                    logging.info('Computer %s has been moved to %s',c['name'], pname)
                elif r.status_code != requests.codes.ok:
                    #print "Computer", c['name'], "was not successfully moved" 
                    logging.info('Computer %s was not successfully moved',c['name'])
            time.sleep(0.10)  #for loop is to fast for CB, requires a little sleep.

def compnotmoveed():
        for c in comps: 
            if c['connected'] == True and re.match('.*\CFG.*',c['name']) is None:
                print "Computer", c['name'], "was not moved"
                logging.info('Computer %s was not moved',c['name'])

def main():
    cbapicall()
    defpolicy()
    movecomps()
    compnotmoveed()

main()
