#Alienvault OTX threat library conversion and submit

import json
import traceback
from pprint import pprint
from datetime import datetime
from typing import Type

from OTXv2 import OTXv2  #Alienvault library
import socket

class alienvaultOTX:
    logData={}
    consolidatedData={}

    def __init__(self, lookout_config, consolidatedData):
        print (" -- OTX Submit object created")
        self.lookout_config = lookout_config
        self.consolidatedData=consolidatedData.copy()

    def processConsolidatedData(self):
        #puts the logs in otx json format
        results=self.processLogs(self.consolidatedData)
        print (results)
        self.SubmitOTX_Pulse(results,"HoneyNet")

    def processLogs(self, LogData):
        print ("--==: Number of Unique IPs Submitted to AlienVault:", len(LogData.keys()))

        otxEntries=[]
        for item in LogData:
            if "dest_port" in LogData[item].keys():
                portTags=LogData[item]['dest_port']
                portTags=str(portTags)

                portTags=portTags.replace("[","")
                portTags = portTags.replace("]", "")
                if len(portTags) > 125:
                    strDescription=" Port Scan, scanned many/all ports"
                else:
                    strDescription=str(portTags)

                strTags=str(LogData[item]['type'])
                strTags=strTags.replace("[","")
                strTags = strTags.replace("]", "")

                if "many/all" in strDescription:
                    strTags = strTags + "," + "PortScanner"
                else:
                    strTags = strTags + "," + strDescription

                strTags = strTags.replace("'","")

                OTXEntry={'indicator': item,
                          'type': "ipv4",
                          'tags': strTags,
                          'title' : str("HoneyNet Event:" + item),
                          'description': str("HoneyNet Event: " + item + " connected: " +
                                         str(LogData[item]['count'])+ " times " + "over ports: " +
                                         strDescription + "  Tags: " + strTags),
                          'Role':"hunter"
                          }
                otxEntries.append(OTXEntry.copy())
        return otxEntries

    def SubmitOTX_Pulse(self, indicatorsArray, SubmitTitle):
        strDateTime = datetime.now().date()
        mydate = datetime.now()
        strMonthName = mydate.strftime("%B")
        strYear = mydate.strftime("%Y")
        MonthlyPulseTitle="LCIA:" + SubmitTitle + ":" + strMonthName+" "+strYear
        YearlyPulseTitle="LCIA:" + SubmitTitle + ":" + strYear
        PulseNamesList=[MonthlyPulseTitle, YearlyPulseTitle]
        PulseDescription="Louisiana Cyber Investigators Alliance (LCIA): HoneyPot Suricata Log: " + strYear+ " A unified " \
                         "coordinated group of federal, state, local law enforcement, as well as LA ESF-17 members, " \
                         "focused onsafeguarding Louisiana's networks through collaborative vigilance and thorough " \
                         "investigations http://www.la-safe.org"
        PulseReference=""

        OTX_KeyList=[self.lookout_config['OTX_Key_dm_lacia'] ]
        #OTX_KeyList = [self.lookout_config['OTX_Key_dm_lacia']]
        for otxItem in OTX_KeyList:
            otx = OTXv2(otxItem)
            for pulseItem in PulseNamesList:
                PulseID=self.checkForOTXPulse(pulseItem, otx)
                # print ("PULSEID :", PulseID, " :")
                if PulseID == None:
                    response = otx.create_pulse(name=pulseItem, description=PulseDescription, public=True,
                                                 indicators=indicatorsArray, tags=["tsec", "tpot19", "honeypot","la-safe.org"],
                                                 references=[PulseReference])
                    #print ("Response1:", response)
                else:
                    # print("pulse1 already there, cant create it")
                    response=otx.add_pulse_indicators(pulse_id=PulseID, new_indicators=indicatorsArray)
                    #print ("Response2:",response)

    # Check to see if pulse is already there, if its there add to it, if not create one
    # OTX Pulse is the monthly group i submit things into
    def checkForOTXPulse(self, pulseName, otxObj):
        try:
            # Timeout for network connections
            socket.setdefaulttimeout(120)
            retries = 0
            while retries <= 5:
                try:
                    retries += 1
                    # print('Looking for pulse: ' + pulseName)
                    query = 'name:"{}"'.format(pulseName)
                    pulses = otxObj.get_my_pulses(query=query)
                    if pulses:
                        return pulses[0]['id']
                    else:
                        return None
                except socket.timeout:
                    print("Timeout looking for pulse. Retrying")
                except AttributeError:
                    print("OTX API internal error")

            print("Max retries (5) exceeded")
            return None
        except Exception:
            print(traceback.format_exc())
        finally:
            socket.setdefaulttimeout(5)
