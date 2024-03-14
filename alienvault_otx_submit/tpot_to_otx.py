# This file contains everything needed to query your elasticsearch cluster and submit to alienvault OTX
# other files and directories in this folder are just examples and previous versions

# import libraries
from datetime import datetime
from os import path
import argparse
import yaml
from elasticsearch import Elasticsearch
import os
from tqdm import tqdm
from OTXv2 import OTXv2  # Alienvault library
import socket
import traceback
import time


# *********************************************************************************
# usage: equeryElasticSearch( conofiguration_dictionary)
# description: queries elasticsearch query for tsec tpot indexes over a user provided time period, data is returned
#  and consolidated into a python dictionary.
# sub-methods:
#    __init__(config) : initializes class, takes the yaml config dictionary
#    relativeTimeQuery(timeDisplacement) :  queries es based time differiential
#        Time can be submitted to the method with the following abreviations
#           - seconds = s
#           - minutes = m
#           - hours = h
#           - days = d
#           - Months = M
#        Example: relativeTimeQuery("5m")
#        Example: relativeTimeQuery("12h")
#        Example: relativeTimeQuery("1d")
#        Example: relativeTimeQuery("3M")
#
#
#    addDataToConsolidatedData(item) : takes in item to be added/updated to class dictionary
#    get_consolidated_data() : returns consolidated data dicctionary
# ********************************************************************************
class queryElasticsearch:
    consolidatedData = {}

    def __init__(self, config):
        self.config = config
        print(f"[+] Initializing Elasticsearch: ")
        print(
            f"    -- ElasticSearch Connection Established: {self.config['elasticsearch_host']}:{self.config['elasticsearch_port']}"
        )
        print(f"    -- ElasticSearch Index: {self.config['elasticsearch_index']}")

        # creating elasticsearch connection:
        # TODO: needs try/except block to handle errors
        eshost = (
            self.config["elasticsearch_host"]
            + ":"
            + str(self.config["elasticsearch_port"])
        )
        self.es = Elasticsearch(
            eshost,
            basic_auth=(
                self.config["elasticsearch_username"],
                self.config["elasticsearch_password"],
            ),
        )

    def relativeTimeQuery(self, timeDisplacement):

        # Queries elasticsearch for all data in the past X sec, min, hours, days
        #   seconds = s
        #   minutes = m
        #   hours = h
        #   days = d
        #   Months = M

        gte_displacement = "now-" + timeDisplacement
        # Define the query
        query_body = {
            "query": {"range": {"@timestamp": {"gte": gte_displacement, "lte": "now"}}},
            "size": 10000,
            "from": 0,
        }

        print(f"    -- Query: {query_body}")

        # Execute the initial search request with scroll
        scroll = "5m"  # Keep the search context alive for 2 minutes
        response = self.es.search(
            index=self.config["elasticsearch_index"], body=query_body, scroll=scroll
        )

        # Process the initial search response
        scroll_id = response["_scroll_id"]
        total_hits = response["hits"]["total"]["value"]
        print(f"    -- Total Records Returned: {total_hits}")
        pbar = tqdm(total=total_hits)

        print("[+]: Querying ES, please wait...")

        # Process the initial batch of documents
        for hit in response["hits"]["hits"]:
            if hit["_source"]["type"] not in self.config["blacklist_tpot_types"]:
                self.addDataToConsolidatedData(hit["_source"])
            pbar.update(1)

        # Begin scrolling through the rest of the results
        while len(response["hits"]["hits"]) > 0:
            response = self.es.scroll(scroll_id=scroll_id, scroll=scroll)
            scroll_id = response["_scroll_id"]

            # Process the next batch of documents
            for hit in response["hits"]["hits"]:
                if hit["_source"]["type"] not in self.config["blacklist_tpot_types"]:
                    self.addDataToConsolidatedData(hit["_source"])
                pbar.update(1)
        pbar.close()

        print(
            f"[+] Total Objects Added to Consolidated List: {len(self.get_consolidated_data())}"
        )
        return self.get_consolidated_data()

    def addDataToConsolidatedData(self, item):
        # TODO: there has to be a better way than 5+ nested if's
        if "src_ip" in item.keys():  # if there is a source IP address
            if "type" in item.keys():  # if there is a honeypot type listed
                if (
                    item["type"] not in self.config["blacklist_tpot_types"]
                ):  # skips honeypot types listed in blacklist in config
                    if (
                        item["src_ip"] not in self.config["whitelist_ips"]
                    ):  # if not honeypot ip
                        if (
                            item["src_ip"] in self.consolidatedData.keys()
                        ):  # if IP Already in list
                            self.consolidatedData[item["src_ip"]]["count"] += 1
                            if (
                                item["type"]
                                not in self.consolidatedData[item["src_ip"]]["type"]
                            ):
                                self.consolidatedData[item["src_ip"]]["type"].append(
                                    item["type"]
                                )
                            if "src_port" in item.keys():
                                if (
                                    item["src_port"]
                                    not in self.consolidatedData[item["src_ip"]][
                                        "src_port"
                                    ]
                                ):
                                    self.consolidatedData[item["src_ip"]][
                                        "src_port"
                                    ].append(item["src_port"])
                            if "dest_port" in item.keys():
                                if (
                                    item["dest_port"]
                                    not in self.consolidatedData[item["src_ip"]][
                                        "dest_port"
                                    ]
                                ):
                                    self.consolidatedData[item["src_ip"]][
                                        "dest_port"
                                    ].append(item["dest_port"])
                            portCount = len(
                                self.consolidatedData[item["src_ip"]]["src_port"]
                            ) + len(self.consolidatedData[item["src_ip"]]["dest_port"])
                            if (
                                portCount > 20
                            ):  # if more than 20 ports in list, just say port scan
                                portDescription = (
                                    "Port Scan:"
                                    + str(portCount)
                                    + " ports were scanned"
                                )
                            else:
                                count = self.consolidatedData[item["src_ip"]]["count"]
                                portDescription = (
                                    "Attacker attempted communication "
                                    + str(count)
                                    + " times on ports:"
                                    + str(
                                        set(
                                            (
                                                self.consolidatedData[item["src_ip"]][
                                                    "src_port"
                                                ]
                                            )
                                            + self.consolidatedData[item["src_ip"]][
                                                "dest_port"
                                            ]
                                        )
                                    )
                                )
                            self.consolidatedData[item["src_ip"]][
                                "portDescription"
                            ] = portDescription

                        else:  # new ip
                            tempDict = {}
                            tempDict["type"] = []
                            tempDict["src_port"] = []
                            tempDict["dest_port"] = []
                            tempDict["hosts"] = []
                            tempDict["src_repList"] = []
                            tempDict["count"] = 1
                            tempDict["type"].append(item["type"])
                            if "src_port" in item.keys():
                                tempDict["src_port"].append(item["src_port"])

                            if "dest_port" in item.keys():
                                tempDict["dest_port"].append(item["dest_port"])
                            if "src_port" in item.keys():
                                tempDict["src_ip"] = item["src_ip"]
                                self.consolidatedData[item["src_ip"]] = tempDict.copy()

    def get_consolidated_data(self):
        return self.consolidatedData.copy()

# *********************************************************************************
# usage: alienvaultOTX( conofiguration_dictionary, consolidated data dictionary)
# description: submits consolidated data from tsec tpot to alienvault otx open source threat community


# sub-methods:
#    __init__(config) : initializes class, takes the yaml config dictionary, and consolidated data dictionary
#    processConsolidatedData : main driving method, formats the data submits to otx
#    processLogs : formats items in consolidated data dictionary into a form OTX can accept
#    SubmitOTX_Pulse : submits to OTX
#    checkForOTXPulse : checks to see if "pulse" is already present in OTX, if no current pulse create one, if there
#       add to pulse. A pulse is OTX's term for a container for indicators of threat. this script creates a pulse for
#       each individual month
#
# ********************************************************************************
class alienvaultOTX:
    logData = {}
    consolidatedData = {}

    def __init__(self, lookout_config, consolidatedData):
        self.lookout_config = lookout_config
        self.consolidatedData = consolidatedData.copy()

    def processConsolidatedData(self):
        # puts the logs in otx json format
        results = self.processLogs(self.consolidatedData)
        self.SubmitOTX_Pulse(results, "HoneyNet")

    def processLogs(self, LogData):
        otxEntries = []
        for item in LogData:
            if "dest_port" in LogData[item].keys():
                portTags = LogData[item]["dest_port"]
                portTags = str(portTags)

                portTags = portTags.replace("[", "")
                portTags = portTags.replace("]", "")
                if len(portTags) > 125:
                    strDescription = " Port Scan, scanned many/all ports"
                else:
                    strDescription = str(portTags)

                strTags = str(LogData[item]["type"])
                strTags = strTags.replace("[", "")
                strTags = strTags.replace("]", "")

                if "many/all" in strDescription:
                    strTags = strTags + "," + "PortScanner"
                else:
                    strTags = strTags + "," + strDescription

                strTags = strTags.replace("'", "")

                OTXEntry = {
                    "indicator": item,
                    "type": "ipv4",
                    "tags": strTags,
                    "title": str("HoneyNet Event:" + item),
                    "description": str(
                        "HoneyNet Event: "
                        + item
                        + " connected: "
                        + str(LogData[item]["count"])
                        + " times "
                        + "over ports: "
                        + strDescription
                        + "  Tags: "
                        + strTags
                    ),
                    "Role": "hunter",
                }
                otxEntries.append(OTXEntry.copy())
        return otxEntries

    def SubmitOTX_Pulse(self, indicatorsArray, SubmitTitle):
        strDateTime = datetime.now().date()
        mydate = datetime.now()
        strMonthName = mydate.strftime("%B")
        strYear = mydate.strftime("%Y")
        MonthlyPulseTitle = "LCIA:" + SubmitTitle + ":" + strMonthName + " " + strYear
        YearlyPulseTitle = "LCIA:" + SubmitTitle + ":" + strYear
        PulseNamesList = [MonthlyPulseTitle, YearlyPulseTitle]
        PulseDescription = (
            "Louisiana Cyber Investigators Alliance (LCIA): HoneyPot Suricata Log: "
            + strYear
            + " A unified "
            "coordinated group of federal, state, local law enforcement, as well as LA ESF-17 members, "
            "focused onsafeguarding Louisiana's networks through collaborative vigilance and thorough "
            "investigations http://www.la-safe.org"
        )
        PulseReference = ""

        OTX_KeyList = [self.lookout_config["OTX_Key_dm_lacia"]]
        print(f"[+]: Building OTX package please wait.. ")
        # OTX_KeyList = [self.lookout_config['OTX_Key_dm_lacia']]
        for otxItem in OTX_KeyList:
            otx = OTXv2(otxItem)
            for pulseItem in PulseNamesList:
                PulseID = self.checkForOTXPulse(pulseItem, otx)
                # print ("PULSEID :", PulseID, " :")
                if PulseID == None:
                    response = otx.create_pulse(
                        name=pulseItem,
                        description=PulseDescription,
                        public=True,
                        indicators=indicatorsArray,
                        tags=["tsec", "tpot19", "honeypot", "la-safe.org"],
                        references=[PulseReference],
                    )
                    print(
                        f"    - Submitted: {len(indicatorsArray)} indicators to : {pulseItem}"
                    )
                else:
                    # print("pulse1 already there, cant create it")
                    response = otx.add_pulse_indicators(
                        pulse_id=PulseID, new_indicators=indicatorsArray
                    )
                    print(
                        f"    - Submitted: {len(indicatorsArray)} indicators to : {pulseItem}"
                    )

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
                        return pulses[0]["id"]
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


# *********************************************************************************
if __name__ == "__main__":
    # start timer
    script_start = time.time()

    # ------------- Reads Config File ---------------
    YAMLFILE = "./lookoutConfig.yml"  # System Configuration and Variables
    queryResults = {}
    currentTime = datetime.now()

    if path.exists(YAMLFILE):
        # -- Loads Configuration File for LookOut --> python dictionary
        with open(YAMLFILE, "r") as file:
            lookout_config = yaml.load(file, Loader=yaml.FullLoader)
    else:
        print(
            "ERROR: No config file, please refer to lookout.yml.example in root folder of script"
        )
        exit()

    print(f"[+]: Current Configuration: {lookout_config}")

    # ------------ Query and Consolidate Data --------------------
    queryObj = queryElasticsearch(lookout_config)
    queryResults = queryObj.relativeTimeQuery("15m")

    # ------------ Submit to OTX ------------
    otx_obj = alienvaultOTX(lookout_config, queryResults)
    otx_obj.processConsolidatedData()

    script_stop = time.time()
    print("[+] %s seconds of time to run script ---" % (script_stop - script_start))
