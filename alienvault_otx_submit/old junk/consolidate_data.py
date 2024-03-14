from datetime import datetime
from os import path
import argparse
import yaml
import threading
import logging
from esWithPaging import queryElasticsearch

from submit_alienvault_otx import alienvaultOTX
from tqdm import tqdm
from pprint import pprint
import json


class consolidateTpotData:
    p0fData = []
    fattData = []
    suricataData = []
    hpData = []
    # consolidatedData={}
    typeDict = {}
    submitCount = 1
    submitAmount = 1000000

    def __init__(self, lookout_config, queryData):
        print (f' -- Consolidate Object Created:')
        self.lookout_config = lookout_config
        self.dataList= queryData

    # This is UGLY.. there has to be a better way.. but it reduces/consolidates the data from es query. it creates a
    # dictionary with the malicious ip as the dictionary key..

    def reduceQueryData(self):
        # print ("packing data.. please wait..")
        consolidatedData = {}

        print (f' -- Reducing Elasticsearch Query Data.. please wait..')
        for item in tqdm(self.dataList):
            if "src_ip" in item.keys():
                if "type" in item.keys():
                    if (
                        item["src_ip"] not in self.lookout_config["whitelist_ips"]
                    ):  # honeypot ip
                        if (
                            item["src_ip"] in consolidatedData.keys()
                        ):  # IP Already in list
                            consolidatedData[item["src_ip"]]["count"] += 1
                            if (
                                item["type"]
                                not in consolidatedData[item["src_ip"]]["type"]
                            ):
                                consolidatedData[item["src_ip"]]["type"].append(
                                    item["type"]
                                )
                            if "src_port" in item.keys():
                                if (
                                    item["src_port"]
                                    not in consolidatedData[item["src_ip"]][
                                        "src_port"
                                    ]
                                ):
                                    consolidatedData[item["src_ip"]][
                                        "src_port"
                                    ].append(item["src_port"])
                            if "dest_port" in item.keys():
                                if (
                                    item["dest_port"]
                                    not in consolidatedData[item["src_ip"]][
                                        "dest_port"
                                    ]
                                ):
                                    consolidatedData[item["src_ip"]][
                                        "dest_port"
                                    ].append(item["dest_port"])
                            portCount = len(
                                consolidatedData[item["src_ip"]]["src_port"]
                            ) + len(consolidatedData[item["src_ip"]]["dest_port"])
                            if portCount > 20:
                                portDescription = (
                                    "Port Scan:"
                                    + str(portCount)
                                    + " ports were scanned"
                                )
                            else:
                                count = consolidatedData[item["src_ip"]]["count"]
                                portDescription = (
                                    "Attacker attempted communication "
                                    + str(count)
                                    + " times on ports:"
                                    + str(
                                        set(
                                            (
                                                consolidatedData[item["src_ip"]][
                                                    "src_port"
                                                ]
                                            )
                                            + consolidatedData[item["src_ip"]][
                                                "dest_port"
                                            ]
                                        )
                                    )
                                )
                            consolidatedData[item["src_ip"]][
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
                                consolidatedData[item["src_ip"]] = tempDict.copy()
        return consolidatedData.copy()

        print("Total Number of Indicators to Submit:", len(consolidatedData))
        openCTI_Obj = libOpenCTI_v4.OpenCTI_Submit(
            self.lookout_config, consolidatedData
        )
        # libAlienvault.alienvaultOTX(self.lookout_config, self.reduceQueryData(DataList))
        # x = threading.Thread(target=self.threadSubmit, args=(self.reduceQueryData(DataList),))
        DataList.clear()

        # x.join()

        # self.submitLogToES()
        print("Total Count of Log Entries:", count)
        print("Time Taken:", datetime.now() - startTime)
        timeToQuery = datetime.now() - startTime
        # return DataList.copy()

    def getConsolidatedData(self):
        return self.consolidatedData.copy()

    def recordHoneyPotType(self, hpType):
        if hpType in self.typeDict.keys():
            self.typeDict[hpType] += 1
        else:
            self.typeDict[hpType] = 1
