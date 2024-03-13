from datetime import datetime
from os import path
import argparse
import yaml
from alienvault_otx_submit import submit_alienvault_otx
from alienvault_otx_submit import esWithPaging
from alienvault_otx_submit import consolidate_data
from alienvault_otx_submit import submit_alienvault_otx

# This was originally called project "lookout" you can call it whatever or want.. or continue on with that name

if __name__ == "__main__":
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

    print(f" -- Current Configuration: {lookout_config}")

    # process run in submitAlienvault class
    # [1] Query ES
    es_query_obj = esWithPaging.queryElasticsearch(
        es_host=lookout_config['elasticsearch_host'],
        es_port=lookout_config['elasticsearch_port'],
        es_index=lookout_config['elasticsearch_index'],
        es_user=lookout_config['elasticsearch_username'],
        es_password=lookout_config['elasticsearch_password'],
    )
    tpot_query_data=es_query_obj.relativeTimeQuery("1h")

    # [2] consolidate by IP
    consolidate_obj=consolidate_data.consolidateTpotData(lookout_config, tpot_query_data)
    reducedDataList=consolidate_obj.reduceQueryData()
    print (f' -- Number of unique entries to submit to OTX: {len(reducedDataList)}')

    # [3] submit to otx
    submit_alienvault_obj=submit_alienvault_otx.alienvaultOTX(lookout_config, reducedDataList)
    submit_alienvault_obj.processConsolidatedData()


    #alienvault_obj = submit_alienvault_otx.alienvaultOTX(lookout_config)
