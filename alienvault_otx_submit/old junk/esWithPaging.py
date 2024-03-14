from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
import os
from tqdm import tqdm
import tracemalloc

# Create an Elasticsearch client
# es = Elasticsearch()


class queryElasticsearch:
    q_results = []

    def __init__(
        self,
        es_host="localhost",
        es_port=9200,
        es_index="logstash-*",
        es_user="",
        es_password="",
    ):

        self.es_host = es_host
        self.es_port = es_port
        self.es_index = es_index
        self.es_user = es_user
        self.es_password = es_password

        print(
            f" -- ElasticSearch Connection Established: {self.es_host}:{self.es_port}"
        )
        print(f" -- ElasticSearch Index: {self.es_index}")

        eshost = self.es_host + ":" + str(self.es_port)

        self.es = Elasticsearch(eshost, basic_auth=(self.es_user, self.es_password))

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

        print(f" -- Query: {query_body}")

        # Execute the initial search request with scroll
        scroll = "2m"  # Keep the search context alive for 2 minutes
        response = self.es.search(index=self.es_index, body=query_body, scroll=scroll)

        # Process the initial search response
        scroll_id = response["_scroll_id"]
        total_hits = response["hits"]["total"]["value"]
        print(f" -- Total Hits: {total_hits}")
        pbar = tqdm(total=total_hits)

        print(" [+]: querying ES, please wait...")
        # Process the initial batch of documents
        count = 0
        for hit in response["hits"]["hits"]:
            if hit["_source"]["type"] not in ["Fatt", "P0f"]:
                self.q_results.append(hit["_source"])
            pbar.update(1)

        # Begin scrolling through the rest of the results
        while len(response["hits"]["hits"]) > 0:
            response = self.es.scroll(scroll_id=scroll_id, scroll=scroll)
            scroll_id = response["_scroll_id"]

            # Process the next batch of documents
            for hit in response["hits"]["hits"]:
                if hit["_source"]["type"] not in ["Fatt", "P0f"]:
                    self.q_results.append(hit["_source"])
                pbar.update(1)
        pbar.close()

        print(f" -- Total Hits Added to List: {len(self.q_results)}")

        return self.q_results.copy()

    def relativeTimeQuery_cache_to_disk(self, timeDisplacement):
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

        print(f" -- Query: {query_body}")

        # creation of temp folder for cache file
        path = "./cache"
        # Check whether the specified path exists or not
        isExist = os.path.exists(path)
        if not isExist:

            # Create a new directory because it does not exist
            os.makedirs(path)
            print("The new directory is created!")

        # create file writer to write temp/cache file
        filename = "./cache/" + "queryResults.json"
        fileWriter = open(filename, "w")

        # Execute the initial search request with scroll
        scroll = "2m"  # Keep the search context alive for 2 minutes
        response = self.es.search(index=self.es_index, body=query_body, scroll=scroll)

        # Process the initial search response
        scroll_id = response["_scroll_id"]
        total_hits = response["hits"]["total"]["value"]
        print(f" -- Total Hits: {total_hits}")
        pbar = tqdm(total=total_hits)

        print(" [+]: querying ES, please wait...")
        # Process the initial batch of documents
        count = 0
        for hit in response["hits"]["hits"]:
            # self.q_results.append(hit["_source"])
            if hit["_source"]["type"] not in ["Fatt", "P0f"]:
                lineToSave = str(hit["_source"]) + "\n"
                fileWriter.write(lineToSave)
            pbar.update(1)

        # Begin scrolling through the rest of the results
        while len(response["hits"]["hits"]) > 0:
            response = self.es.scroll(scroll_id=scroll_id, scroll=scroll)
            scroll_id = response["_scroll_id"]

            # Process the next batch of documents
            for hit in response["hits"]["hits"]:
                if hit["_source"]["type"] not in ["Fatt", "P0f"]:
                    # self.q_results.append(hit["_source"])
                    lineToSave = str(hit["_source"]) + "\n"
                    fileWriter.write(lineToSave)
                pbar.update(1)
        pbar.close()
        fileWriter.close()

        print(f" -- Total Hits Added to List: {len(self.q_results)}")
        return self.q_results.copy()


if __name__ == "__main__":
    esq_obj = queryElasticsearch(
        es_host="http://10.0.0.25",
        es_port=9200,
        es_index="logstash-hive-1",
        es_user="elastic",
        es_password="elastic",
    )
    esq_obj.relativeTimeQuery("1h")
