from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from tqdm import tqdm

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
            self.q_results.append(hit["_source"])
            pbar.update(1)

        # Begin scrolling through the rest of the results
        while len(response["hits"]["hits"]) > 0:
            response = self.es.scroll(scroll_id=scroll_id, scroll=scroll)
            scroll_id = response["_scroll_id"]

            # Process the next batch of documents
            for hit in response["hits"]["hits"]:
                self.q_results.append(hit["_source"])
                pbar.update(1)
        pbar.close()

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
