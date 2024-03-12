from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan


class queryTpot:
    def __init__(self, es_host, es_port, es_index, es_user, es_password):
        print("object created")

        self.es_host = es_host + ":" + es_port  # elasticsearch host
        self.es_port = es_port  # elasticsearch port
        self.es_index = es_index  # elasticsearch index
        self.es_user = es_user  # elasticsearch user
        self.es_password = es_password  # elastic password

        self.junkTypes = [
            "P0f",
            "Fatt",
        ]  # entry types that are junk and not added to list

        print("Host:", self.es_host)
        print("Index:", self.es_index)

        self.es = Elasticsearch(
            self.es_host, basic_auth=(self.es_user, self.es_password)
        )

        # Define index name
        index_name = "logstash-hive-1"

        # Define Elasticsearch query (match_all)
        query = {"query": {"match_all": {}}}

        # Execute the query
        result = self.es.search(index=index_name, body=query)
        print (result)

        # Process the results
        for hit in result["hits"]["hits"]:
            print(hit["_source"])  # Print the source document


# Press the green button in the gutter to run the script.
if __name__ == "__main__":
    qtPot_obj = queryTpot(
        "http://10.0.0.25", "9200", "logstash-hive-1", "elastic", "NotMonday@1"
    )
