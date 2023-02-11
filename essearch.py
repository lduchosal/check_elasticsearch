import warnings
from datetime import datetime
from elasticsearch import Elasticsearch

es = Elasticsearch(
      ['elastic'],
      http_auth=('nagios', '77777777777777777777777777777777'),
      port=9200
)

query_text = "host: (\"ans1\") AND program: (mtree)"
query_size = 1
query_search = {
    "bool": {
      "must": [
        {
          "query_string": {
            "query": query_text
          }
        }
      ],
      "filter": [
        {
          "range": {
            "@timestamp": {
              "format": "strict_date_optional_time",
              "gte": "now-1d/d",
              "lte": "now/d"
            }
          }
        }
      ]
    }
  }

# res = es.search(index="logstash", query={"match": {}}) body={"query":{"query_string":{"query":query}},"sort":[{"@timestamp":{"order":"desc"}}]}

# with warnings.catch_warnings(record=True) as w:
#     es.info()

count = es.count(index="logstash", body={"query":{"query_string":{"query": query_text }}})
print(count)
res = es.search(index="logstash", query=query_search, size=query_size)

print("Got %d Hits:" % res['hits']['total']['value'])
for hit in res['hits']['hits']:
    print("%(timestamp)s %(host)s: %(program)s" % hit["_source"])



search_query1 = { "bool": { "must": [ {"match": {"host": "ans1*"}}, {"match": {"program": "mtree"}} ] }}
search_query2 = { "bool": { "must": [ {"match": {"query": "mtree"}} ] }}
search_query3 = { "match": 
   {  
      "host": {"query": "mtree"}
   }
}

search_query4 = { 
   "bool": {
      "must": [],
      "filter": [
        {
          "bool": {
            "filter": [
              {
                "bool": {
                  "should": [
                    {
                      "match": {
                        "program": "mtree"
                      }
                    }
                  ],
                  "minimum_should_match": 1
                }
              },
              {
                "bool": {
                  "should": [
                    {
                      "match": {
                        "host": "rs3"
                      }
                    }
                  ],
                  "minimum_should_match": 1
                }
              }
            ]
          }
        },
        {
          "range": {
            "@timestamp": {
              "format": "strict_date_optional_time",
              "gte": "2023-02-09T00:00:00.000Z",
              "lte": "2023-02-10T00:00:00.000Z"
            }
          }
        }
      ],
      "should": [],
      "must_not": []
    }
}



search_query  = {
    "bool": {
      "filter": [
        {
          "bool": {
            "filter": [
              {
                "bool": {
                  "should": [
                    {
                      "match": {
                        "host": "ans1"
                      }
                    }
                  ],
                  "minimum_should_match": 1
                }
              }
            ]
          }
        }
      ]
    }
  }



search_query = {
    "bool": {
      "must": [],
      "filter": [
        {
          "bool": {
            "filter": [
              {
                "bool": {
                  "should": [
                    {
                      "match": {
                        "program": "mtree"
                      }
                    }
                  ],
                  "minimum_should_match": 1
                }
              },
              {
                "bool": {
                  "should": [
                    {
                      "match": {
                        "host": "ans1"
                      }
                    }
                  ],
                  "minimum_should_match": 1
                }
              }
            ]
          }
        },
        {
          "range": {
            "@timestamp": {
              "format": "strict_date_optional_time",
              "gte": "2023-02-09T09:48:34.970Z",
              "lte": "2023-02-10T09:48:34.970Z"
            }
          }
        }
      ],
      "should": [],
      "must_not": []
    }
}

search_query = {
      "query_string" : {
          "query" : "host:((ans1) AND program:((mtree))",
          "default_field" : "*"
      }
  }

