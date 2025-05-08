#!/usr/local/bin/python3.9
"""Usage:
    check_elasticsearch.py --host <host> --user <esuser> --pass <espass> --index <index> --query <query> --gte <gte> --lte <lte> --warning <warning> --critical <critical> [--msgchars=<msgchars>] [--msgkey=<msgkey>] [--srckey=<srckey>]
    check_elasticsearch.py --host <host> --user <esuser> --pass <espass> --filter <query> --warning <warning> --critical <critical>

Options:
    --host      Endpoint to Elasticsearch, eg. http://<ip>:<port>. Logging in with user/password: http://<username>:<password>@<ip>:<port>
    --index     Elastic index to use, eg. rsyslog-* or filebeat-*. Use _all to search all indexes (more resource intensive).
    --query     Raw Elastic/Lucene query, eg. "received_from=10.0.5.2 and program=systemd and host=10.0.5.10 and @timestamp: [now-5h TO now]".
    --filter    Name of saved filter in Kibana, its index will be used automatically.
    --warning   Threshold as integer. eg. 128.
    --critical  Threshold as integer. eg. 299.
    --msgchars=<msgchars>  Number of characters to display in latest log message as integer or "all". eg. 255 [default: 255].
    --msgkey=<msgkey>    For query searches only. Index of message to display. eg. full_message [default: message].
    --srckey=<srckey>    For query searches only. Index of log source. eg. source [default: logsource].
    --user      elasticsearch user
    --pass      elasticsearch password
    --gte       filter on the last now-1d/d, now-1h/h, ...
    --lte       filter on the last now/d, now/h, ...


    DEPENDENCIES:
        pip install docopt elasticsearch

    Examples:
         check_elasticsearch.py --host elasticip --user user --pass secret --index "filebeat-*" --query "system_process_id=148" --last 1d --warning 1 --critical 2
         check_elasticsearch.py --host elasticip --filter "some_saved_filter_in_kibana" --warning 1 --critical 2


Original Author: Misiu Pajor
Updated by: Sebastian Leung
"""
__author__ = 'Misiu Pajor, OP5 AB'
__date__ = '2017-10-02'
__version__ = '0.6.2'


try:

    from docopt import docopt
    from elasticsearch import Elasticsearch
    from elasticsearch.exceptions import ConnectionError, \
        TransportError, \
        ConnectionTimeout, \
        NotFoundError, \
        RequestError
    import json
    import logging
except ImportError as missing:
    print (
        'Error - could not import all required Python modules\n"%s"'
        % missing + '\nDependency installation with pip:\n'
        '"# pip install docopt elasticsearch"'
        'or use your prefered package manage, i.e. APT or YUM.\n Example: yum install python-docopt python-elasticsearch')
    exit(3)

logging.getLogger("urllib3").setLevel(logging.CRITICAL)
logging.getLogger("elasticsearch").setLevel(logging.CRITICAL)

class ElasticAPI(object):
    def __init__(self):
        self.args = docopt(__doc__, version=None)
        self.url = self.args["<host>"]
        self.user = self.args["<esuser>"]
        self.secret = self.args["<espass>"]
        try:
            self.es = Elasticsearch(
                [ self.url ],
                http_auth=(self.user, self.secret),
                port=9200,
                scheme="https",
                ssl_show_warn=False,
                verify_certs=False
                # sniff_on_start=False,
                # timeout=60,
            )
        except (ConnectionTimeout, ConnectionError, TransportError, NotFoundError, RequestError) as error:
            exit("ctor Error: Exception: {0}".format(error))

    ''' queries elasticsearch to find saved filter as argumented in get_filter() '''
    def _find_filter(self, filter):
        json = self.es.search(index="_all", body={"query":{"query_string":{"query":filter}}})
        try:
            data = json["hits"]["hits"][0]["_source"]["kibanaSavedObjectMeta"]["searchSourceJSON"]
        except KeyError:
            exit("find_filter Error: Filter {0} could not be found.".format(filter))
        return data

    ''' find saved filters in kibana by its given named in GUI  '''
    def get_filter(self, filter):
        data = json.loads(self._find_filter(filter))
        try:
            data["index"]
        except IndexError:
            exit("get_filter Error: No index could not be localised for the given filter.")
        query = data["query"]["query_string"]["query"]
        count = self.es.count(index=data["index"], body={"query":{"query_string":{"query":query}}})
        if count["count"] is not None:
            return count["count"]
        exit("get_filter Error: Query did not return any hits")

    ''' gets count for a given query (eg. "+@timestamp: [now-30m TO now] and +received_from:172.27.105.3)" '''
    def get_query(self, query, index=None):

        index = self.args["<index>"]
        gte = self.args["<gte>"] or "now-1d/d"
        lte = self.args["<lte>"] or "now/d"
        query_search = { "bool": { 
           "must": [ { "query_string": { "query": query } } ],
           "filter": [ { "range": { "@timestamp": { "format": "strict_date_optional_time", "gte": gte, "lte": lte } } } ]
           }
        }
        

        latest_log = self.es.search(index=index, query=query_search, size=1)
#        print(latest_log)
        count = latest_log['hits']['total']['value']
        last_message = ""
        last_date = index
        if count > 0:
           last_message = latest_log['hits']['hits'][0]['_source']['message']
           last_date = latest_log['hits']['hits'][0]['_source']['timestamp']
        msg = [ last_date, last_message ]
        return count, msg

    ''' determinates the exit_code and plugin_output '''
    def _exit_state(self, count):
        warning = int(self.args["<warning>"])
        critical = int(self.args["<critical>"])
        
        #
        # special case
        # critical == 0 and warning == 0
        #
        if critical == 0 and warning == 0 and count == 0:
            message = message = "CRITICAL - 0 hits: {0} - must have hits| hits={0}".format(count)
            print(message)
            exit(2)
        elif critical == 0 and warning == 0 and count > 0:
            message = message = "OK - Total hits: {0} | hits={0}".format(count)
            print(message)
            exit(0)

        if count >= critical:
            if 'latest_message' in globals() or 'latest_message' in locals():
                message = "CRITICAL - Total hits: {0} - Last message from: {2} [ {1} ] | hits={0}".format(count,\
                                                                           latest_message[0].encode('utf-8'), latest_message[1].encode('utf-8'))
            else:
                message = message = "CRITICAL - Total hits: {0} | hits={0}".format(count)
            exit_code = 2
        elif count >= warning:
            if 'latest_message' in globals() or 'latest_message' in locals():
                message = "WARNING - Total hits: {0} - Last message from: {2} [ {1} ] | hits={0}".format(count,\
                                                                           latest_message[0].encode('utf-8'), latest_message[1].encode('utf-8'))
            else:
                message = message = "WARNING - Total hits: {0} | hits={0}".format(count)
            exit_code = 1
        else:
            if 'latest_message' in globals() or 'latest_message' in locals():
                message = "OK - Total hits: {0} - Last message from: {2} [ {1} ] | hits={0}".format(count,\
                                                                           latest_message[0].encode('utf-8'), latest_message[1].encode('utf-8'))
            else:
                message = message = "OK - Total hits: {0} | hits={0}".format(count)
            exit_code = 0
        if message:
            print(message)
        exit(exit_code)

if __name__ == '__main__':
    elastic = ElasticAPI()
    if elastic.args["--msgchars"]:
        if elastic.args["--msgchars"] == "all":
            msgchars = -1
        else:
            msgchars = elastic.args["--msgchars"]
        try:
            int(msgchars)
        except ValueError:
            print("Error: --msgchars must be an integer or 'all'")
            exit(3)

    if elastic.args["--msgkey"]:
        msgkey = elastic.args["--msgkey"]
    if elastic.args["--srckey"]:
        srckey = elastic.args["--srckey"]

    if elastic.args["--query"]:
        try:
            count, latest_message = elastic.get_query(elastic.args["<query>"], elastic.args["<index>"])
        except TypeError:
            count = elastic.get_query(elastic.args["<query>"], elastic.args["<index>"])
    if elastic.args["--filter"]:
        count = elastic.get_filter(elastic.args["<query>"])
    elastic._exit_state(count)
