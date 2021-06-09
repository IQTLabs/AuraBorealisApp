"""
This file loads live Aura data 
"""

import scipy.stats

from elasticsearch import Elasticsearch, RequestsHttpConnection
from es.elastic.api import connect
from elasticsearch_dsl import Search, A, Q
#from requests_aws4auth import AWS4Auth

#HOST = '192.168.68.9'
#HOST = 'localhost'
HOST = 'vpc-auradata2-2b3s6lmtpt2wcb6ytkjd2y5yau.us-east-1.es.amazonaws.com'
DEBUG = " limit 100"

unique_packages = []

def scan_aggs(search, source_aggs, inner_aggs={}, size=10):
    """
    Helper function used to iterate over all possible bucket combinations of
    ``source_aggs``, returning results of ``inner_aggs`` for each. Uses the
    ``composite`` aggregation under the hood to perform this.
    """

    def run_search(**kwargs):
        s = search[:0]
        s.aggs.bucket("comp", "composite", sources=source_aggs, size=size, **kwargs)
        for agg_name, agg in inner_aggs.items():
            s.aggs["comp"][agg_name] = agg
        return s.execute()

    response = run_search()
    while response.aggregations.comp.buckets:
        for b in response.aggregations.comp.buckets:
            yield b
        if "after_key" in response.aggregations.comp:
            after = response.aggregations.comp.after_key
        else:
            after = response.aggregations.comp.buckets[-1].key
        response = run_search(after=after)


def get_unique_package_list():
    client = Elasticsearch(host=HOST)
    #client = Elasticsearch(host='vpc-auradata-gvykpxgobffy7eomi2q7hmqbma.us-east-1.es.amazonaws.com')

    #unique_packages = []
    for b in scan_aggs(
        Search(using=client),
        {"unique_packages": A("terms", field="package.keyword")}
    ):
        unique_packages.append(b.key.unique_packages)

    print(len(unique_packages))
    return unique_packages

    #s = Search(using=client).params(request_timeout=30)
    #a = A('terms', field='package')
    #s.aggs.bucket('unique_packages', a)
    #print(s.to_dict())
    #response = s.execute()
    #for tag in response.aggregations.unique_packages.buckets:
    #    print(tag)
    #for hit in s.scan():
        #print(type(hit))
        #print(hit)

 #init_all_severities
    #'kayobe': [{'warning_type': 'LeakingSecret', 'severity': 'critical', 'score': 0, 'line': "mock_getpass.return_value = 'test-pass'", 'line_no': 65}, {'warning_type': 'LeakingSecret', 'severity': 'critical', 'score': 0, 'line': "mock_getpass.return_value = 'test-pass'", 'line_no': 65}], 'karton-core': [{'warning_type': 'LeakingSecret', 'severity': 'critical', 'score': 0, 'line': 'minio_secret_key = "minioadmin"', 'line_no': 40}]

# for get_warnings_by_package, package_warnings should look like {'FunctionCall':{'critical':3, 'low':2}, 'ModuleImport':{'high':11, 'low':0}}


def get_warnings_by_package(package_name, package_warnings):
    client = Elasticsearch(host=HOST)
    s = Search(using=client)
    s = s.source(['package', 'type', 'severity', 'score'])
    #q = Q("match", type=warning)  & Q("match", severity=severity) 
    s = s.query("match", package__keyword=package_name)
    s = s.exclude("match", tag="test_code")
    #print(s.to_dict())

    # process the query
    for hit in s.scan():
        #print(hit.type)
        #print(hit.severity)
        #print(hit.package)

        if hit.type not in package_warnings.keys():
              package_warnings[hit.type] = {}
        if hit.severity in package_warnings[hit.type]:
              package_warnings[hit.type][hit.severity] += 1
        else:
              package_warnings[hit.type][hit.severity] = 0

    #print(package_warnings)
    #return package_warnings

#def get_warnings_by_package(package, warning, severity, package_warnings, init_all_severities, init_all_warnings):
#   """
#   get all the warnings for a specific package
#
#   Arguments
#   ---------
#   package : the package you want warnings for (do not specify a version for now)
#   warning : the Aura warning types you care about
#   severity : the severity level you care about
#   package_warnings : the dict this function will update
#        """
#        all_pkg_sevs = init_all_severities.get(package)
#        all_pkg_warns = init_all_severities.get(package)
#        print(all_pkg_sevs)
#        print(all_pkg_warns)

# [['import network', 137, '..../path/file1.py'], ['x = "password"', 5878, '..../path/file2.py']]
def get_LOC_by_warning(package_name):
    """
    get all the LOC for a specific package

    Arguments
    ---------
    package_name : the package you want warnings for (do not specify a version)

    Returns
    ---------
    warnings : a list of lines of code (and their metadata)
    """
    client = Elasticsearch(host=HOST)
    s = Search(using=client)
    s = s.source(['package', 'type', 'severity', 'score', 'line', 'line_no', 'location'])
    #q = Q("match", type=warning)  & Q("match", severity=severity)
    s = s.query("match", package__keyword=package_name)
    s = s.exclude("match", tag="test_code")
    #print(s.to_dict())

    # process the query
    results = []
    for hit in s.scan():
        if not hasattr(hit, "line"):
           hit.line = None
        if not hasattr(hit, "line_no"):
           hit.line_no = None
        if not hasattr(hit, "location"):
           hit.location = None
        #print(hit.to_dict())
        results.append([hit.line, hit.line_no, hit.location, hit.type, hit.severity])
    #print(results)
    return results

def get_all_warnings_x(warning_type, all_warnings):
    """
    get all warnings for all packages, specified by a specific warning type

    Arguments
    ---------
    warning_type : the name of the warning type
    all_warnings : a dict of all the warnings of that type and their metadata, keyed by package name,
        which is empty to start

    Returns:
    ---------
    populates all_warnings

    """
    client = Elasticsearch(host=HOST)
    #s = Search(using=client, index='production-logs-2021.04.14').params(request_timeout=60)
    s = Search(using=client)
    s = s.source(['package', 'type', 'severity', 'score', 'line','line_no'])
    s = s.query("match", type=warning_type)
    s = s.exclude("match", tag="test_code")
    #s = s.query("multi_match", type=warning_type, fields=['package', 'type', 'severity', 'score', 'line','line_no'])
    #print(s.to_dict())
    #response = s.execute()
    #print(response)
    #for i in response:
        #print(i)

    # process the query
    for hit in s.scan():
        if hit.package not in all_warnings.keys():
                        all_warnings[hit.package] = []
        if not hasattr(hit, "severity"):
            hit.severity = None
        if not hasattr(hit, "score"):
            hit.score = None
        if not hasattr(hit, "line"):
            hit.line = None
        if not hasattr(hit, "line_no"):
            hit.line_no = None
        all_warnings[hit.package].append({'warning_type':warning_type, 'severity':hit.severity, 'score':hit.score, 'line':hit.line, 'line_no':hit.line_no})
    #print(all_warnings)


def get_score_percentiles(array, score):
    """
    returns the percentile severity score of a score

    Arguments
    ---------
    array : a list of all scores of all packages in the database
    score : the score you want converted to a percentile using that array

    Returns
    ---------
    the score converted to a percent between 0 and 10
    """

    return int(scipy.stats.percentileofscore(array, score) / 10) 


def get_all_warnings_counts_x(warning_type, all_warnings, all_unique_warnings, all_severities, all_raw_scores):
    """
    populates the incoming dictionaries by the warning type specified

    Arguments
    ---------
    warning_type : the AuraScan warning type to search the database for
    all_warnings : a dict that stores the total number of warnings, keyed by package
    all_unique_warnings : a dict that stores the total number of unique warnings, keyed by package
    all_severities : a dict that stores all the severities for each package
    all_raw_scores : a list of all the scores of all packages, used to calculate percentile scores

    Returns
    ---------
    None, but populates all_warnings, all_unique_warnings, and all_severities
    """
    client = Elasticsearch(host=HOST)
    s = Search(using=client).params(request_timeout=30)
    s = s.source(['package', 'type', 'severity', 'score'])
    s = s.query("match", type=warning_type)
    s = s.exclude("match", tag="test_code")
    #print(s.to_dict())

    # process the query
    for hit in s.scan():
        #print(hit)
        #print(hit.score)
        if not hasattr(hit, "severity"):
            hit.severity = None
        if not hasattr(hit, "score"):
            hit.score = None
        
        if hit.package not in all_warnings.keys():
                        all_warnings[hit.package] = 0
        all_warnings[hit.package] += 1

        if hit.package not in all_unique_warnings.keys():
                        all_unique_warnings[hit.package] = {}
        if warning_type not in all_unique_warnings[hit.package].keys():
                        all_unique_warnings[hit.package][warning_type] = 1

        if hit.package not in all_severities.keys():
                        all_severities[hit.package] = 0
        all_severities[hit.package] += get_score_percentiles(all_raw_scores, int(hit.score))


def connect_and_load_default(warning_types):
    """
    loads all the packages for the specified warning_type
    Arguments
    ---------
    warning_types : the Aura warning types you care about
    Returns
    ---------
    warnings : a dict of lists of warnings, by package name
    """

    all_warnings = {}
    for warning in warning_types:
        get_all_warnings_x(warning, all_warnings)
    return all_warnings

'''
def iterate_distinct_field(fieldname, pagesize=250, **kwargs):
    """
    Helper to get all distinct values from ElasticSearch
    (ordered by number of occurrences)
    """
    es = Elasticsearch(host=HOST)

    compositeQuery = {
        "size": pagesize,
        "sources": [{
                fieldname: {
                    "terms": {
                        "field": fieldname
                    }
                }
            }
        ]
    }
    # Iterate over pages
    while True:
        result = es.search(**kwargs, body={
            "aggs": {
                "values": {
                    "composite": compositeQuery
                }
            }
        })
        # Yield each bucket
        for aggregation in result["aggregations"]["values"]["buckets"]:
            yield aggregation
        # Set "after" field
        if "after_key" in result["aggregations"]["values"]:
            compositeQuery["after"] = \
                result["aggregations"]["values"]["after_key"]
        else: # Finished!
            break

def get_unique_warnings():
    res = iterate_distinct_field(fieldname="severity.keyword", index="lambda-s3-file-index")
    for result in res:
        print(result)
    return res
'''

#if __name__ == '__main__':
    #get_all_scores_x()
    #get_LOC_by_warning('support', 'ModuleImport', 'unknown')
    #get_warnings_by_package()
    #get_unique_package_list()
    #get_all_scores()
    #get_unique_warnings()
    #all_warnings = {}
    #get_all_warnings_x('SensitiveFile', all_warnings) 
    #get_unique_package_list()