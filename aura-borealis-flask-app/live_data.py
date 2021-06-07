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
#   """
#   get all the LOC for a specific package and warning and severity

#   Arguments
#   ---------
#   package : the package you want warnings for (do not specify a version)
#   warning : the Aura warning types you care about
#   severity : the severity level you care about.

#   Returns
#   ---------
#   warnings : a list of lines of code tuples
#   """
        client = Elasticsearch(host=HOST)
        s = Search(using=client)
        s = s.source(['package', 'type', 'severity', 'score', 'line', 'line_no', 'location'])
        #q = Q("match", type=warning)  & Q("match", severity=severity)
        s = s.query("match", package__keyword=package_name)
        s = s.exclude("match", tag="test_code")
        #print(s.to_dict())
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

    #conn = connect(host=HOST)
    #curs = conn.cursor()

    #print("select line, line_no, location from lambda-s3-file-index  where package='" + package + "' and type='" + warning + "' and severity='" + severity + "'  and tags.keyword != 'test_code'")
    #curs.execute(
    #           "select line, line_no, location from lambda-s3-file-index  where package='" + package + "' and type='" + warning + "' and severity='" + severity + "'  and tags.keyword != 'test_code'"
    #   )
    #results = []
    #for row in curs:
    #   print("in ruc")
    #   print(row[0])
    #   results.append([row[0], row[1], row[2]])
    #return results

# http://192.168.68.9:5601/app/kibana#/discover?_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:now-1y,to:now))&_a=(columns:!(_source),filters:!(),index:'30bc7830-7530-11eb-870c-ad2473be90c7',interval:auto,query:(language:kuery,query:''),sort:!())


def get_all_warnings_x(warning_type, all_warnings):
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


def get_all_scores_x():
    packages = {}
    client = Elasticsearch(host=HOST)

    s = Search(using=client)
    s = s.source(['score'])
    s = s.query("match", package="12306-booking")
    s = s.exclude("match", tag="test_code")
    s = s[:0]
    s.aggs.metric('total_score', 'sum', field='score')


    response = s.execute()
    #print(response.aggregations.total_score.value)
    #print(s.aggs['per_score'])
    #print(s.hits.total)
    #print(s.aggs['per_score'].buckets)
    #print(response.to_dict())

def get_all_scores(unique_packages):
    """
    processes the entire database to collect raw severity scores for all packages
    meant to be called once at the load of the app, because this takes a while...maybe it should be cached?
    Returns
    ---------
    a list of all severity scores
    """

    packages = {}
    client = Elasticsearch(host=HOST)

    for package in unique_packages:
        #print(package)
        total = 0
        s = Search(using=client)
        s = s.source(['score'])
        s = s.query("match", package=package)
        s = s.exclude("match", tag="test_code")
        s = s[:0]
        s.aggs.metric('total_score', 'sum', field='score')
        response = s.execute()
        #print(response.aggregations.total_score.value)

        #for hit in s.scan():
            #total += int(hit.score)
        #print(total)

        packages[package] = response.aggregations.total_score.value

    #print(packages)
    return list(packages.values())

def get_score_percentiles(array, score):
    """
    returns the percentile severity score of a score
    Arguments
    ---------
    array : a list of all scores of all packages in the database
    score : the score you want converted to a percentile using that array
    Returns
    ---------
    the score converted to a percent between 0 and 100
    """

    return int(scipy.stats.percentileofscore(array, score) / 10) 


def get_package_score(package, init_all_severities):
        """
        gets the severity score for a package
        Arguments
        ---------
        package : the package you care about
        Returns
        ---------
        score : a positive integer, the sum of all the severitiy scores of all warnings for this package
        """

        client = Elasticsearch(host=HOST)

        s = Search(using=client)
        s = s.source(['score'])
        s = s.query("match", package=package)
        s = s.exclude("match", tag="test_code")
        s = s[:0]
        s.aggs.metric('total_score', 'sum', field='score')


        response = s.execute()
        #print(response.aggregations.total_score.value)

        return response.aggregations.total_score.value
        #score = 0
        #all_sevs = init_all_severities.get(package)
        #if all_sevs:
        #   for sev in all_sevs:
        #       score += int(sev["score"])
        #return score

def get_all_warnings_counts_x(warning_type, all_warnings, all_unique_warnings, all_severities, all_raw_scores):
    client = Elasticsearch(host=HOST)
    s = Search(using=client).params(request_timeout=30)
    s = s.source(['package', 'type', 'severity', 'score'])
    s = s.query("match", type=warning_type)
    s = s.exclude("match", tag="test_code")
    #print(s.to_dict())

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


def get_all_warnings_counts(warning_type, all_warnings, all_unique_warnings, all_severities, all_raw_scores):
    """
    get all the warnings for a warning_type
    Arguments
    ---------
    warning_type : the Aura warning type you care about
    all_warnings : a dictionary of all warnings, grouped by package, to be updated
    all_unique_warnings : a dictionary of all unique warnings, grouped by package, to be updated
    all_severities :  dictionary of severity scores, grouped by package, to be updated
    """

    conn = connect(host=HOST)
    curs = conn.cursor()

    curs.execute(
        "select package, type, severity, score from lambda-s3-file-index  where type='" + warning_type + "'" + DEBUG
    )

    for row in curs:
        package = row[0]
        warning_type = row[1]
        severity = row[2] 
        score = row[3]

        # update the dictionary that counts the total number of warnings (including duplicates)
        if package not in all_warnings.keys():
            all_warnings[package] = 0
        all_warnings[package] += 1

        if package not in all_unique_warnings.keys():
            all_unique_warnings[package] = {}
        if warning_type not in all_unique_warnings[package].keys():
            all_unique_warnings[package][warning_type] = 1

        if package not in all_severities.keys():
            all_severities[package] = 0
        all_severities[package] += get_score_percentiles(all_raw_scores, int(score))


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