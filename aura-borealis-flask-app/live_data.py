"""
This file loads live Aura data
"""
from elasticsearch import Elasticsearch
from es.elastic.api import connect
HOST = '192.168.68.9'

DEBUG = " limit 100"

def get_warnings_by_package(package, warning, severity, package_warnings):
	"""
	get all the warnings for a specific package

	Arguments
	---------
	package : the package you want warnings for (do not specify a version for now)
	warning : the Aura warning types you care about
	severity : the severity level you care about
	package_warnings : the dict this function will update
	"""
	conn = connect(host=HOST)
	curs = conn.cursor()

	count_warnings = {}
	curs.execute(
			    "select count(*) from aura_detections where package='" + package + "' and type='" + warning + "' and severity='" + severity + "'"
		)
	for row in curs:
		if warning not in package_warnings.keys():
			package_warnings[warning] = {}
		package_warnings[warning][severity] = row[0]


def get_LOC_by_warning(package, warning, severity):
	"""
	get all the LOC for a specific package and warning and severity

	Arguments
	---------
	package : the package you want warnings for (do not specify a version)
	warning : the Aura warning types you care about
	severity : the severity level you care about.

	Returns
	---------
	warnings : a list of lines of code tuples
	"""
	conn = connect(host=HOST)
	curs = conn.cursor()

	print("select line, line_no, location from aura_detections where package='" + package + "' and type='" + warning + "' and severity='" + severity + "'")
	curs.execute(
			    "select line, line_no, location from aura_detections where package='" + package + "' and type='" + warning + "' and severity='" + severity + "'"
		)
	results = []
	for row in curs:
		print("in ruc")
		print(row[0])
		results.append([row[0], row[1], row[2]])
	return results

# http://192.168.68.9:5601/app/kibana#/discover?_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:now-1y,to:now))&_a=(columns:!(_source),filters:!(),index:'30bc7830-7530-11eb-870c-ad2473be90c7',interval:auto,query:(language:kuery,query:''),sort:!())
def get_all_warnings(warning_type, all_warnings):
	"""
	get all the warnings for a warning_type across all packages

	Arguments
	---------
	warning_type : the Aura warning type you care about
	all_warnings : a dictionary of all warnings, grouped by package, to be modified by this function
	"""

	conn = connect(host=HOST)
	curs = conn.cursor()

	curs.execute(
		"select package, type, severity, score, line, line_no from aura_detections where type='" + warning_type + "'" + DEBUG
	)
	for row in curs:
		package = row[0]
		warning_type = row[1]
		severity = row[2] 
		score = row[3]
		line = row[4]
		line_no = row[5]

		if package not in all_warnings.keys():
			all_warnings[package] = []
		all_warnings[package].append({'warning_type':warning_type, 'severity':severity, 'score':score, 'line':line, 'line_no':line_no})

def get_package_score(package):
	"""
	gets the severity score for a package

	Arguments
	---------
	package : the package you care about

	Returns
	---------
	score : a positive integer, the sum of all the severitiy scores of all warnings for this package
	"""

	conn = connect(host=HOST)
	curs = conn.cursor()

	curs.execute(
		"select score from aura_detections where package='" + package + "'" + DEBUG
	)

	score = 0
	for row in curs:
		score += int(row[0])
	return score

def get_all_warnings_counts(warning_type, all_warnings, all_unique_warnings, all_severities):
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
		"select package, type, severity, score from aura_detections where type='" + warning_type + "'" + DEBUG
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
		all_severities[package] += int(score)


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
		get_all_warnings(warning, all_warnings)
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
    res = iterate_distinct_field(es, fieldname="severity.keyword", index="aura_detections")
    for result in res:
        print(result)
    return res

