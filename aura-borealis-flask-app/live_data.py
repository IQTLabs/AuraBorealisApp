"""
This file loads live Aura data
"""
from elasticsearch import Elasticsearch
from es.elastic.api import connect
HOST = '192.168.68.9'

es = Elasticsearch(host=HOST)

def get_warnings(package, warning_types, curs):
	"""
	get all the warning for a specific package

	Arguments
	---------
	package : the package you want warnings for (do not specify a version)
	warning_types : the Aura warning types you care about
	curs : the cursor to the opened connection to the database

	Returns
	---------
	warnings : a dict of warnings, by warning type, for this package
	"""
	count_warnings = {}
	for warning in warning_types:
		curs.execute(
		    "select count(*) from aura_detections where package='" + package + "' and type='" + warning + "'"
		)
		count_warnings[warning.lower()] = [row for row in curs]
	return count_warnings


def connect_and_load(packages, warning_types):
	"""
	loads all the warnings for the specified packages

	Arguments
	---------
	packages : the list package you want warnings for (do not specify versions)
	warning_types : the Aura warning types you care about

	Returns
	---------
	warnings : a dict of warnings, by package name
	"""
	conn = connect(host=HOST)
	curs = conn.cursor()

	warnings = {}
	for package in packages:
		warnings[package] = get_warnings(package, warning_types, curs)

	return warnings

def iterate_distinct_field(es, fieldname, pagesize=250, **kwargs):
    """
    Helper to get all distinct values from ElasticSearch
    (ordered by number of occurrences)
    """
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

if __name__ == '__main__':
    get_unique_warnings()
