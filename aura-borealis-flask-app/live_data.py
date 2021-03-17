"""
This file loads live Aura data
"""

from es.elastic.api import connect
HOST = '192.168.68.9'


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