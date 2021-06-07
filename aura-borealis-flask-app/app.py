from flask import Flask, render_template, request, make_response, jsonify
from flask_datepicker import datepicker
import json
import time
import pickle
import random

from search import PackageSearch
import os
SECRET_KEY = os.urandom(32)

#from live_data import connect_and_load_default, get_all_warnings_counts, get_warnings_by_package, get_LOC_by_warning
#from live_data import get_package_score, get_score_percentiles, get_all_scores
from live_data import *

from dummy_data import *

unique_packages = []
all_raw_scores = []

# hand select certain packages and warnings for demo purposes
PACKAGES = ['requests', 'network', 'pycurl', 'pandas', 'boto', 'sqlint', 'ssh-python', 'sqlmap', 
		'netlogger', 'streamlit', 'pillow', 'huggingface']
#WARNING_TYPES = ['LeakingSecret' ]

WARNING_TYPES = ['LeakingSecret', 'ModuleImport', 'SuspiciousFile', 'OutdatedPackage', 'UnpinnedPackage',' Base64Blob',
      'Binwalk', 'InvalidRequirement', 'ArchiveAnomaly', 'SuspiciousArchiveEntry', 'SetupScript', 'Wheel',  
      'DataProcessing', 'FileStats', 'ASTAnalysisError', 'ASTParseError', 'FunctionCall', 'SQLInjection',
      'StringMatch', 'YaraMatch', 'YaraError', 'CryptoKeyGeneration', 'Detection', 'MalformedXML', 'TaintAnomaly',
      'Misc']




SEVERITIES = ['critical', 'high', 'moderate', 'low', 'unknown']


def get_user_selected_warnings(request):
	'''
		collects all the checked checkboxes from a POST request used on various forms, 
		and returns them as a list of strings
	'''
	warning_types_selected = []
	if request.form.get('LeakingSecret') != None:
		warning_types_selected.append(request.form.get('LeakingSecret'))
	if request.form.get('SuspiciousFile') != None:
		warning_types_selected.append(request.form.get('SuspiciousFile'))
	if request.form.get('SensitiveFile') != None:
		warning_types_selected.append(request.form.get('SensitiveFile'))
	if request.form.get('SQLInjection') != None:
		warning_types_selected.append(request.form.get('SQLInjection'))
	if request.form.get('SetupScript') != None:
		warning_types_selected.append(request.form.get('SetupScript'))
	if request.form.get('FunctionCall') != None:
		warning_types_selected.append(request.form.get('FunctionCall'))
	if request.form.get('ModuleImport') != None:
		warning_types_selected.append(request.form.get('ModuleImport'))
	if request.form.get('Base64Blob') != None:
		warning_types_selected.append(request.form.get('Base64Blob'))
	if request.form.get('Binwalk') != None:
		warning_types_selected.append(request.form.get('Binwalk'))
	if request.form.get('CryptoKeyGeneration') != None:
		warning_types_selected.append(request.form.get('CryptoKeyGeneration'))
	if request.form.get('DataProcessing') != None:
		warning_types_selected.append(request.form.get('DataProcessing'))
	if request.form.get('Detection') != None:
		warning_types_selected.append(request.form.get('Detection'))
	if request.form.get('InvalidRequirement') != None:
		warning_types_selected.append(request.form.get('InvalidRequirement'))
	if request.form.get('MalformedXML') != None:
		warning_types_selected.append(request.form.get('MalformedXML'))
	if request.form.get('ArchiveAnomaly') != None:
		warning_types_selected.append(request.form.get('ArchiveAnomaly'))
	if request.form.get('SuspiciousArchiveEntry') != None:
		warning_types_selected.append(request.form.get('SuspiciousArchiveEntry'))
	if request.form.get('OutdatedPackage') != None:
		warning_types_selected.append(request.form.get('OutdatedPackage'))
	if request.form.get('UnpinnedPackage') != None:
		warning_types_selected.append(request.form.get('UnpinnedPackage'))
	if request.form.get('TaintAnomaly') != None:
		warning_types_selected.append(request.form.get('TaintAnomaly'))
	if request.form.get('Wheel') != None:
		warning_types_selected.append(request.form.get('Wheel'))
	if request.form.get('StringMatch') != None:
		warning_types_selected.append(request.form.get('StringMatch'))
	if request.form.get('FileStats') != None:
		warning_types_selected.append(request.form.get('FileStats'))
	if request.form.get('YaraMatch') != None:
		warning_types_selected.append(request.form.get('YaraMatch'))
	if request.form.get('YaraError') != None:
		warning_types_selected.append(request.form.get('YaraError'))
	if request.form.get('ASTAnalysisError') != None:
		warning_types_selected.append(request.form.get('ASTAnalysisError'))
	if request.form.get('ASTParseError') != None:
		warning_types_selected.append(request.form.get('ASTParseError'))
	if request.form.get('Misc') != None:
		warning_types_selected.append(request.form.get('Misc'))

	return warning_types_selected

# #########################################################################################################
# SET UP FLASK APP
# #########################################################################################################

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
datepicker(app)


def sum_warning_count_init(init_all_warnings, init_all_unique_warnings, init_all_severities):
		for warning_type in WARNING_TYPES:
				get_all_warnings_counts_x(warning_type, init_all_warnings, init_all_unique_warnings, init_all_severities, all_raw_scores)

@app.route('/')
def home():
	#print(get_score_percentiles(all_raw_scores, 5))
	return render_template('./home.html')

@app.route('/about/')
def about():
	return render_template('about.html')

# Display all packages with the highest number of warnings (uses live data)
@app.route('/top_warnings/', methods=['GET', 'POST'])
def top_warnings():
	# load the live Aura data
	warning_types_selected = []

	if request.method == 'POST':
		warning_types_selected = get_user_selected_warnings(request)
		dict_packages = connect_and_load_default(set(warning_types_selected))
		checked = {}
		for type_w in warning_types_selected:
			checked[type_w] = True

	else:
		warning_types_selected = ['LeakingSecret']
		checked = {'LeakingSecret':True}

		# load the default packge from a cached version to increase speed
		#dict_packages = connect_and_load_default(warning_types_selected)
		#cacheData(dict_packages, 'dict_packages_default_LeakingSecret')
		dict_packages = loadData('dict_packages_default_LeakingSecret')

	data = []
	for package in dict_packages.keys():
		#print('processing', package)
		entry = {}
		entry['package'] = "<a href='/single_package?package=" + package +"'>" + package +"</a>"
		warning_counts = {}
		for warning in dict_packages[package]:	# go through a list of all the warnings for a package
			if warning['warning_type'] not in warning_counts.keys():
				warning_counts[warning['warning_type']] = 1
			else:
				warning_counts[warning['warning_type']] += 1
		#print('warning_counts', warning_counts)
		for warning_type in warning_types_selected:
			if warning_type in warning_counts.keys():
				entry[warning_type.lower()] = warning_counts[warning_type]
			else:
				entry[warning_type.lower()] = 0
		#print('entry', entry)
		data.append(entry)

	# other column settings -> http://bootstrap-table.wenzhixin.net.cn/documentation/#column-options
	columns = []
	columns.append({"field": "package", "title": "package", "sortable": True,})
	for warning in warning_types_selected:
		columns.append({"field": warning.lower(), "title": warning, "sortable": True,})

	return render_template("top_warnings.html",
		data=data,
		columns=columns,
		title='Aura Borealis',
		checked=checked)

# display all the packages by their overall severity scores, total warnings, and total unique warnings
@app.route('/sum_warning_count/', methods=['GET', 'POST'])
def sum_warning_count():
	#all_warnings = {}
	#all_unique_warnings = {}
	#all_severities = {}
	#for warning_type in WARNING_TYPES:
	#	get_all_warnings_counts_x(warning_type, all_warnings, all_unique_warnings, all_severities, all_raw_scores)


	all_unique_warnings_summed = {}
	for package in init_all_unique_warnings.keys():
		count = 0
		for warning in init_all_unique_warnings[package].keys():
			count += init_all_unique_warnings[package][warning]
		all_unique_warnings_summed[package] = count

	columns = [
		{
		"field": "package", # which is the field's name of data key 
		"title": "package", # display as the table header's name
		"sortable": True,
		},
		{
		"field": "total_warnings_count",
		"title": "total number of indicators",
		"sortable": True,
		},
		{
		"field": "unique_warnings_count",
		"title": "number of unique indicators",
		"sortable": True,
		},
		{
		"field": "severity_rating",
		"title": "overall severity score",
		"sortable": True,
		}
	]

	data = []
	for package in list(init_all_severities.keys()):
		entry = {"package": "<a href='/single_package?package=" + package + "'>" + package + "</a>"}
		entry['total_warnings_count'] = init_all_warnings[package]
		entry['unique_warnings_count'] = all_unique_warnings_summed[package]
		entry['severity_rating'] = 0
		#print("init_all_percentiles", list(init_all_percentiles.values())[:5])
		if package in init_all_percentiles.keys():
			entry['severity_rating'] = init_all_percentiles[package]
		data.append(entry)

	return render_template("sum_warning_count.html",
		data=data,
		columns=columns,
		title='Aura Borealis')

# display all packages that have changed in total warnings, total unique warning, or severity 
# score between two dates 
@app.route('/diff_dates/', methods=['GET', 'POST'])
def diff_dates():
	search = PackageSearch(request.form)
	if request.method == 'POST':
		return search_results(search)

	columns = [
		{
		"field": "package", # which is the field's name of data key 
		"title": "package", # display as the table header's name
		"sortable": True,
		},
		{
		"field": "num_changes",
		"title": "total number of indicators changed",
		"sortable": True,
		},
	 {
		"field": "num_changes_unique",
		"title": "number of unique indicators changed",
		"sortable": True,
		},
		{
		"field": "changes_score",
		"title": "change in overall severity score",
		"sortable": True,
		},
	]

	data = getDummyData('diff_dates')

	return render_template("diff_dates.html",
		data=data,
		columns=columns,
		title='Aura Borealis',
		form=search)

# display all lines of code associated with a package, warnings, and severity
@app.route('/loc/', methods=['GET', 'POST'])
def loc():
	search = PackageSearch(request.form)
	package = request.args.get('package')
	warning = request.args.get('warning')
	severity = request.args.get('severity')

	if severity == 'ALL':
		LOCs = []
		for severity in SEVERITIES:
			LOCs += get_LOC_by_warning(package, warning, severity)
	else:
		LOCs = get_LOC_by_warning(package, warning, severity)

	columns = [
		{
		"field": "line", # which is the field's name of data key 
		"title": "line with indicators", # display as the table header's name
		"sortable": True,
		},
		{
		"field": "code", # which is the field's name of data key 
		"title": "source code", # display as the table header's name
		"sortable": True,
		},
		{
		"field": "filename", # which is the field's name of data key 
		"title": "filename", # display as the table header's name
		"sortable": True,
		},
	]

	data = []
	for loc in LOCs:
		data.append({'line':loc[1], 'code':loc[0], 'filename':loc[2].split('$')[1]})

	return render_template("loc.html",
		data=data,
		columns=columns,
		title='Aura Borealis',
		package=package,
		warning=warning)

# display a comparison between two packages, two versions, or a package and a benchmark profile
# https://prismjs.com/#examples	<--- use this for hover over LOC TODO
# http://inria.github.io/sparklificator/ <-- TODO
@app.route('/comparison/', methods=['GET', 'POST'])
def comparison():
	search = PackageSearch(request.form)
	if request.method == 'POST':
		#return search_results(search)
		package1 = request.form['package1']
		package2 = request.form['package2']
	else:
		package1 = request.args.get('package1')
		package2 = request.args.get('package2')

	if package1 == None:
		package1 = "pykalman"
		package2 = "gps-helper-cs"

	score1 = init_all_percentiles[package1]
	score2 = init_all_percentiles[package1]

	data = []
	data.append({"package1": score1,"package2": score2,"warning_type": "OVERALL SEVERITY"})

	package1_warnings = {}
	package2_warnings = {}
	get_warnings_by_package(package1, package1_warnings)
	get_warnings_by_package(package2, package2_warnings)


	for warning_type in WARNING_TYPES:
		p1_sum = 0
		p2_sum = 0
		for severity in SEVERITIES:
			if warning_type in package1_warnings.keys() and severity in package1_warnings[warning_type].keys():
				p1_sum += package1_warnings[warning_type][severity]
			if warning_type in package2_warnings.keys() and severity in package2_warnings[warning_type].keys():
				p2_sum += package2_warnings[warning_type][severity]
		if p1_sum != 0:
			p1_sum = '<a href="/loc?package=' + package1 + '&warning=' + warning_type + '&severity=ALL">' + str(p1_sum) + '</a>'
		if p2_sum != 0:
			p2_sum = '<a href="/loc?package=' + package2 + '&warning=' + warning_type + '&severity=ALL">' + str(p2_sum) + '</a>'		
		data.append({"package1": p1_sum,"package2": p2_sum,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#" + warning_type.lower() + "'>" + warning_type + "</a>"})

	columns = [
		{
		"field": "package1", # which is the field's name of data key 
		"title": "<a href='/single_package?package=" + package1 + "'>" + package1 + "</a>", # display as the table header's name
		"sortable": True,
		},
		{
		"field": "package2",
		"title": "<a href='/single_package?package=" + package2 + "'>" + package2 + "</a>",
		"sortable": True,
		},
	 {
		"field": "warning_type",
		"title": "indicator type",
		"sortable": True,
		},
	]

	return render_template("comparison.html",
		data=data,
		columns=columns,
		title='Aura Borealis',
		form=search,
		package1=package1,
		package2=package2)

# display warning information for a single package
@app.route('/single_package/', methods=['GET', 'POST'])
def single_package():

	warning_types_selected = []
	checked = {}
	if request.method == 'POST':
		warning_types_selected = get_user_selected_warnings(request)
		for type_w in warning_types_selected:
			checked[type_w] = True
	
	if len(warning_types_selected) == 0:
		warning_types_selected = WARNING_TYPES

	package = request.args.get('package')
	if package == None:
		if request.method == "POST":
			package = request.form['package']
		else:
			package = 'gps-helper-cs'
	score = init_all_percentiles[package]
	count_warnings = {}
		
	get_warnings_by_package(package, count_warnings)

	data = []
	LOCs = get_LOC_by_warning(package)
	for warning_type in warning_types_selected:
		for severity in SEVERITIES:
			cleaned_locs = []
			for loc in LOCs:
				if loc[2] is None:
					cleaned_locs.append({'warning_type':warning_type, 'severity':severity, 'line':loc[1], 'code':loc[0], 'filename':loc[2]})
				else:   
					cleaned_locs.append({'warning_type':warning_type, 'severity':severity, 'line':loc[1], 'code':loc[0], 'filename':loc[2].split('$')[1]})

	entries = {}
	for loc in LOCs:
		warning_type = loc[3]
		severity = loc[4]
		if warning_type not in entries.keys():
			entries[warning_type] = {}
			entries[warning_type]['label'] = "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#" + warning_type.lower() + "' target='_blank'>" + warning_type + "</a>"
		if severity in entries[warning_type].keys():
			entries[warning_type][severity]['count'] += 1
		else:
			entries[warning_type][severity] = {}
			entries[warning_type][severity]['count'] = 1

	data = []
	for warning_type in entries.keys():
		if warning_type in warning_types_selected:
			row = {}
			row['warning_type'] = "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#" + warning_type.lower() + "' target='_blank'>" + warning_type + "</a>"
			for severity in SEVERITIES:
				if severity in entries[warning_type].keys(): 
					row[severity] = entries[warning_type][severity]['count']
				else:
					row[severity] = 0

			data.append(row)

	cleaned_locs = []
	LOCs = get_LOC_by_warning(package)
	for loc in LOCs:
		if loc[2] is None and loc[3] in warning_types_selected:
			cleaned_locs.append({'warning_type':entries[loc[3]]['label'], 'severity':loc[4], 'line':loc[1], 'code':loc[0], 'filename':loc[2]})
		elif loc[3] in warning_types_selected:   
			cleaned_locs.append({'warning_type':entries[loc[3]]['label'], 'severity':loc[4], 'line':loc[1], 'code':loc[0], 'filename':loc[2].split('$')[1]})

	loc_columns = [
	{
		"field": "warning_type",
		"title": "indicator type",
		"sortable": True,
		},
		{
		"field": "severity", # which is the field's name of data key 
		"title": "severity", # display as the table header's name
		"sortable": True,
		},
		{
		"field": "line",
		"title": "line",
		"sortable": True,
		},
		{
		"field": "code", # which is the field's name of data key 
		"title": "code", # display as the table header's name
		"sortable": True,
		},
		{
		"field": "filename",
		"title": "filename",
		"sortable": True,
		},
	]

	columns = [
	{
		"field": "warning_type",
		"title": "indicator type",
		"sortable": True,
		},
		{
		"field": "critical", # which is the field's name of data key 
		"title": "critical", # display as the table header's name
		"sortable": True,
		},
		{
		"field": "high",
		"title": "high",
		"sortable": True,
		},
		{
		"field": "moderate", # which is the field's name of data key 
		"title": "moderate", # display as the table header's name
		"sortable": True,
		},
		{
		"field": "low",
		"title": "low",
		"sortable": True,
		},
		{
		"field": "unknown",
		"title": "unknown",
		"sortable": True,
		},
	]

	return render_template("single_package.html",
		data=data,
		columns=columns,
		title='Aura Borealis',
		package=package,
		score=score,
		data_cleaned_locs=cleaned_locs,
		loc_columns=loc_columns,
		checked=checked)

@app.route('/autocomplete/<inp>', methods=['GET'])
def autocomplete(inp):
	pkg_list = []
	#print(unique_packages)
	#unique_packages = get_unique_package_list()
	#for pkg in unique_packages:
	#	pkg_list.extend(map(lambda st: st.strip(), map(lambda s: str(s), pkg.split(','))))
	filtered=filter(lambda ing: ing.startswith(inp),set(unique_packages))
	#print(list(filtered))
	return jsonify({"listaing":list(filtered)})
	#return make_response({"listaing":list(filtered)}, 200)

# #########################################################################################################
# MAIN
# #########################################################################################################

def cacheData(data, name):
	with open(name + '.pickle', 'wb') as handle:
	  pickle.dump(data, handle, protocol=pickle.HIGHEST_PROTOCOL)
	print("Printed to " + name + ".pickle")

def loadData(name):
	infile = open(name+".pickle",'rb')
	data = pickle.load(infile)
	infile.close()
	return data

if __name__ == '__main__':
		print("Initializing App Data")
		
		'''tic = time.perf_counter()
		init_all_warnings = {}
		init_all_unique_warnings = {}
		init_all_severities = {}
		sum_warning_count_init(init_all_warnings, init_all_unique_warnings, init_all_severities)
		unique_packages = get_unique_package_list()
		print(unique_packages[:10])
		print("*********** WARNINGS ***************")
		print(init_all_warnings)
		print("*********** UNIQUE WARNINGS ***************")
		print(init_all_unique_warnings)
		print("*********** SEVERITIES ***************")
		print(init_all_severities)
		cacheData(unique_packages, 'unique_packages')
		cacheData(init_all_warnings, 'init_all_warnings')
		cacheData(init_all_unique_warnings, 'init_all_unique_warnings')
		cacheData(init_all_severities, 'init_all_severities')
		cacheData(init_all_percentiles, 'init_all_percentiles')
		print('init_all_percentiles', init_all_percentiles)'''


		

		unique_packages = list(loadData('unique_packages'))
		#print('unique_packages', list(unique_packages))
		init_all_warnings = loadData('init_all_warnings')
		#print('init_all_warnings', init_all_warnings)
		init_all_unique_warnings = loadData('init_all_unique_warnings')
		#print('init_all_unique_warnings', init_all_unique_warnings)
		init_all_severities = loadData('init_all_severities')
		#print('init_all_severities', init_all_severities)
		init_all_percentiles = loadData('init_all_percentiles')
		#print('init_all_percentiles', init_all_percentiles)

		all_raw_scores = init_all_severities
		#toc = time.perf_counter()
		#print(f"App data initialized -  {toc - tic:0.4f} seconds")
		app.run(host='0.0.0.0', debug=True, port=7000)

