from flask import Flask, render_template, request
from flask_datepicker import datepicker
import json

from search import PackageSearch
import os
SECRET_KEY = os.urandom(32)

from live_data import connect_and_load_default, get_all_warnings_counts, get_warnings_by_package, get_LOC_by_warning, get_package_score
from dummy_data import *


# hand select certain packages and warnings for demo purposes
PACKAGES = ['requests', 'network', 'pycurl', 'pandas', 'boto', 'sqlint', 'ssh-python', 'sqlmap', 
        'netlogger', 'streamlit', 'pillow', 'huggingface']

WARNING_TYPES = ['LeakingSecret', 'SuspiciousFile', 'SQLInjection', 'SensitiveFile', 'SetupScript', 'FunctionCall', 'ModuleImport',
        'Base64Blob', 'Binwalk', 'CryptoKeyGeneration', 'DataProcessing', 'Detection', 'InvalidRequirement', 'MalformedXML',
        'ArchiveAnomaly', 'SuspiciousArchiveEntry', 'OutdatedPackage', 'UnpinnedPackage', 'TaintAnomaly', 'Wheel', 'StringMatch',
        'FileStats', 'YaraMatch', 'YaraError', 'ASTAnalysisError', 'ASTParseError', 'Misc']

SEVERITIES = ['critical', 'severe', 'moderate', 'low', 'unknown']

# #########################################################################################################
# SET UP FLASK APP
# #########################################################################################################

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
datepicker(app)


@app.route('/')
def home():
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

        dict_packages = connect_and_load_default(set(warning_types_selected))

    else:
        warning_types_selected = ['LeakingSecret']
        dict_packages = connect_and_load_default(warning_types_selected)

    data = []
    for package in dict_packages.keys():
        #print('processing', package)
        entry = {}
        entry['package'] = "<a href='/single_package?package=" + package +"'>" + package +"</a>"
        warning_counts = {}
        for warning in dict_packages[package]:  # go through a list of all the warnings for a package
            #print('warning', warning)
            for warning_type in warning_types_selected:
                #print('warning_type', warning_type)
                if warning_type not in warning_counts.keys():
                    warning_counts[warning_type] = 1
                else:
                    warning_counts[warning_type] += 1
        #print('warning_counts', warning_counts)
        for warning_type in warning_types_selected:
            entry[warning_type.lower()] = warning_counts[warning_type]
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
      title='Aura Borealis')

# display all the packages by their overall severity scores, total warnings, and total unique warnings
@app.route('/sum_warning_count/', methods=['GET', 'POST'])
def sum_warning_count():
    all_warnings = {}
    all_unique_warnings = {}
    all_severities = {}
    for warning_type in WARNING_TYPES:
        get_all_warnings_counts(warning_type, all_warnings, all_unique_warnings, all_severities)

    all_unique_warnings_summed = {}
    for package in all_unique_warnings.keys():
        count = 0
        for warning in all_unique_warnings[package].keys():
            count += all_unique_warnings[package][warning]
        all_unique_warnings_summed[package] = count

    columns = [
      {
        "field": "package", # which is the field's name of data key 
        "title": "package", # display as the table header's name
        "sortable": True,
      },
      {
        "field": "total_warnings_count",
        "title": "total number of warnings",
        "sortable": True,
      },
      {
        "field": "unique_warnings_count",
        "title": "number of unique warnings",
        "sortable": True,
      },
      {
        "field": "severity_rating",
        "title": "overall severity score",
        "sortable": True,
      }
    ]

    data = []
    for package in all_severities.keys():
        entry = {"package": "<a href='/single_package?package=" + package + "'>" + package + "</a>"}
        entry['total_warnings_count'] = all_warnings[package]
        entry['unique_warnings_count'] = all_unique_warnings_summed[package]
        entry['severity_rating'] = all_severities[package]
        data.append(entry)

    #data = getDummyData('sum_warning_count')

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
        "title": "total number of warnings changed",
        "sortable": True,
      },
     {
        "field": "num_changes_unique",
        "title": "number of unique warnings changed",
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

    LOCs = get_LOC_by_warning(package, warning, severity)

    columns = [
      {
        "field": "line", # which is the field's name of data key 
        "title": "line with warning", # display as the table header's name
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
        print(loc)
        data.append({'line':loc[1], 'code':loc[0], 'filename':loc[2].split('$')[1]})

    return render_template("loc.html",
      data=data,
      columns=columns,
      title='Aura Borealis',
      package=package,
      warning=warning)

# display a comparison between two packages, two versions, or a package and a benchmark profile
# https://prismjs.com/#examples  <--- use this for hover over LOC TODO
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
        package1 = "boto__1_0"
        package2 = "requests__2_3"

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
        "title": "warning type",
        "sortable": True,
      },
    ]

    data = getComparisonDummyData([package1, package2])

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
    package = request.args.get('package')
    print(package)
    if package == None:
        package = 'requests'

    score = get_package_score(package)

    count_warnings = {}
    for severity in SEVERITIES:
        for warning_type in WARNING_TYPES:
             get_warnings_by_package(package, warning_type, severity, count_warnings)

    data = []
    for warning_type in WARNING_TYPES:
        entry = {}
        entry["warning_type"] = "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#" + warning_type.lower() + "' target='_blank'>" + warning_type + "</a>"
        for severity in SEVERITIES:
            if count_warnings[warning_type][severity] != 0:
                entry[severity] = '<a href="/loc?package=' + package + '&warning=' + warning_type + '&severity=' + severity + '" target="_blank">' + str(count_warnings[warning_type][severity]) + '</a>' 
            else:
                entry[severity] = 0
        data.append(entry)


    columns = [
     {
        "field": "warning_type",
        "title": "warning type",
        "sortable": True,
      },
      {
        "field": "critical", # which is the field's name of data key 
        "title": "critical", # display as the table header's name
        "sortable": True,
      },
      {
        "field": "severe",
        "title": "severe",
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
      score=score)

# #########################################################################################################
# MAIN
# #########################################################################################################

if __name__ == '__main__':
  app.run(host='0.0.0.0', debug=True)

