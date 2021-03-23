from flask import Flask, render_template, request
from flask_datepicker import datepicker
import json

from search import PackageSearch
import os
SECRET_KEY = os.urandom(32)

from live_data import connect_and_load
from dummy_data import *


# hand select certain packages and warnings for demo purposes
PACKAGES = ['requests', 'network', 'pycurl', 'pandas', 'boto', 'sqlint', 'ssh-python', 'sqlmap', 
        'netlogger', 'streamlit', 'pillow', 'huggingface']
WARNING_TYPES = ['LeakingSecret', 'SuspiciousFile', 'SQLInjection', 'SensitiveFile', 'SetupScript']


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
    warnings = connect_and_load(PACKAGES, WARNING_TYPES)
    data = []
    for package in PACKAGES:
        entry = {}
        entry['package'] = "<a href='/single_package?package=" + package +"'>" + package +"</a>"
        for warning in warnings[package].keys():
            entry[warning] = warnings[package][warning][0]
        data.append(entry)

    # other column settings -> http://bootstrap-table.wenzhixin.net.cn/documentation/#column-options
    columns = []
    columns.append({"field": "package", "title": "package", "sortable": True,})
    for warning in WARNING_TYPES:
        columns.append({"field": warning.lower(), "title": warning, "sortable": True,})

    search = PackageSearch(request.form)
    if request.method == 'POST':
        return search_results(search)
    return render_template("top_warnings.html",
      data=data,
      columns=columns,
      title='Aura Borealis',
      form=search)

# display all the packages by their overall severity scores, total warnings, and total unique warnings
@app.route('/sum_warning_count/', methods=['GET', 'POST'])
def sum_warning_count():
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

    data = getDummyData('sum_warning_count')

    return render_template("sum_warning_count.html",
      data=data,
      columns=columns,
      title='Aura Borealis',
      form=search)

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

    LOCs = getLOCDummyData(package, warning, severity)

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
        data.append({'line':loc[0], 'code':loc[2], 'filename':loc[1]})

    return render_template("loc.html",
      data=data,
      columns=columns,
      title='Aura Borealis',
      form=search,
      package=package,
      warning=warning)

# display a comparison between two packages, two versions, or a package and a benchmark profile
# https://prismjs.com/#examples  <--- use this for hover over LOC TODO
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
    search = PackageSearch(request.form)
    if request.method == 'POST':
        return search_results(search)

    package = request.args.get('package')
    print(package)
    if package == None:
        package = 'requests__2_3'

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

    data = getDummyData('single_package', package)

    return render_template("single_package.html",
      data=data,
      columns=columns,
      title='Aura Borealis',
      form=search,
      package=package)

# #########################################################################################################
# MAIN
# #########################################################################################################

if __name__ == '__main__':
  app.run(host='0.0.0.0', debug=True)

