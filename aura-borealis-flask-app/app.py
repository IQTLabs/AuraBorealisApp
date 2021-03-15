from flask import Flask, render_template, request
from flask_datepicker import datepicker
import json
from es.elastic.api import connect
from search import PackageSearch
import os
SECRET_KEY = os.urandom(32)



conn = connect(host='192.168.68.9')
curs = conn.cursor()

# Package requests
curs.execute(
    #"select count(*) from aura_detections where package='request' and type='StringMatch'"
    "select count(*) from aura_detections where package='requests' and type='LeakingSecret'"
)
count_leakingsecret_requests = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='requests' and type='SuspiciousFile'"
)
count_suspiciousfile_requests = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='requests' and type='SQLInjection'"
)
count_sqlinjection_requests = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='requests' and type='SensitiveFile'"
)
count_sensitivefile_requests = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='requests' and type='SetupScript'"
)
count_setupscript_requests = [row for row in curs]

# network
curs.execute(
    "select count(*) from aura_detections where package='network' and type='LeakingSecret'"
)
count_leakingsecret_network = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='network' and type='SuspiciousFile'"
)
count_suspiciousfile_network = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='networks' and type='SQLInjection'"
)
count_sqlinjection_network = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='network' and type='SensitiveFile'"
)
count_sensitivefile_network = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='network' and type='SetupScript'"
)
count_setupscript_network = [row for row in curs]

# pycurl
curs.execute(
    "select count(*) from aura_detections where package='pycurl' and type='LeakingSecret'"
)
count_leakingsecret_pycurl = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='pycurl' and type='SuspiciousFile'"
)
count_suspiciousfile_pycurl = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='pycurl' and type='SQLInjection'"
)
count_sqlinjection_pycurl = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='pycurl' and type='SensitiveFile'"
)
count_sensitivefile_pycurl = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='pycurl' and type='SetupScript'"
)
count_setupscript_pycurl = [row for row in curs]

# pandas
curs.execute(
    "select count(*) from aura_detections where package='pandas' and type='LeakingSecret'"
)
count_leakingsecret_pandas = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='pandas' and type='SuspiciousFile'"
)
count_suspiciousfile_pandas = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='pandas' and type='SQLInjection'"
)
count_sqlinjection_pandas = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='pandas' and type='SensitiveFile'"
)
count_sensitivefile_pandas = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='pandas' and type='SetupScript'"
)
count_setupscript_pandas = [row for row in curs]

# boto
curs.execute(
    "select count(*) from aura_detections where package='boto' and type='LeakingSecret'"
)
count_leakingsecret_boto = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='boto' and type='SuspiciousFile'"
)
count_suspiciousfile_boto = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='boto' and type='SQLInjection'"
)
count_sqlinjection_boto = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='boto' and type='SensitiveFile'"
)
count_sensitivefile_boto = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='boto' and type='SetupScript'"
)
count_setupscript_boto = [row for row in curs]

# sqlint
curs.execute(
    "select count(*) from aura_detections where package='sqlint' and type='LeakingSecret'"
)
count_leakingsecret_sqlint = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='sqlint' and type='SuspiciousFile'"
)
count_suspiciousfile_sqlint = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='sqlint' and type='SQLInjection'"
)
count_sqlinjection_sqlint = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='sqlint' and type='SensitiveFile'"
)
count_sensitivefile_sqlint = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='sqlint' and type='SetupScript'"
)
count_setupscript_sqlint = [row for row in curs]

# ssh-python
curs.execute(
    "select count(*) from aura_detections where package='ssh-python' and type='LeakingSecret'"
)
count_leakingsecret_sshpython = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='ssh-python' and type='SuspiciousFile'"
)
count_suspiciousfile_sshpython = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='ssh-python' and type='SQLInjection'"
)
count_sqlinjection_sshpython = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='ssh-python' and type='SensitiveFile'"
)
count_sensitivefile_sshpython = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='ssh-python' and type='SetupScript'"
)
count_setupscript_sshpython = [row for row in curs]

# sqlmap
curs.execute(
    "select count(*) from aura_detections where package='sqlmap' and type='LeakingSecret'"
)
count_leakingsecret_sqlmap = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='sqlmap' and type='SuspiciousFile'"
)
count_suspiciousfile_sqlmap = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='sqlmap' and type='SQLInjection'"
)
count_sqlinjection_sqlmap = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='sqlmap' and type='SensitiveFile'"
)
count_sensitivefile_sqlmap = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='sqlmap' and type='SetupScript'"
)
count_setupscript_sqlmap = [row for row in curs]

# netlogger
curs.execute(
    "select count(*) from aura_detections where package='netlogger' and type='LeakingSecret'"
)
count_leakingsecret_netlogger = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='netlogger' and type='SuspiciousFile'"
)
count_suspiciousfile_netlogger = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='netlogger' and type='SQLInjection'"
)
count_sqlinjection_netlogger = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='netlogger' and type='SensitiveFile'"
)
count_sensitivefile_netlogger = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='netlogger' and type='SetupScript'"
)
count_setupscript_netlogger = [row for row in curs]

# streamlit

curs.execute(
    "select count(*) from aura_detections where package='streamlit' and type='LeakingSecret'"
)
count_leakingsecret_streamlit = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='streamlit' and type='SuspiciousFile'"
)
count_suspiciousfile_streamlit = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='streamlit' and type='SQLInjection'"
)
count_sqlinjection_streamlit = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='streamlit' and type='SensitiveFile'"
)
count_sensitivefile_streamlit = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='streamlit' and type='SetupScript'"
)
count_setupscript_streamlit = [row for row in curs]

# pillow

curs.execute(
    "select count(*) from aura_detections where package='pillow' and type='LeakingSecret'"
)
count_leakingsecret_pillow = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='pillow' and type='SuspiciousFile'"
)
count_suspiciousfile_pillow = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='pillow' and type='SQLInjection'"
)
count_sqlinjection_pillow = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='pillow' and type='SensitiveFile'"
)
count_sensitivefile_pillow = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='pillow' and type='SetupScript'"
)
count_setupscript_pillow = [row for row in curs]

# huggingface

curs.execute(
    "select count(*) from aura_detections where package='huggingface' and type='LeakingSecret'"
)
count_leakingsecret_huggingface = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='huggingface' and type='SuspiciousFile'"
)
count_suspiciousfile_huggingface = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='huggingface' and type='SQLInjection'"
)
count_sqlinjection_huggingface = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='huggingface' and type='SensitiveFile'"
)
count_sensitivefile_huggingface = [row for row in curs]

curs.execute(
    "select count(*) from aura_detections where package='huggingface' and type='SetupScript'"
)
count_setupscript_huggingface = [row for row in curs]
"""
A example for creating a Table that is sortable by its header
"""

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
datepicker(app)
data = [
        {
            "package": "<a href='/single_package?package=streamlit'>streamlit</a>",
            "leakingsecret": count_leakingsecret_streamlit[0],
            "suspiciousfile": count_suspiciousfile_streamlit[0],
            "sqlinjection": count_sqlinjection_streamlit[0],
            "sensitivefile": count_sensitivefile_streamlit[0],
            "setupscript": count_setupscript_streamlit[0]
        },
        {
            "package": "<a href='/single_package?package=pillow'>pillow</a>",
            "leakingsecret": count_leakingsecret_pillow[0],
            "suspiciousfile": count_suspiciousfile_pillow[0],
            "sqlinjection": count_sqlinjection_pillow[0],
            "sensitivefile": count_sensitivefile_pillow[0],
            "setupscript": count_setupscript_pillow[0]
        },
        {
            "package": "<a href='/single_package?package=huggingface'>huggingface</a>",
            "leakingsecret": count_leakingsecret_huggingface[0],
            "suspiciousfile": count_suspiciousfile_huggingface[0],
            "sqlinjection": count_sqlinjection_huggingface[0],
            "sensitivefile": count_sensitivefile_huggingface[0],
            "setupscript": count_setupscript_huggingface[0]
        },
        {
            "package": "<a href='/single_package?package=requests'>requests</a>",
            "leakingsecret": count_leakingsecret_requests[0],
            "suspiciousfile": count_suspiciousfile_requests[0],
            "sqlinjection": count_sqlinjection_requests[0],
            "sensitivefile": count_sensitivefile_requests[0],
            "setupscript": count_setupscript_requests[0]
        },
        {
            "package": "<a href='/single_package?package=network'>network</a>",
            "leakingsecret": count_leakingsecret_network[0],
            "suspiciousfile": count_suspiciousfile_network[0],
            "sqlinjection": count_sqlinjection_network[0],
            "sensitivefile": count_sensitivefile_network[0],
            "setupscript": count_setupscript_network[0]
        },
        {
            "package": "<a href='/single_package?package=pycurl'>pycurl</a>",
            "leakingsecret": count_leakingsecret_pycurl[0],
            "suspiciousfile": count_suspiciousfile_pycurl[0],
            "sqlinjection": count_sqlinjection_pycurl[0],
            "sensitivefile": count_sensitivefile_pycurl[0],
            "setupscript": count_setupscript_pycurl[0]
        },
        {
            "package": "<a href='/single_package?package=pandas'>pandas</a>",
            "leakingsecret": count_leakingsecret_pandas[0],
            "suspiciousfile": count_suspiciousfile_pandas[0],
            "sqlinjection": count_sqlinjection_pandas[0],
            "sensitivefile": count_sensitivefile_pandas[0],
            "setupscript": count_setupscript_pandas[0]
        },
        {
            "package": "<a href='/single_package?package=boto'>boto</a>",
            "leakingsecret": count_leakingsecret_boto[0],
            "suspiciousfile": count_suspiciousfile_boto[0],
            "sqlinjection": count_sqlinjection_boto[0],
            "sensitivefile": count_sensitivefile_boto[0],
            "setupscript": count_setupscript_boto[0]
        },
        {
            "package": "<a href='/single_package?package=sqlint'>sqlint</a>",
            "leakingsecret": count_leakingsecret_sqlint[0],
            "suspiciousfile": count_suspiciousfile_sqlint[0],
            "sqlinjection": count_sqlinjection_sqlint[0],
            "sensitivefile": count_sensitivefile_sqlint[0],
            "setupscript": count_setupscript_sqlint[0]
        },
        {
            "package": "<a href='/single_package?package=ssh-python'>ssh-python</a>",
            "leakingsecret": count_leakingsecret_sshpython[0],
            "suspiciousfile": count_suspiciousfile_sshpython[0],
            "sqlinjection": count_sqlinjection_sshpython[0],
            "sensitivefile": count_sensitivefile_sshpython[0],
            "setupscript": count_setupscript_sshpython[0]
        },
        {
            "package": "<a href='/single_package?package=sqlmap'>sqlmap</a>",
            "leakingsecret": count_leakingsecret_sqlmap[0],
            "suspiciousfile": count_suspiciousfile_sqlmap[0],
            "sqlinjection": count_sqlinjection_sqlmap[0],
            "sensitivefile": count_sensitivefile_sqlmap[0],
            "setupscript": count_setupscript_sqlmap[0]
        },
        {
            "package": "<a href='/single_package?package=netlogger'>netlogger</a>",
            "leakingsecret": count_leakingsecret_netlogger[0],
            "suspiciousfile": count_suspiciousfile_netlogger[0],
            "sqlinjection": count_sqlinjection_netlogger[0],
            "sensitivefile": count_sensitivefile_netlogger[0],
            "setupscript": count_setupscript_netlogger[0]
        }
]
'''
data = [{
  "name": "bootstrap-table",
  "commits": "10",
  "attention": "122",
  "uneven": "An extended Bootstrap table"
},
 {
  "name": "multiple-select",
  "commits": "288",
  "attention": "20",
  "uneven": "A jQuery plugin"
}, {
  "name": "Testing",
  "commits": "340",
  "attention": "20",
  "uneven": "For test"
}]
'''
# other column settings -> http://bootstrap-table.wenzhixin.net.cn/documentation/#column-options
columns = [
  {
    "field": "package", # which is the field's name of data key 
    "title": "package", # display as the table header's name
    "sortable": True,
  },
  {
    "field": "leakingsecret",
    "title": "LeakingSecret",
    "sortable": True,
  },
  {
    "field": "suspiciousfile",
    "title": "SuspiciousFile",
    "sortable": True,
  },
  {
    "field": "sqlinjection",
    "title": "SQLInjection",
    "sortable": True,
  },
  {
    "field": "sensitivefile",
    "title": "SensitiveFile",
    "sortable": True,
  },
  {
    "field": "setupscript",
    "title": "SetupScript",
    "sortable": True,
  }
]

#jdata=json.dumps(data)


@app.route('/')
def home():
    return render_template('./home.html')

@app.route('/about/')
def about():
    return render_template('about.html')

@app.route('/top_warnings/', methods=['GET', 'POST'])
def top_warnings():
    search = PackageSearch(request.form)
    if request.method == 'POST':
        return search_results(search)
    return render_template("top_warnings.html",
      data=data,
      columns=columns,
      title='Aura Borealis',
      form=search)

@app.route('/sum_warning_count/', methods=['GET', 'POST'])
def sum_warning_count():
    search = PackageSearch(request.form)
    if request.method == 'POST':
        return search_results(search)

    # dummy data
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

    data = [
            {"package": "<a href='/single_package?package=requests'>requests</a>","total_warnings_count": 23,"unique_warnings_count": 2, 'severity_rating':'neutral'},
            {"package": "<a href='/single_package?package=network'>network</a>","total_warnings_count": 0,"unique_warnings_count": 0, 'severity_rating':'good'},
            {"package": "<a href='/single_package?package=pycurl'>pycurl</a>","total_warnings_count": 0,"unique_warnings_count": 0, 'severity_rating':'good'},
            {"package": "<a href='/single_package?package=pandas'>pandas</a>","total_warnings_count": 1,"unique_warnings_count": 1, 'severity_rating':'bad'},
            {"package": "<a href='/single_package?package=boto'>boto</a>","total_warnings_count": 2,"unique_warnings_count": 1, 'severity_rating':'neutral'},
            {"package": "<a href='/single_package?package=sqlint'>sqlint</a>","total_warnings_count": 20,"unique_warnings_count": 13, 'severity_rating':'neutral'},
            {"package": "<a href='/single_package?package=ssh-python'>ssh-python</a>","total_warnings_count": 0,"unique_warnings_count": 0, 'severity_rating':'good'},
            {"package": "<a href='/single_package?package=sqlmap'>sqlmap</a>","total_warnings_count": 11,"unique_warnings_count": 9, 'severity_rating':'bad'},
            {"package": "<a href='/single_package?package=netlogger'>netlogger</a>","total_warnings_count": 0,"unique_warnings_count": 0, 'severity_rating':'neutral'},
    ]

    return render_template("sum_warning_count.html",
      data=data,
      columns=columns,
      title='Aura Borealis',
      form=search)

@app.route('/diff_dates/', methods=['GET', 'POST'])
def diff_dates():
    search = PackageSearch(request.form)
    if request.method == 'POST':
        return search_results(search)

    # dummy data
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

    data = [
            {"package": "<a href='/single_package?package=requests'>requests</a>","num_changes": 3,"num_changes_unique": 2, 'changes_score':'- bad'},
            {"package": "<a href='/single_package?package=network'>network</a>","num_changes": 0,"num_changes_unique": 0, 'changes_score':'none'},
            {"package": "<a href='/single_package?package=pycurl'>pycurl</a>","num_changes": 1,"num_changes_unique": 1, 'changes_score':'none'},
            {"package": "<a href='/single_package?package=pandas'>pandas</a>","num_changes": 1,"num_changes_unique": 1, 'changes_score':'+ good'},
            {"package": "<a href='/single_package?package=boto'>boto</a>","num_changes": 2,"num_changes_unique": 1, 'changes_score':'+ neutral'},
            {"package": "<a href='/single_package?package=sqlint'>sqlint</a>","num_changes": 20,"num_changes_unique": 1, 'changes_score':'none'},
            {"package": "<a href='/single_package?package=ssh-python'>ssh-python</a>","num_changes": 0,"num_changes_unique": 0, 'changes_score':'none'},
            {"package": "<a href='/single_package?package=sqlmap'>sqlmap</a>","num_changes": 11,"num_changes_unique": 9, 'changes_score':'- neutral'},
            {"package": "<a href='/single_package?package=netlogger'>netlogger</a>","num_changes": 0,"num_changes_unique": 0, 'changes_score':'none'},
    ]
    return render_template("diff_dates.html",
      data=data,
      columns=columns,
      title='Aura Borealis',
      form=search)

def getComparisonDummyData(packs):
    packs = sorted(packs)
    if packs[0] == "boto__1_0" and packs[1] == "requests__2_3":
        data = [
                {"package1": 'good',"package2": 'neutral',"warning_type": "OVERALL SEVERITY"},
                {"package1": 0,"package2": 1,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#leakingsecret'>LeakingSecret</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#functioncall'>FunctionCall</a>"},
                {"package1": 1,"package2": 1,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#moduleimport'>ModuleImport</a>"},
                {"package1": 0,"package2": 13,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#base64blob'>Base64Blob</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#binwalk'>Binwalk</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#cryptokeygeneration'>CryptoKeyGeneration</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#dataprocessing'>DataProcessing</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#detection'>Detection</a>"},
                {"package1": 1,"package2": 2,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#invalidrequirement'>InvalidRequirement</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#malformedxml'>MalformedXML</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#archiveanomaly'>ArchiveAnomaly</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#suspiciousarchiveentry'>SuspiciousArchiveEntry</a>"},
                {"package1": 0,"package2": 1,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#outdatedpackage'>OutdatedPackage</a>"},
                {"package1": 0,"package2": 1,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#suspiciousfile'>SuspiciousFile</a>"},
                {"package1": 0,"package2": 1,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#unpinnedpackage'>UnpinnedPackage</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#sqlinjection'>SQLInjection</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#taintanomaly'>TaintAnomaly</a>"},
                {"package1": 0,"package2": 1,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#sensitivefile'>SensitiveFile</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#setupscript'>SetupScript</a>"},
                {"package1": 0,"package2": 1,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#wheel'>Wheel</a>"},
                {"package1": 0,"package2": 5,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#stringmatch'>StringMatch</a>"},
                {"package1": 1,"package2": 1,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#file-stats'>File stats</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#yaramatch'>YaraMatch</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#yaraerror'>YaraError</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#astanalysiserror'>ASTAnalysisError</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#astparseerror'>ASTParseError</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#misc'>Misc</a>"},
        ]

    elif 'pandas' in packs[1] and 'BENCHMARK' in packs[0]:
        data = [
                {"package1": 'good',"package2": 'neutral',"warning_type": "OVERALL SEVERITY"},
                {"package1": 0,"package2": 1,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#leakingsecret'>LeakingSecret</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#functioncall'>FunctionCall</a>"},
                {"package1": 1,"package2": 1,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#moduleimport'>ModuleImport</a>"},
                {"package1": 0,"package2": 13,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#base64blob'>Base64Blob</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#binwalk'>Binwalk</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#cryptokeygeneration'>CryptoKeyGeneration</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#dataprocessing'>DataProcessing</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#detection'>Detection</a>"},
                {"package1": 1,"package2": 2,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#invalidrequirement'>InvalidRequirement</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#malformedxml'>MalformedXML</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#archiveanomaly'>ArchiveAnomaly</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#suspiciousarchiveentry'>SuspiciousArchiveEntry</a>"},
                {"package1": 0,"package2": 1,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#outdatedpackage'>OutdatedPackage</a>"},
                {"package1": 0,"package2": 1,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#suspiciousfile'>SuspiciousFile</a>"},
                {"package1": 0,"package2": 1,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#unpinnedpackage'>UnpinnedPackage</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#sqlinjection'>SQLInjection</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#taintanomaly'>TaintAnomaly</a>"},
                {"package1": 0,"package2": 1,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#sensitivefile'>SensitiveFile</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#setupscript'>SetupScript</a>"},
                {"package1": 0,"package2": 1,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#wheel'>Wheel</a>"},
                {"package1": 0,"package2": 5,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#stringmatch'>StringMatch</a>"},
                {"package1": 1,"package2": 1,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#file-stats'>File stats</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#yaramatch'>YaraMatch</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#yaraerror'>YaraError</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#astanalysiserror'>ASTAnalysisError</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#astparseerror'>ASTParseError</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#misc'>Misc</a>"},
        ]
    else:
        data = [
                {"package1": 'bad',"package2": 'neutral',"warning_type": "OVERALL SEVERITY"},
                {"package1": 11,"package2": 1,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#leakingsecret'>LeakingSecret</a>"},
                {"package1": 2,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#functioncall'>FunctionCall</a>"},
                {"package1": 1,"package2": 1,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#moduleimport'>ModuleImport</a>"},
                {"package1": 0,"package2": 3,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#base64blob'>Base64Blob</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#binwalk'>Binwalk</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#cryptokeygeneration'>CryptoKeyGeneration</a>"},
                {"package1": 4,"package2": 2,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#dataprocessing'>DataProcessing</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#detection'>Detection</a>"},
                {"package1": 1,"package2": 2,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#invalidrequirement'>InvalidRequirement</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#malformedxml'>MalformedXML</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#archiveanomaly'>ArchiveAnomaly</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#suspiciousarchiveentry'>SuspiciousArchiveEntry</a>"},
                {"package1": 0,"package2": 1,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#outdatedpackage'>OutdatedPackage</a>"},
                {"package1": 0,"package2": 1,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#suspiciousfile'>SuspiciousFile</a>"},
                {"package1": 0,"package2": 1,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#unpinnedpackage'>UnpinnedPackage</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#sqlinjection'>SQLInjection</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#taintanomaly'>TaintAnomaly</a>"},
                {"package1": 0,"package2": 1,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#sensitivefile'>SensitiveFile</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#setupscript'>SetupScript</a>"},
                {"package1": 0,"package2": 1,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#wheel'>Wheel</a>"},
                {"package1": 0,"package2": 5,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#stringmatch'>StringMatch</a>"},
                {"package1": 1,"package2": 1,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#file-stats'>File stats</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#yaramatch'>YaraMatch</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#yaraerror'>YaraError</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#astanalysiserror'>ASTAnalysisError</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#astparseerror'>ASTParseError</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#misc'>Misc</a>"},
        ]
    return data

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

    # dummy data
    data = getComparisonDummyData([package1, package2])

    return render_template("comparison.html",
      data=data,
      columns=columns,
      title='Aura Borealis',
      form=search,
      package1=package1,
      package2=package2)



@app.route('/single_package/', methods=['GET', 'POST'])
def single_package():
    search = PackageSearch(request.form)
    if request.method == 'POST':
        return search_results(search)

    package = request.args.get('package')
    print(package)
    # dummy data
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

    data = [
            {"unknown": 0,"low": 0,"moderate": 1,"severe": 0,"critical": 5,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#leakingsecret'>LeakingSecret</a>"},
            {"unknown": 0,"low": 0,"moderate": 0,"severe": 0,"critical": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#functioncall'>FunctionCall</a>"},
            {"unknown": 0,"low": 0,"moderate": 0,"severe": 0,"critical": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#moduleimport'>ModuleImport</a>"},
            {"unknown": 1,"low": 0,"moderate": 0,"severe": 0,"critical": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#base64blob'>Base64Blob</a>"},
            {"unknown": 1,"low": 0,"moderate": 0,"severe": 0,"critical": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#binwalk'>Binwalk</a>"},
            {"unknown": 0,"low": 0,"moderate": 0,"severe": 0,"critical": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#cryptokeygeneration'>CryptoKeyGeneration</a>"},
            {"unknown": 1,"low": 0,"moderate": 0,"severe": 0,"critical": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#dataprocessing'>DataProcessing</a>"},
            {"unknown": 0,"low": 0,"moderate": 0,"severe": 0,"critical": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#detection'>Detection</a>"},
            {"unknown": 0,"low": 1,"moderate": 3,"severe": 0,"critical": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#invalidrequirement'>InvalidRequirement</a>"},
            {"unknown": 0,"low": 0,"moderate": 0,"severe": 1,"critical": 2,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#malformedxml'>MalformedXML</a>"},
            {"unknown": 0,"low": 0,"moderate": 0,"severe": 0,"critical": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#archiveanomaly'>ArchiveAnomaly</a>"},
            {"unknown": 0,"low": 0,"moderate": 0,"severe": 0,"critical": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#suspiciousarchiveentry'>SuspiciousArchiveEntry</a>"},
            {"unknown": 0,"low": 0,"moderate": 0,"severe": 0,"critical": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#outdatedpackage'>OutdatedPackage</a>"},
            {"unknown": 0,"low": 0,"moderate": 0,"severe": 2,"critical": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#suspiciousfile'>SuspiciousFile</a>"},
            {"unknown": 11,"low": 0,"moderate": 0,"severe": 0,"critical": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#unpinnedpackage'>UnpinnedPackage</a>"},
            {"unknown": 0,"low": 0,"moderate": 0,"severe": 0,"critical": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#sqlinjection'>SQLInjection</a>"},
            {"unknown": 0,"low": 2,"moderate": 2,"severe": 0,"critical": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#taintanomaly'>TaintAnomaly</a>"},
            {"unknown": 0,"low": 0,"moderate": 0,"severe": 0,"critical": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#sensitivefile'>SensitiveFile</a>"},
            {"unknown": 0,"low": 0,"moderate": 0,"severe": 0,"critical": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#setupscript'>SetupScript</a>"},
            {"unknown": 3,"low": 0,"moderate": 0,"severe": 0,"critical": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#wheel'>Wheel</a>"},
            {"unknown": 0,"low": 0,"moderate": 0,"severe": 0,"critical": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#stringmatch'>StringMatch</a>"},
            {"unknown": 0,"low": 5,"moderate": 0,"severe": 0,"critical": 3,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#file-stats'>File stats</a>"},
            {"unknown": 0,"low": 0,"moderate": 0,"severe": 2,"critical": 1,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#yaramatch'>YaraMatch</a>"},
            {"unknown": 0,"low": 0,"moderate": 1,"severe": 1,"critical": 1,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#yaraerror'>YaraError</a>"},
            {"unknown": 0,"low": 0,"moderate": 0,"severe": 0,"critical": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#astanalysiserror'>ASTAnalysisError</a>"},
            {"unknown": 2,"low": 0,"moderate": 0,"severe": 0,"critical": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#astparseerror'>ASTParseError</a>"},
            {"unknown": 0,"low": 0,"moderate": 0,"severe": 0,"critical": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#misc'>Misc</a>"},


    ]
    return render_template("single_package.html",
      data=data,
      columns=columns,
      title='Aura Borealis',
      form=search,
      package=package)


"""
@app.route('/', methods=['GET', 'POST'])
def index():
    search = PackageSearch(request.form)
    if request.method == 'POST':
        return search_results(search)
    return render_template("table.html",
      data=data,
      columns=columns,
      title='Aura Borealis',
      form=search)

#endpoint for search
@app.route('/results')
def search_results(search):
    results = []
    search_string = search.data['package']
    print(search_string)
    results = curs.execute(
    "select count(*) as number, type from aura_detections where package=%s and type in ('SetupScript', 'SensitiveFile', 'LeakingSecret', 'SuspiciousFile', 'SQLInjection')", (search_string)
)

    # display results
    return render_template('results.html', results=results)
'''
@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == "POST":
        package = request.form['package']
        # search by author or book
        #cursor.execute("SELECT name, author from Book WHERE name 
        #                LIKE %s OR author LIKE %s", (book, book))
        #conn.commit()
        #data = cursor.fetchall()
        data = curs.execute(
    "select count(*) as number, type from aura_detections where package=%s and type in ('SetupScript', 'SensitiveFile', 'LeakingSecret', 'SuspiciousFile', 'SQLInjection')", (package)
)
        # all in the search box will return all the tuples
        #if len(data) == 0 and book == 'all': 
        #    cursor.execute("SELECT name, author from Book")
        #    conn.commit()
        #    data = cursor.fetchall()
        return render_template('table.html', data=data)
    return render_template('table.html')
'''
"""
if __name__ == '__main__':
	#print jdata
  app.run(host='0.0.0.0', debug=True)
