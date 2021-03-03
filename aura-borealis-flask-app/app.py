from flask import Flask, render_template, request
import json
from es.elastic.api import connect
from search import PackageSearch
import os
SECRET_KEY = os.urandom(32)

conn = connect(host='localhost')
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
"""
A example for creating a Table that is sortable by its header
"""

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
data = [
        {
            "package": "requests",
            "leakingsecret": count_leakingsecret_requests[0],
            "suspiciousfile": count_suspiciousfile_requests[0],
            "sqlinjection": count_sqlinjection_requests[0],
            "sensitivefile": count_sensitivefile_requests[0],
            "setupscript": count_setupscript_requests[0]
        },
        {
            "package": "network",
            "leakingsecret": count_leakingsecret_network[0],
            "suspiciousfile": count_suspiciousfile_network[0],
            "sqlinjection": count_sqlinjection_network[0],
            "sensitivefile": count_sensitivefile_network[0],
            "setupscript": count_setupscript_network[0]
        },
        {
            "package": "pycurl",
            "leakingsecret": count_leakingsecret_pycurl[0],
            "suspiciousfile": count_suspiciousfile_pycurl[0],
            "sqlinjection": count_sqlinjection_pycurl[0],
            "sensitivefile": count_sensitivefile_pycurl[0],
            "setupscript": count_setupscript_pycurl[0]
        },
        {
            "package": "pandas",
            "leakingsecret": count_leakingsecret_pandas[0],
            "suspiciousfile": count_suspiciousfile_pandas[0],
            "sqlinjection": count_sqlinjection_pandas[0],
            "sensitivefile": count_sensitivefile_pandas[0],
            "setupscript": count_setupscript_pandas[0]
        },
        {
            "package": "boto",
            "leakingsecret": count_leakingsecret_boto[0],
            "suspiciousfile": count_suspiciousfile_boto[0],
            "sqlinjection": count_sqlinjection_boto[0],
            "sensitivefile": count_sensitivefile_boto[0],
            "setupscript": count_setupscript_boto[0]
        },
        {
            "package": "sqlint",
            "leakingsecret": count_leakingsecret_sqlint[0],
            "suspiciousfile": count_suspiciousfile_sqlint[0],
            "sqlinjection": count_sqlinjection_sqlint[0],
            "sensitivefile": count_sensitivefile_sqlint[0],
            "setupscript": count_setupscript_sqlint[0]
        },
        {
            "package": "ssh-python",
            "leakingsecret": count_leakingsecret_sshpython[0],
            "suspiciousfile": count_suspiciousfile_sshpython[0],
            "sqlinjection": count_sqlinjection_sshpython[0],
            "sensitivefile": count_sensitivefile_sshpython[0],
            "setupscript": count_setupscript_sshpython[0]
        },
        {
            "package": "sqlmap",
            "leakingsecret": count_leakingsecret_sqlmap[0],
            "suspiciousfile": count_suspiciousfile_sqlmap[0],
            "sqlinjection": count_sqlinjection_sqlmap[0],
            "sensitivefile": count_sensitivefile_sqlmap[0],
            "setupscript": count_setupscript_sqlmap[0]
        },
        {
            "package": "netlogger",
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

if __name__ == '__main__':
	#print jdata
  app.run(host='0.0.0.0', debug=True)
