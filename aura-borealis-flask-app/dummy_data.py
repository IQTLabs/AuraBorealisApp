"""
This temporary file loads a bunch of dummy data for demo purposes

"""

sum_warning_count_data = [
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

diff_dates_data = [
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

dummyJSONs = {
        'boto__1_0': [
            {
              "score": 0,
              "type": "ModuleImport",
              "severity": "unknown",
              "extra": {
                "name": "binascii"
              },
              "line": "import binascii",
              "line_no": 1,
              "signature": "module_import#binascii#/mnt/pypi_mirror/packages/80/3b/9e2fa0d13c860b0e91c6b40fc98050bf3ecbb02ede66324b9f6a7ee91b5d/shellcodepatterns-0.1.tar.gz$shellcodepatterns-0.1/shellcodepatterns/__init__.py",
              "message": "Module 'binascii' import in a source code",
              "location": "/mnt/pypi_mirror/packages/80/3b/9e2fa0d13c860b0e91c6b40fc98050bf3ecbb02ede66324b9f6a7ee91b5d/shellcodepatterns-0.1.tar.gz$shellcodepatterns-0.1/shellcodepatterns/__init__.py"
            },
            {
              "score": 0,
              "type": "Base64Blob",
              "severity": "unknown",
              "tags": [
                "base64"
              ],
              "extra": {
                "base64_decoded": "https://www.tiktok.com/api/user/detail/"  
              },
              "line": "helper = base64.b64decode(\"aHR0cHM6Ly93d3cudGlrdG9rLmNvbS9hcGkvdXNlci9kZXRhaWwv\").decode()",
              "line_no": 11,
              "signature": "data_finder#base64_blob#-119572759001070983#-2548831473978034482",
              "message": "Base64 data blob found",
              "location": "/mnt/pypi_mirror/packages/7f/e3/46ed3fa11eb08ca42e88ef7f26567f317778c717ebace5e4c021b1dd1eef/tiky-1.0.6.tar.gz$tiky-1.0.6/tiky.py"
            },
            {
              "score": 100,
              "type": "CryptoKeyGeneration",
              "severity": "critical",
              "extra": {
                "function": "Crypto.PublicKey.RSA.generate",
                "key_type": "rsa",
                "key_size": 1024
              },
              "signature": "crypto#gen_key#/mnt/pypi_mirror/packages/33/2f/ff513daa5da0bd81aac42650a377279547deebf79cfbe58868f0da179fe8/chval-0.6.7.tar.gz$chval-0.6.7/chval_core/crypto.py#45",
              "message": "Generation of cryptography key detected",
              "location": "/mnt/pypi_mirror/packages/33/2f/ff513daa5da0bd81aac42650a377279547deebf79cfbe58868f0da179fe8/chval-0.6.7.tar.gz$chval-0.6.7/chval_core/crypto.py"
            }
        ], 
        'requests__2_3': [
            {
              "score": 0,
              "type": "Detection",
              "severity": "unknown",
              "extra": {
                "type": "high_entropy_string",
                "entropy": 5.832890014164737,
                "string": "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
              },
              "line": "chars = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'",
              "line_no": 10,
              "signature": "misc#high_entropy#/mnt/pypi_mirror/packages/2f/ee/6ad696ef6e59d46b26def2fe92ef17519047b9f24dc1443a84a9fa8ff85d/django_markdown_messaging-0.1.0-py3-none-any.whl$django_markdown_messaging/models.py#10",
              "message": "A string with high shanon entropy was found",
              "location": "/mnt/pypi_mirror/packages/2f/ee/6ad696ef6e59d46b26def2fe92ef17519047b9f24dc1443a84a9fa8ff85d/django_markdown_messaging-0.1.0-py3-none-any.whl$django_markdown_messaging/models.py"
            },
            {
              "score": 0,
              "type": "InvalidRequirement",
              "severity": "unknown",
              "tags": [
                "cant_parse",
                "invalid_requirement"
              ],
              "extra": {
                "reason": "cant_parse",
                "line": "-r install.txt",
                "line_no": 1,
                "exc_message": "Parse error at \"'-r insta'\": Expected W:(abcd...)",
                "exc_type": "InvalidRequirement"
              },
              "signature": "req_invalid#/mnt/pypi_mirror/packages/e0/fc/bacea406af04cfbb6ae49ef9716ee8f696cbf0b4df37443fdf2fabcda15b/wagtailleafletwidget-1.0.1.tar.gz$wagtailleafletwidget-1.0.1/requirements/tests.txt/1",
              "message": "Could not parse the requirement for analysis",
              "location": "/mnt/pypi_mirror/packages/e0/fc/bacea406af04cfbb6ae49ef9716ee8f696cbf0b4df37443fdf2fabcda15b/wagtailleafletwidget-1.0.1.tar.gz$wagtailleafletwidget-1.0.1/requirements/tests.txt"
            },
            {
              "score": 0,
              "type": "LeakingSecret",
              "severity": "critical",
              "tags": [
                "test_code"
              ],
              "extra": {
                "name": "Attribute(Call(Container(name='User', pointer=Import(names={'User': 'registration.ormmanager.tests.samodel.User', 'Group': 'registration.ormmanager.tests.samodel.Group', 'users_table': 'registration.ormmanager.tests.samodel.users_table', 'groups_table': 'registration.ormmanager.tests.samodel.groups_table', 'user_group_table': 'registration.ormmanager.tests.samodel.user_group_table', 'metadata': 'registration.ormmanager.tests.samodel.metadata'})))() . 'password')",
                "secret": "hammertime",
                "extra": {
                  "type": "variable"
                }
              },
              "line": "u2.password='hammertime'",
              "line_no": 31,
              "signature": "leaking_secret#/mnt/pypi_mirror/packages/83/6f/c603de0b686d9e89b58b2bfc5875299955a48c5e423b8885c1c51a0b2c46/registration-0.50-py2.5.egg$registration/ormmanager/tests/testsa.py#31",
              "message": "Possible sensitive leaking secret",
              "location": "/mnt/pypi_mirror/packages/83/6f/c603de0b686d9e89b58b2bfc5875299955a48c5e423b8885c1c51a0b2c46/registration-0.50-py2.5.egg$registration/ormmanager/tests/testsa.py"
            },
            {
              "score": 0,
              "type": "LeakingSecret",
              "severity": "critical",
              "tags": [
                "test_code"
              ],
              "extra": {
                "name": "Attribute(Call(Container(name='User', pointer=Import(names={'User': 'registration.ormmanager.tests.samodel.User', 'Group': 'registration.ormmanager.tests.samodel.Group', 'users_table': 'registration.ormmanager.tests.samodel.users_table', 'groups_table': 'registration.ormmanager.tests.samodel.groups_table', 'user_group_table': 'registration.ormmanager.tests.samodel.user_group_table', 'metadata': 'registration.ormmanager.tests.samodel.metadata'})))() . 'password')",
                "secret": "hammertime",
                "extra": {
                  "type": "variable"
                }
              },
              "line": "u2.password='passy'",
              "line_no": 23,
              "signature": "leaking_secret#/mnt/pypi_mirror/packages/83/6f/c603de0b686d9e89b58b2bfc5875299955a48c5e423b8885c1c51a0b2c46/registration-0.50-py2.5.egg$registration/ormmanager/tests/testsa.py#31",
              "message": "Possible sensitive leaking secret",
              "location": "/mnt/pypi_mirror/packages/83/6f/c603de0b686d9e89b58b2bfc5875299955a48c5e423b8885c1c51a0b2c46/registration-0.50-py2.5.egg$registration/ormmanager/tests/testsa.py"
            },
            {
              "score": 0,
              "type": "LeakingSecret",
              "severity": "critical",
              "tags": [
                "test_code"
              ],
              "extra": {
                "name": "Attribute(Call(Container(name='User', pointer=Import(names={'User': 'registration.ormmanager.tests.samodel.User', 'Group': 'registration.ormmanager.tests.samodel.Group', 'users_table': 'registration.ormmanager.tests.samodel.users_table', 'groups_table': 'registration.ormmanager.tests.samodel.groups_table', 'user_group_table': 'registration.ormmanager.tests.samodel.user_group_table', 'metadata': 'registration.ormmanager.tests.samodel.metadata'})))() . 'password')",
                "secret": "hammertime",
                "extra": {
                  "type": "variable"
                }
              },
              "line": "u2.password='password123'",
              "line_no": 6523,
              "signature": "leaking_secret#/mnt/pypi_mirror/packages/83/6f/c603de0b686d9e89b58b2bfc5875299955a48c5e423b8885c1c51a0b2c46/registration-0.50-py2.5.egg$registration/ormmanager/tests/testsa.py#31",
              "message": "Possible sensitive leaking secret",
              "location": "/mnt/pypi_mirror/packages/83/6f/c603de0b686d9e89b58b2bfc5875299955a48c5e423b8885c1c51a0b2c46/registration-0.50-py2.5.egg$registration/ormmanager/tests/testsa.py"
            },
            {
              "score": 0,
              "type": "LeakingSecret",
              "severity": "moderate",
              "tags": [
                "test_code"
              ],
              "extra": {
                "name": "Attribute(Call(Container(name='User', pointer=Import(names={'User': 'registration.ormmanager.tests.samodel.User', 'Group': 'registration.ormmanager.tests.samodel.Group', 'users_table': 'registration.ormmanager.tests.samodel.users_table', 'groups_table': 'registration.ormmanager.tests.samodel.groups_table', 'user_group_table': 'registration.ormmanager.tests.samodel.user_group_table', 'metadata': 'registration.ormmanager.tests.samodel.metadata'})))() . 'password')",
                "secret": "hammertime",
                "extra": {
                  "type": "variable"
                }
              },
              "line": "u2.password='hammertime2'",
              "line_no": 11,
              "signature": "leaking_secret#/mnt/pypi_mirror/packages/83/6f/c603de0b686d9e89b58b2bfc5875299955a48c5e423b8885c1c51a0b2c46/registration-0.50-py2.5.egg$registration/ormmanager/tests/testsa.py#31",
              "message": "Possible sensitive leaking secret",
              "location": "/mnt/pypi_mirror/packages/83/6f/c603de0b686d9e89b58b2bfc5875299955a48c5e423b8885c1c51a0b2c46/registration-0.50-py2.5.egg$registration/ormmanager/tests/testsa.py"
            }
        ]
    }

def getSinglePackageDummyData(package):
    single_package_data = [
                {"unknown": 0,"low": 0,"moderate": '<a href="/loc?package=' + package + '&warning=leakingsecret&severity=moderate">1</a>',"severe": 0,"critical": '<a href="/loc?package=' + package + '&warning=leakingsecret&severity=critical">3</a>',"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#leakingsecret'>LeakingSecret</a>"},
                {"unknown": 0,"low": 0,"moderate": 0,"severe": 0,"critical": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#functioncall'>FunctionCall</a>"},
                {"unknown": 0,"low": 0,"moderate": 0,"severe": 0,"critical": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#moduleimport'>ModuleImport</a>"},
                {"unknown": '<a href="/loc?package=' + package + '&warning=base64blob&severity=unknown">1</a>',"low": 0,"moderate": 0,"severe": 0,"critical": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#base64blob'>Base64Blob</a>"},
                {"unknown": '<a href="/loc?package=' + package + '&warning=binwalk&severity=unknown">1</a>',"low": 0,"moderate": 0,"severe": 0,"critical": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#binwalk'>Binwalk</a>"},
                {"unknown": 0,"low": 0,"moderate": 0,"severe": 0,"critical": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#cryptokeygeneration'>CryptoKeyGeneration</a>"},
                {"unknown": '<a href="/loc?package=' + package + '&warning=dataprocessing&severity=unknown">1</a>',"low": 0,"moderate": 0,"severe": 0,"critical": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#dataprocessing'>DataProcessing</a>"},
                {"unknown": 0,"low": 0,"moderate": 0,"severe": 0,"critical": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#detection'>Detection</a>"},
                {"unknown": 0,"low": '<a href="/loc?package=' + package + '&warning=invalidrequirement&severity=low">1</a>',"moderate": '<a href="/loc?package=' + package + '&warning=invalidrequirement&severity=moderate">3</a>',"severe": 0,"critical": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#invalidrequirement'>InvalidRequirement</a>"},
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
    return single_package_data

def getLOCDummyData(package, warning_type, critical=None):
    
    dummyJSONs = getDummyData('dummyJSONs')
    results = []
    if package in dummyJSONs.keys():
        print('found', package)
        for warning in dummyJSONs[package]:
            if warning['type'].lower() == warning_type:
                if critical == None or critical == warning['severity']:
                    results.append([warning['line_no'], warning["location"], warning["line"]])
    return results

def getComparisonDummyData(packs):
    packs = sorted(packs)
    if packs[0] == "boto__1_0" and packs[1] == "requests__2_3":
        data = [
                {"package1": 'good',"package2": 'neutral',"warning_type": "OVERALL SEVERITY"},
                {"package1": 0,"package2": '<a href="/loc?package=' + packs[1] + '&warning=leakingsecret">1</a>',"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#leakingsecret'>LeakingSecret</a>"},
                {"package1": 0,"package2": 0,"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#functioncall'>FunctionCall</a>"},
                {"package1": '<a href="/loc?package=' + packs[0] + '&warning=moduleimport">1</a>',"package2": '<a href="/loc?package=' + packs[1] + '&warning=moduleimport">1</a>',"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#moduleimport'>ModuleImport</a>"},
                {"package1": 0,"package2": '<a href="/loc?package=' + packs[1] + '&warning=base4blob">13</a>',"warning_type": "<a href='https://docs.aura.sourcecode.ai/cookbook/misc/detections.html#base64blob'>Base64Blob</a>"},
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

def getDummyData(label, package=None):
    if label == 'sum_warning_count':
        return sum_warning_count_data
    elif label == 'diff_dates':
        return diff_dates_data
    elif label == 'dummyJSONs':
        return dummyJSONs
    elif label == 'single_package':
        return getSinglePackageDummyData(package)






