"""
This temporary file loads a bunch of dummy data for demo purposes

"""

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

'''
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
'''

def getDummyData(label, package=None):
    if label == 'diff_dates':
        return diff_dates_data






