import sys, hashlib, vt, os, time, requests, json
from queue import Queue

#Constants
WAIT_TIME_SCAN=30
PROGRAM_USAGE_STR="python vt-sbs.py [ | -e {extensions} | -u | --unsafe-only | -f | --full-report (NOT IMPLEMENTED)] PATH_TO_DIR"

#Environment variables
VERBOSE = True
NO_JSON_DUMP=False

#Runtime global variables
scanQueue = Queue()
everyFileResult = list(dict())
client_api_key=open("vt_api_key.txt","r").read()
headers={
        "accept" : "application/json",
        "x-apikey" : client_api_key
    }


#Program data
__author__="Antonio M-B | aantoniomarinb@github.com"
__version__ = "0.1.3"
__maintainer__="Antonio M-B"
__status__=" 0.1 Development"
__ascii_art__= r'''
 /$$    /$$ /$$$$$$$$       /$$$$$$  /$$$$$$$   /$$$$$$ 
| $$   | $$|__  $$__/      /$$__  $$| $$__  $$ /$$__  $$
| $$   | $$   | $$        | $$  \__/| $$  \ $$| $$  \__/
|  $$ / $$/   | $$ /$$$$$$|  $$$$$$ | $$$$$$$ |  $$$$$$ 
 \  $$ $$/    | $$|______/ \____  $$| $$__  $$ \____  $$
  \  $$$/     | $$         /$$  \ $$| $$  \ $$ /$$  \ $$
   \  $/      | $$        |  $$$$$$/| $$$$$$$/|  $$$$$$/
    \_/       |__/         \______/ |_______/  \______/                                                        
'''

'''--------------------FILE SCANNING FUNCTIONS------------------'''

def getFilesToScan(rootDir : str, extension : str) -> list:

    candidateFiles=getAllFilesInDirHierarchy(rootDir)
    return filterFilesByExtension(candidateFiles, extension)

def getAllFilesInDirHierarchy(rootDir : str) -> list : #RETURN RELATIVE_PATH OF ALL FILES IN FOLDER HYERARCHY
    files_list = []
    for root, dirs, files in os.walk(rootDir):
        for file in files:
            full_path = os.path.join(root, file)
            files_list.append(full_path)
    return files_list


def filterFilesByExtension(candidateFiles_RELPATH: list, extensionstr: str) -> list:  # SHOULD BE CALLED ONCE

    # If no extension provided, return all candidate files
    if extensionstr == None or extensionstr.strip() == "":  return candidateFiles_RELPATH

    extensionset = set(extensionstr.split(","))  # Split input extensions
    extensionset = [extension.strip().removeprefix('.') for extension in
                    extensionset]  # Strip every extension and normalize format
    output = [file for file in candidateFiles_RELPATH if
              file.split(".")[-1] in extensionset]  # Return every file that matches with one of the extensions
    return output

'''--------------------- FILE ANALYSIS FUNCTIONS ------------------'''

#FETCH FILE ANALYSIS FROM VT
def getFileAnalysis(file_hash: str) ->int & dict | None:
    global headers
    analysis_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    try:
        response=requests.get(analysis_url,headers=headers)
        return response.status_code, response.json()

    #API ERROR HANDLING
    except Exception as e:
        print(e)


#SENDS FILE TO VT FOR SCANNING
def scanFile(file_path: str) -> int & str:#Puts analysis link into ScanQueue
    global scanQueue, headers
    try:
        if VERBOSE: print("SCANNING: " + file_path)
        with open(file_path, "rb") as f:
            response = requests.post("https://www.virustotal.com/api/v3/files", files={"file": f}, headers=headers)

        if(response.status_code == 200):
            scanQueue.put(response.json()['data']['links']['self'])
        return response.status_code, response.json()

    except Exception as e:
        print(e)

#TODO
def getQueuedScansResults():
    global scanQueue, headers
    while(not scanQueue.empty()):
        link = scanQueue.get()
        try: response = requests.get(link, headers=headers)
        except Exception as e: print(e); return None

        if(response.json()['data']['attributes']['status'] == "completed"):
            results=response.json()
            createAnalysisFile(results, "vt-sbs-0.2.py")
            code, results = getFileAnalysis(results["data"]["meta"]["sha256"])
            if(code==200):
                file_name=results["data"]["attributes"]["names"][0]
                print(f"Successfully scanned file: {file_name}")
                createAnalysisFile(results, file_name)
                printSummarizedReport(results)
                everyFileResult.append(results["data"]["attributes"]["last_analysis_stats"])
        else:
            scanQueue.put(link)
            time.sleep(1)

def fileWizard(file : str) -> None:

    hash=HashFileMD5(file)
    if VERBOSE: print("REQUESTING FILE ANALYSIS: " + file)
    code, results = getFileAnalysis(hash)

    if (code == 200):
        print(file + " : Scan retrieved successfully")
        createAnalysisFile(results, file)
        printSummarizedReport(results)
        everyFileResult.append(results["data"]["attributes"]["last_analysis_stats"])

    elif (code==404):
        print(file + " : Does not have valid previous analyses, sending it for scanning")
        request_status, response = scanFile(file)
        if (request_status == 200):  print("Sent successfully")
        else:   print("Could not be sent for scanning: ",response)

    else:
        print(file + " : Error code: " + str(code))

'''-----------------FILE FORMATTING FUNCTIONS---------'''

def createAnalysisFile(jsondump : dict, file_path : str):
    with open(f"{file_path}-{HashFileMD5(file_path)}.analysis.json", "w", encoding="utf-8") as json_file:
        json.dump(jsondump, json_file, indent=4)

def printSummarizedReport(jsondump : dict):
    print(f"Registered name: {jsondump["data"]["attributes"]["names"][0]}")
    print(f"Link: {jsondump['data']['links']["self"]}")
    print(f"Summary: {jsondump['data']['attributes']['last_analysis_stats']}")

'''-----------------HELPER FUNCTIONS------------------'''

def getUserVerification(files: list):
    # PREREQUISITES
    if (files == []):
        print("No files found in directory, aborting")
        exit(1)

    # SHOW FILES BY EXTENSION
    fileMap = {}
    print("The following files will be uploaded for verification: ")
    for f in files:
        extension = "." + f.split(".")[-1]
        fileMap.setdefault(extension, []).append(f)
    for key in fileMap.keys():
        print(key + ": ")
        for f in fileMap[key]:
            print('\t' + f)

    # ASK USER FOR FINAL VERIFICATION
    while (1):
        userVerification = input("\nWant to proceed? (yes/no) \n").lower()
        if (userVerification == "no" or userVerification == "n"):
            exit(1)
        elif (userVerification == "yes" or userVerification == "y"):
            return
        else:
            print("Unvalid option")


def argumentHandler():
    global DIRECTORY_PATH, extension, only_print_unsafe, full_report
    DIRECTORY_PATH = None
    extension = None
    only_print_unsafe = False
    full_report = False

    sys.argv.pop(0)  # Pop scripts name

    # if(sys.argv.__len__()==0): exit("Program usage: python vtbu.py [-e {extension} | other_arguments] PATH_TO_DIR")
    if (sys.argv.__len__() == 0):
        DIRECTORY_PATH, extension = LaunchSimpleTUI()
        return

    while (sys.argv.__len__() != 0):
        argument = sys.argv[0]

        # Is modifier?
        if argument.startswith("-") or argument.startswith("--"):

            if argument == "-e" or argument == "--extension":

                if (sys.argv.__len__() < 2):
                    exit("Argument -e must be followed by an extension, for example: -e .exe")

                extension = sys.argv[1]
                sys.argv.pop(0)

            elif argument == "-u" or argument == "--unsafe-only":
                only_print_unsafe = True
            elif argument == "-f" or argument == "--full-report":
                full_report = True
            else:
                exit("Invalid argument, : " + argument)

            sys.argv.pop(0)

        # If is not modifier, it is folder path
        else:
            DIRECTORY_PATH = sys.argv[0]
            if not os.path.isdir(DIRECTORY_PATH):
                exit("Invalid directory path: " + argument)

            # if DIRECTORY_PATH.endswith("/"):            # python vt-sbs myDir/ -> myDir
            # DIRECTORY_PATH=DIRECTORY_PATH[:-1]

            sys.argv.pop(0)
    if DIRECTORY_PATH == None:
        exit("Aborted: file path cant be None")


def HashFileMD5(file: str) -> str:
    # Source - https://stackoverflow.com/questions/22058048/hashing-a-file-in-python
    # Posted by Randall Hunt
    # Retrieved 2025-12-28, License - CC BY-SA 4.0
    # BUF_SIZE is totally arbitrary, change for your app!
    BUF_SIZE = 65536  # lets read stuff in 64kb chunks!

    md5 = hashlib.md5()

    with open(file, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            md5.update(data)
    return md5.hexdigest()


def LaunchSimpleTUI():
    DIRECTORY_PATH = input("Choose directory to fetch files from (if blank, will choose the current dir): ")
    if(DIRECTORY_PATH == ""):
        DIRECTORY_PATH = os.getcwd()
    print("Extensions to scan (leave blank to scan every extension)")
    print("F.E: .dll, .exe")
    extension = input()
    return DIRECTORY_PATH, extension


# FILE ANALYSIS HANDLERS
def ScanAndGetResults(files: list):
    global everyFileResult

    summarized_results = {
        "malicious_files": list(),
        "suspicious_files": list(),
        "undetected_files": list()
    }

    for file_path in files:
        everyFileResult.append({file_path, fileWizard(file_path)})
    getQueuedScansResults()

    for file_results in everyFileResult :
        if file_results[1]["malicious"] != 0: summarized_results["malicious_files"].append(file_results[0])
        elif file_results[1]["suspicious"] != 0: summarized_results["suspicious_files"].append(file_results[0])
        else: summarized_results["undetected_files"].append(file_results[0])

    print("Malicious: "+str(summarized_results["malicious_files"]))
    print("Suspicious: "+str(summarized_results["suspicious_files"]))
    print("Undetected: "+str(summarized_results["undetected_files"]))



######### MAIN #########
print(__ascii_art__)
argumentHandler()
files = getFilesToScan(DIRECTORY_PATH, extension)
getUserVerification(files)
ScanAndGetResults(files)
exit(0)