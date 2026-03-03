import sys, hashlib, os, time, requests, json, datetime, threading
from queue import Queue

#Constants
API_SCAN_REQUESTS_PER_MINUTE=4
QUEUE_RETRY_DELAY=2
PROGRAM_USAGE_STR="python vt-sbs.py [ | -e {extensions} | -u | --unsafe-only | -f | --full-report (NOT IMPLEMENTED)] PATH_TO_DIR"

#Environment variables
VERBOSE = True
NO_JSON_DUMP=False
CHECK_QUOTA=True


#Runtime global variables
finished_requesting_scans=False
analysis_results_queue = Queue()
files_need_scanning_queue = Queue()
path_and_link_to_requested_analysis_queue = Queue()


#Program data
__author__="Antonio M-B | antoniomarinb@github.com"
__program_name__="vt-bulk.0.3"
__version__ = "0.3"
__maintainer__="Antonio M-B"
__status__=" 0.3 Development"
__ascii_art__= r'''
 /$$    /$$ /$$$$$$$$      /$$$$$$$  /$$   /$$ /$$       /$$   /$$      
| $$   | $$|__  $$__/     | $$__  $$| $$  | $$| $$      | $$  /$$/      
| $$   | $$   | $$        | $$  \ $$| $$  | $$| $$      | $$ /$$/       
|  $$ / $$/   | $$ /$$$$$$| $$$$$$$ | $$  | $$| $$      | $$$$$/        
 \  $$ $$/    | $$|______/| $$__  $$| $$  | $$| $$      | $$  $$        
  \  $$$/     | $$        | $$  \ $$| $$  | $$| $$      | $$\  $$       
   \  $/      | $$        | $$$$$$$/|  $$$$$$/| $$$$$$$$| $$ \  $$      
    \_/       |__/        |_______/  \______/ |________/|__/  \__/      
'''

'''--------------------- FILE CANDIDATE SELECTION ----------------------'''

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

'''--------------------- FILE ANALYSIS FUNCTIONS ----------------------'''

def getQueuedScansResultsV2():
    global path_and_link_to_requested_analysis_queue, headers, QUEUE_RETRY_DELAY, VERBOSE

    threads=[]

    while(not path_and_link_to_requested_analysis_queue.empty()):
        pair = path_and_link_to_requested_analysis_queue.get()
        file_path=pair[0]; link=pair[1]

        try: response = requests.get(link, headers=headers)
        except Exception as e: print(e); return None

        if(response.json()['data']['attributes']['status'] == "completed"):
            t=threading.Thread(target=multithread_GetFileResults,args=(file_path,))
            t.start()
            threads.append(t)

        else:
            if VERBOSE: print(f"STATUS: {file_path}: {response.json()['data']['attributes']['status']}")
            path_and_link_to_requested_analysis_queue.put(pair)
            if VERBOSE : print(f"Waiting for: {QUEUE_RETRY_DELAY}s")
            time.sleep(QUEUE_RETRY_DELAY)

    for t in threads:
        t.join()
    return

def multithread_GetFileResults(file_path : str):
    global headers
    response=requests.get(f"https://www.virustotal.com/api/v3/files/{HashFileMD5(file_path)}",headers=headers)

    if response.status_code == 200:
        if VERBOSE: print(f"File {os.path.basename(file_path)} retrieved successfully")
        jsondump = response.json()
        analysis_results_queue.put({"file_path" : file_path, "names" : jsondump["data"]["attributes"]["names"], "link": jsondump['data']['links']["self"], "summary" : jsondump["data"]["attributes"]["last_analysis_stats"]  })
        createAnalysisFile(jsondump, file_path)

    elif response.status_code==404:
        if VERBOSE: print(f"File {os.path.basename(file_path)} does not have valid previous analyses, sending to VT")
        files_need_scanning_queue.put(file_path)

    else:
        print(f"UNKNOWN ERROR: {response.status_code}, EXITING NOW")
        exit(1)

def multithread_launchProgram(file_list : list) -> None:
    global finished_requesting_scans
    threads=[]

    batch_results={
        "malicious_files": list(),
        "suspicious_files": list(),
        "undetected_files": list()
    }

    analysisWorker = threading.Thread(target=requestedAnalysisWorker)
    analysisWorker.start()

    for file_path in file_list:
        t = threading.Thread(target=multithread_GetFileResults, args=(file_path,))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    finished_requesting_scans=True
    analysisWorker.join()

    getQueuedScansResultsV2()

    while(not analysis_results_queue.empty()):
        result = analysis_results_queue.get()
        printSummarizedReport2(result)
        if result["summary"]["malicious"]!=0: batch_results["malicious_files"].append(os.path.basename(result["file_path"]))
        elif result["summary"]["suspicious"]!=0: batch_results["suspicious_files"].append(os.path.basename(result["file_path"]))
        else: batch_results["undetected_files"].append(os.path.basename(result["file_path"]))

    print("\nTotal results: ")
    print("\tMalicious: " + str(batch_results["malicious_files"]))
    print("\tSuspicious: " + str(batch_results["suspicious_files"]))
    print("\tUndetected: " + str(batch_results["undetected_files"])+"\n")

'''--------------------- WORKERS --------------------------------------'''
class APIRateLimiter:
    def __init__(self, analysis_requests_per_minute):
        self.rpm = int(analysis_requests_per_minute)
        self.queue = Queue()

    def request(self):
        if self.queue.qsize() >= self.rpm:
            oldest_request_time = self.queue.get()
            time_delta = time.time() - oldest_request_time
            if time_delta <= 60:
                if VERBOSE: print(f"API minutely upload minute reached, thread sleeping for: {60-time_delta}s.")
                time.sleep(60-time_delta) #Sleep for time remaining for last request decay

    def place(self):
            self.queue.put(time.time())

def requestedAnalysisWorker():  #Async queue manager for files sent to VT
    global API_SCAN_REQUESTS_PER_MINUTE
    rateLimiter = APIRateLimiter(API_SCAN_REQUESTS_PER_MINUTE)

    while not finished_requesting_scans or not files_need_scanning_queue.empty():
        if not files_need_scanning_queue.empty():
            file_path = files_need_scanning_queue.get()
            try:
                with open(file_path, "rb") as f:

                    rateLimiter.request()
                    response = requests.post("https://www.virustotal.com/api/v3/files", files={"file": f},headers=headers)
                    rateLimiter.place()

            except Exception as e:
                print(f"Could not open or send file {file_path}")
                print(e)

            if response.status_code == 200:
                path_and_link_to_requested_analysis_queue.put((file_path, response.json()['data']['links']['self']))
            else: print(f"Error has ocurred while attempting to send file {file_path} to Virus-Total")
        else:
            time.sleep(0.1)

'''--------------------- AUXILIARY FUNCTIONS --------------------------'''

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
    global DIRECTORY_PATH, extension
    DIRECTORY_PATH = None
    extension = None

    sys.argv.pop(0)  # Pop scripts name

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
    global NO_JSON_DUMP
    DIRECTORY_PATH = input("Choose directory to fetch files from (if blank, will choose the current dir): ")
    if(DIRECTORY_PATH == ""):
        DIRECTORY_PATH = os.getcwd()
    print("Extensions to scan (leave blank to scan every extension)")
    print("F.E: .dll, .exe")
    extension = input()

    while(1):
        user_wants_dumps=input("Do you want the results dumped into .json files? (y/n) :")
        if(user_wants_dumps[0].lower() == "y"): NO_JSON_DUMP=False; break
        elif(user_wants_dumps[0].lower() == "n"): NO_JSON_DUMP=True; break


    return DIRECTORY_PATH, extension

def APIHelper():
    global client_api_key,vt_user_id
    vt_user_id = ""
    client_api_key = ""
    print("Seems like you dont have an vt_api_key.txt file, let me help you with that")
    while(vt_user_id==""):
        vt_user_id = input("Enter your Virus total user id (Virus Total -> Profile) : ")
    while(len(client_api_key)!=64):
        client_api_key=input(f"Paste your Virus Total API key (https://www.virustotal.com/gui/user/{vt_user_id}/apikey) : ")
        if(len(client_api_key)!=64): print("Invalid API key")
    with open("vt_api_key.txt","w") as api_key_file:
        api_key_file.write(f"{client_api_key}:{vt_user_id}")
        api_key_file.close()
    print("All set!, resuming")

def printAndSaveDailyAPIQuotaStats():
    global headers
    response = requests.get(f"https://www.virustotal.com/api/v3/users/{vt_user_id}/api_usage", headers=headers)
    response_json=response.json()
    if response.status_code==200:
        print("Daily API Quota Stats: ")
        print("\t"+str(response_json["data"]["daily"][datetime.datetime.today().strftime('%Y-%m-%d')]))
        if(not NO_JSON_DUMP):
            with open(f"quota_stats.json", "w", encoding="utf-8") as json_file:
                json.dump(response_json, json_file, indent=4)
    else:
        print(f"Could not fetch quota stats, request code \"{response.status_code}\", skipping. ")

def createAnalysisFile(jsondump : dict, file_path : str):
    global NO_JSON_DUMP

    if NO_JSON_DUMP:
        return
    if not os.path.exists("./scans"):
        os.makedirs("./scans")
    with open(f"./scans/{os.path.basename(file_path)}-{HashFileMD5(file_path)}.analysis.json", "w", encoding="utf-8") as json_file:
        json.dump(jsondump, json_file, indent=4)

def printSummarizedReport2(results : dict):
    print("\n"+results["file_path"]+": ")
    print(f"Registered names: {results["names"]}")
    if VERBOSE: print(f"Link: {results["link"]}")
    print(f"Results: {results["summary"]}")


'''--------------------- MAIN ----------------------------------------'''

if __name__ == '__main__':

    try:
        api_and_user_string = open("vt_api_key.txt", "r").read()
    except FileNotFoundError:
        APIHelper()
        api_and_user_string = open("vt_api_key.txt", "r").read()

    client_api_key = api_and_user_string.split(":")[0]
    vt_user_id = api_and_user_string.split(":")[1]
    headers={
            "accept" : "application/json",
            "x-apikey" : client_api_key
        }

    print(__ascii_art__)
    argumentHandler()
    files = getFilesToScan(DIRECTORY_PATH, extension)
    getUserVerification(files)
    multithread_launchProgram(files)
    printAndSaveDailyAPIQuotaStats()
    exit(0)