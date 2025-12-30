import sys, hashlib, vt, os, time
from queue import Queue

client_api_key=open("vt_api_key.txt","r").read()

global WAIT_TIME_SCAN
WAIT_TIME_SCAN=30

#FILE SCANNING FUNCTIONS
def getFilesToScan(rootDir : str, extension : str) -> list:

    candidateFiles=getAllFilesInDirHyerarchy(rootDir)
    return filterFilesByExtension(candidateFiles, extension)
def getAllFilesInDirHyerarchy(rootDir : str) -> list : #RETURN RELATIVE_PATH OF ALL FILES IN FOLDER HYERARCHY 
    files_list = []
    for root, dirs, files in os.walk(rootDir):
        for file in files:
            full_path = os.path.join(root, file)
            files_list.append(full_path)
    return files_list
def filterFilesByExtension(candidateFiles_RELPATH : list, extensionstr : str) -> list:           #SHOULD BE CALLED ONCE 
    
    #If no extension provided, return all candidate files
    if extensionstr == None or extensionstr.strip()=="":  return candidateFiles_RELPATH
        
    extensionset=set(extensionstr.split(","))                                           #Split input extensions
    extensionset=[extension.strip().removeprefix('.') for extension in extensionset]    #Strip every extension and normalize format
    output=[file for file in candidateFiles_RELPATH if file.split(".")[-1] in extensionset] #Return every file that matches with one of the extensions
    return output

#FILE ANALYSIS FUNCTIONS     
def getFileAnalysis(file : str) -> vt.Object:
    try:
        #print(file)
        #print(MD5_File_Hash)
        MD5_File_Hash=HashFileMD5(file)
        analysis=client.get_object("/files/"+MD5_File_Hash)
        return analysis
    
    except vt.error.APIError as e:
        if e.args[0]=="NotFoundError":
            return scanFile(file)
        else: 
            client.close()
            print("API Error: " + str(e))
            raise 
def scanFile(file : str) -> vt.Object:
    #Scans the file
    print("SCANNING: "+file)
    
    try:
        with open(file, "rb") as f:
            analysis = client.scan_file(f)
        
        while True:
            analysis = client.get_object("/analyses/"+analysis.id)
            print(analysis.status)
            if analysis.status == "completed":
                break
            time.sleep(WAIT_TIME_SCAN)
        return analysis
    
    except vt.error.APIError as e:
        client.close()
        print("API Error: " + str(e))
        raise

#HELPER FUNCTIONS
def getUserVerification(files : list): 
    #PREREQUISITES
    if(files==[]):
        print("No files found in directory, aborting")
        exit(1)
        
     #SHOW FILES BY EXTENSION
    fileMap={}
    print("The following files will be uploaded for verification: ")
    for f in files:
        extension="."+f.split(".")[-1]
        fileMap.setdefault(extension, []).append(f)
    for key in fileMap.keys():
        print(key+": ")
        for f in fileMap[key]:
            print('\t'+f)
            
    #ASK USER FOR FINAL VERIFICATION
    while(1):    
        userVerification=input("\nWant to proceed? (yes/no) \n").lower()
        if(userVerification=="no" or userVerification=="n"):
            exit(1)
        elif(userVerification=="yes" or userVerification=="y"):
            return
        else:
            print("Unvalid option")
def argumentHandler():

    global DIRECTORY_PATH,extension, only_print_unsafe,full_report
    DIRECTORY_PATH=None
    extension=None
    only_print_unsafe=False
    full_report=False

    sys.argv.pop(0) #Pop scripts name
    
    if(sys.argv.__len__()==0): exit("Program usage: python vtbu.py [-e {extension} | other_arguments] PATH_TO_DIR")
        
    while(sys.argv.__len__()!=0):
        argument=sys.argv[0]
        
        #Is modifier?
        if argument.startswith("-") or argument.startswith("--"):
        
            if argument=="-e" or argument=="--extension":

                if(sys.argv.__len__() < 2):
                    exit("Argument -e must be followed by an extension, for example: -e .exe")
                    
                extension=sys.argv[1]
                sys.argv.pop(0)
                
            elif argument=="-u" or argument=="--unsafe-only": only_print_unsafe=True
            elif argument=="-f" or argument=="--full-report": full_report=True     
            else: exit("Invalid argument: "+argument) 
            
            sys.argv.pop(0)

        #If is not modifier, it is folder path
        else: 
            DIRECTORY_PATH=sys.argv[0]
            if not os.path.isdir(DIRECTORY_PATH):
                exit("Invalid directory path: "+argument)
                
            #if DIRECTORY_PATH.endswith("/"):            # python vt-sbs myDir/ -> myDir
                #DIRECTORY_PATH=DIRECTORY_PATH[:-1]
                
            sys.argv.pop(0)
    if DIRECTORY_PATH==None:
        exit("Aborted: file path cant be None")
def HashFileMD5(file : str) -> str:
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

#FILE ANALYSIS HANDLERS
def ScanAndGetResults(files : list):
    exit_code=0
    try:
        global client 
        client = vt.Client(client_api_key)
        try:
            malicious=0
            malicious_list=[]
            
            suspicious=0
            suspicious_list=[]
            
            undetected=0
            
            for file in files:
                full_analysis=getFileAnalysis(file)
                print(full_analysis)
                try:
                    analysis_stats=full_analysis.last_analysis_stats     #Fetch from /files/
                except:
                    analysis_stats=full_analysis.stats                   #Fetch from /analyses/
                
                if not full_report:
                    #print(analysis.stats["malicious"])
                    if(analysis_stats["malicious"]!=0 or analysis_stats["suspicious"]!=0):
                        print(file+": ")
                        if(analysis_stats["malicious"]!=0):
                            malicious+=1
                            malicious_list.append(file)
                            print("Malicious: "+str(analysis_stats["malicious"]))
                        if(analysis_stats["suspicious"]!=0):
                            suspicious+=1
                            suspicious_list.append(file)
                            print("Suspicious: "+str(analysis_stats["suspicious"]))          
                                
                    else:
                        undetected+=1
                        if not only_print_unsafe: print(file+": Clean!")
                else:   #TO DO
                    print(file+": ")
                    print(analysis_stats)
                    
                #PRINT SUMMARY
            print("------ SUMMARY ------")
            print("UNDETECTED: "+str(undetected))
            print("SUSPICIOUS: "+str(suspicious))
            if(suspicious>0): print(suspicious_list)
            print("MALICIOUS: "+str(malicious))
            if(malicious>0): print(malicious_list)
                
        except Exception as e: 
            exit_code=1
            print("Couldnt process file: "+file)
            client.close()
            exit(exit_code)

    except Exception as e:
        print(e)
        exit_code=2
    finally: 
        client.close()
        
######### MAIN #########
argumentHandler()
files=getFilesToScan(DIRECTORY_PATH,extension)
getUserVerification(files)
ScanAndGetResults(files)
exit(0)
