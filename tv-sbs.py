import sys
import hashlib
import vt
import os

client_api_key="PLACE_YOUR_VIRUSTOTAL_API_KEY_HERE"

if(sys.argv.__len__()==0): raise Exception("UnsupportedArgumentsException")


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


def getCandidateFiles(dir : str, extension : str | None) -> list: 
    #Normalizes extension format
    if extension != None:
        extension=extension.strip()
        if(extension[0]=='.'):
            extension=extension[1:]
            print(extension)
        
    #List files and filters by extension
    files = os.listdir(dir)
    if(extension!=None):
        candidates=[f for f in files if f.endswith("."+extension)]
        return candidates
    else: 
        return files

def getUserVerification(files : list): 
    if(files==[]):
        print("No files found in directory, aborting")
        exit(1)
        
    print("The following files will be uploaded for verification: ")
    for f in files: 
        print (f)
    while(1):    
        userVerification=input("Want to proceed? yes/no \n").lower()
        if(userVerification=="no" or userVerification=="n"):
            exit(1)
        elif(userVerification=="yes" or userVerification=="y"):
            return
        else:
            print("Unvalid option")
        
def argumentHandler():
    
    global DIRECTORY_PATH
    DIRECTORY_PATH=None
    
    global extension
    extension=None
    
    global only_print_unsafe
    only_print_unsafe=False
    
    global full_report
    full_report=False
    
    sys.argv.pop(0) #Pop scripts name
    
    if(sys.argv.__len__()==0): exit("Program usage: python vtbu.py [-e {extension} | other_arguments] PATH_TO_FILE")
        
    while(sys.argv.__len__()!=0):
        argument=sys.argv[0]
        
        #Is modifier?
        if argument.startswith("-") or argument.startswith("--"):
        
            if argument=="-e" or argument=="--extension":

                if(sys.argv.__len__() < 2):
                    exit("Argument -e must be followed by an extension, for example: -e .exe")
                    
                extension=sys.argv[1]
                sys.argv.pop(0)
                
            elif argument=="-u" or argument=="--only-unsafe": only_print_unsafe=True
            elif argument=="-f" or argument=="--full-report": full_report=True     
            else: exit("Invalid argument: "+argument) 
            
            sys.argv.pop(0)

        #If is not modifier, it is folder path
        else: 
            DIRECTORY_PATH=sys.argv[0]
            if not os.path.isdir(DIRECTORY_PATH):
                exit("Invalid directory path: "+argument)
            sys.argv.pop(0)
    if DIRECTORY_PATH==None:
        exit("Aborted: file path cant be None")
            
def getFileAnalysis(file : str) -> vt.Object:
    try:
        #print(file)
        #print(MD5_File_Hash)
        MD5_File_Hash=HashFileMD5(DIRECTORY_PATH+"/"+file)
        analysis=client.get_object("/files/"+MD5_File_Hash).last_analysis_stats
        return analysis
    
    except vt.error.APIError as e:
        client.close()
        print("API Error, Quota exceeded?: " + str(e))
        raise
    
    

            

#analysis=client.get_object("/files/7b9c519fc7f5f6a49529adf436837e65").last_analysis_stats
#files=[f for f in os.listdir(sys.argv[1]) if os.path.isfile(f)]

argumentHandler()
files=getCandidateFiles(DIRECTORY_PATH,extension)
getUserVerification(files)
exit_code=0
try:
    client = vt.Client(client_api_key)
    try:
        malicious=0
        malicious_list=[]
        
        suspicious=0
        suspicious_list=[]
        
        undetected=0
        
        for file in files:
            analysis=getFileAnalysis(file)
            
            if not full_report:
    
                if(analysis["malicious"]!=0 or analysis["suspicious"]!=0):
                    print(file+": ")
                    if(analysis["malicious"]!=0):
                        malicious+=1
                        malicious_list.append(file)
                        print("Malicious: "+str(analysis["malicious"]))
                    if(analysis["suspicious"]!=0):
                        suspicious+=1
                        suspicious_list.append(file)
                        print("Suspicious: "+str(analysis["suspicious"]))          
                              
                else:
                    undetected+=1
                    if not only_print_unsafe: print(file+": Clean!")
            else:   #TO DO
                print(file+": ")
                print(analysis)
                
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
    exit(exit_code)