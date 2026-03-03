AIM:

My current aim is just to be able to easily bulk-upload files to Virus Total in an easy, Unix-like script way. I am aware that there is an official script to do this, I just dont use it because I dont understand it and prefer to do something more tailored to my needs.

USAGE:

Get your vt API key here: https://www.virustotal.com/gui/my-apikey (Must be logged in)

Get your vt user id here: https://www.virustotal.com -> Profile (Must be logged in)

USAGE:  py vt-sbs.py [-e {extension(s)} | [-n | --no-json-dump] | [-v | --verbose] ] PATH_TO_FILE

PACKAGE DEPENDENCIES: 
  - sys: Get script arguments
  - hashlib: Search files by hash
  - os: Retrieve and filter files
  - time: sleep while waiting for queued analyses 
  - requests: API communicattion
  - json: .json file dumping and formatting
  - datetime: filter daily api usage by day 
  - queue: Queue analyses for later retrieval
  - threading: Multi-threading.

CURRENT PROGRAM FUNCTIONALITY:
  - Get file detections in bulk via the VirusTotal API.
  - Send files for analysis to VirusTotal (show and store results).

TODO:
  - If file is retrieved from vt cache, check multiple hashes to make sure it is not a false match
  - Fix terminal arguments
  - Reduce the amount of API usage by not requesting recently scanned files.
  - Maybe bulk scan URLs in a future?
  - UI in a far future.
