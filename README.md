AIM:

My current aim is just to be able to easily bulk-upload files to Virus Total in an easy, Unix-like script way. I am aware that there is an official script to do this, I just dont use it because I dont understand it and prefer to do something more tailored to my needs.

USAGE:

Get your vt API key here: https://www.virustotal.com/gui/my-apikey (Must be logged in)

py -m pip install vt-py #DO THIS ONCE

py vt-sbs.py [-e {extension} | -u | -f | --unsafe-only | --full-report] PATH_TO_FILE

CURRENT PROGRAM FUNCTIONALITY:
  - Get file detections in bulk via the VirusTotal API.
  - Send files for scanning to VirusTotal (and show results).

TODO:
  - Create detailed scan dump in a file.
  - Store file detection details in .json files.
  - Reduce the amount of API usage by not requesting recently scanned files.
  - Maybe bulk scan URLs in a future?
  - UI in a far future.
