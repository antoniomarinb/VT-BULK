AIM:
My current aim is just to be able to easily bulk-upload files to Virus Total in an easy, Unix-like script way. I am aware that there is an official script to do this, I just dont use it because I dont understand it and prefer to do something more tailored to my needs.

USAGE:

python vt-sbs.py [-e {extension} | -u | -f | --unsafe-only | --full-report] PATH_TO_FILE

CURRENT PROGRAM FUNCTIONALITY:
  - Get file detections in bulk via the VirusTotal API

TODO:
  - Store file detection details in .json files
  - Reduce the amount of API usage by not requesting recently scanned files
  - Add the ability to scan files, not just request info.
  - Maybe bulk scan URLs in a future?
  - UI in a far future.
