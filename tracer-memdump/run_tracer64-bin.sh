#!/usr/bin/bash

"C:\tools\DynamoRIO-Windows-11.3.0\bin64\drrun.exe" -c "./bin/Release/memdump64.dll" -start 0x14000195F -end 0x14000195F -n 32 -b -- "../testsamples/anti_x/x64/Release/anti_x.exe"
