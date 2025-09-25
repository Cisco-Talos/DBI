#!/usr/bin/bash

"C:\tools\DynamoRIO-Windows-11.3.0\bin32\drrun.exe" -c "./bin/Release/memdump32.dll" -start 0x4010DA -n 32 -b -- "../testsamples/strDecode/Release/strDecode.exe"