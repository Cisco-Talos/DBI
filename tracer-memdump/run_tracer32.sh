#!/usr/bin/bash

"C:\tools\DynamoRIO-Windows-11.3.0\bin32\drrun.exe" -c "./bin/Release/memdump32.dll" -start 0x401040 -end 0x4010FA -n 32 -- "../testsamples/strDecode/Release/strDecode.exe"