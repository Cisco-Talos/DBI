#!/usr/bin/bash

"C:\tools\DynamoRIO-Windows-11.3.0\bin32\drrun.exe" -c "./bin/Release/strdump32.dll" -start 0x401040 -end 0x401174 -n 32 -- "../testsamples/strDecode_x32.exe"