#!/usr/bin/bash

"C:\tools\DynamoRIO-Windows-11.3.0\bin64\drrun.exe" -c "./bin/Release/strdump64.dll" -start 0x1400018F0 -end 0x140001983 -n 32 -- "../testsamples/anti_x/x64/Release/anti_x.exe"
