@echo off

REM use "build.bat --verbose" to see compiler and linker flags

rd /S /Q build
cmake -S . -B build -G "Visual Studio 16 2019" -A x64 -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release %1

echo.
echo Test the client like this:
echo "C:\tools\DynamoRIO-Windows-11.3.0\bin64\drrun.exe" -c ".\build\Release\simple_client.dll" -s 1400018F0 -e 140001983 -- "..\testsamples\anti_x\x64\Release\anti_x.exe"
echo.

choice /c YN /n /m "Run the the client (y/n) ?"

if errorlevel 2 (
    echo Ok. Not running client.
) else (
	echo. 
	echo.
    "C:\tools\DynamoRIO-Windows-11.3.0\bin64\drrun.exe" -c ".\build\Release\simple_client.dll" -s 1400018E0 -e 140001983 -- "..\testsamples\anti_x\x64\Release\anti_x.exe"
)

