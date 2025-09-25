@echo off

setlocal

set /p userInput=Removing old build directory? (Y/n): 
if "%userInput%"=="" set "userInput=Y"

if /I "%userInput%"=="Y" (
    echo Deleting build directory...
    rmdir /s /q build
) else (
    echo Skipping deletion.
)

endlocal

cmake -S . -B build -G "Visual Studio 16 2019" -A x64 -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release %1

echo.
echo Test the client like this:
echo "C:\tools\DynamoRIO-Windows-11.3.0\bin64\drrun.exe" -c ".\build\Release\simple_client.dll" -s 140001919 -e 140001927 -m "anti_x.exe" -- "..\testsamples\anti_x\x64\Release\anti_x.exe"
echo.

choice /c YN /n /m "Run the the client (y/n) ?"

if errorlevel 2 (
    echo Ok. Not running client.
) else (
	echo. 
	echo.
    "C:\tools\DynamoRIO-Windows-11.3.0\bin64\drrun.exe" -c ".\build\Release\simple_client.dll" -s 140001919 -e 140001927 -m "anti_x.exe" -- "..\testsamples\anti_x\x64\Release\anti_x.exe"
)

