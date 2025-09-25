@echo off
echo compiling...
rd /S /Q build
cmake -S . -B build -G "Visual Studio 16 2019" -A Win32 -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --verbose

echo.
echo Run the client like this:
echo "C:\tools\DynamoRIO-Windows-11.3.0\bin32\drrun.exe" -c "./build\Release\simple_client.dll" -- "..\testsamples\threads\Release\threads.exe"
echo.