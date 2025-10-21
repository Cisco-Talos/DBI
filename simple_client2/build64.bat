
@echo off

echo compiling...
rd /S /Q build
cmake -S . -B build -G "Visual Studio 16 2019" -A x64 -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --verbose

echo.
echo Run the client like this:
echo "C:\tools\DynamoRIO-Windows-11.3.0\bin64\drrun.exe" -c "./bin/Release/simpleclient2_64.dll" -- "..\testsamples\anti_x\x64\Release\anti_x.exe"
echo.
