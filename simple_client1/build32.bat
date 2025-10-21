@echo off
echo compiling...
rd /S /Q build
cmake -S . -B build -G "Visual Studio 16 2019" -A Win32 -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --verbose

echo.
echo Run the 32 bit client like this:
echo "C:\tools\DynamoRIO-Windows-11.3.0\bin32\drrun.exe" -c ".\bin\Release\simple_client-32.dll" -- "..\testsamples\threads\Release\threads.exe"
echo.