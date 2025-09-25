Build:

- verify/change the path for your DynamoRio installation in CMakeLists.txt 
- just run MSYS_build32.sh (32bit client) and/or MSYS_build64.sh (64bit client) in an MSYS2 shell 

If you want to change source and/or DLL filename for own projects, edit "CMakeLists.txt" in this directory
Just change the names in these two lines:

set(OUTPUT_BASENAME "strdump" CACHE STRING "Base name for output file")
set(SRCFILE "strdump.c" CACHE STRING "Your source file")

