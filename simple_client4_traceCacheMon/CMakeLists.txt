# CMakeLists.txt for SimpleClient4
# 
# Build (Open Developer Prompt 2019):
# 
# cmake -S . -B build -G "Visual Studio 16 2019" -A x64 -DCMAKE_BUILD_TYPE=Release
# cmake --build build --config Release
# 
# Test: 
# <PathToDynRioInstall>\bin64\drrun.exe -c "<Path>\client4.dll"  -- "<Path>\sample.exe"

cmake_minimum_required(VERSION 3.15)
project(client4 LANGUAGES C CXX)

# Path to your DynamoRIO folder
set(DR_BASE "C:/tools/DynamoRIO-Windows-11.3.0")

# Add this to let CMake find the DynamoRIOConfig.cmake
list(APPEND CMAKE_PREFIX_PATH "${DR_BASE}/cmake")

# Find the DynamoRIO package (uses the config file in the path above)
find_package(DynamoRIO REQUIRED CONFIG)

if(NOT DynamoRIO_FOUND)
    message(FATAL_ERROR "DynamoRIO package required to build.")  
endif()

# Add DynamoRIO include directories and define your client target
include_directories(${DynamoRIO_INCLUDE_DIRS})

# Define the client as a shared library
add_library(client4 SHARED client4.c)

# Set the DLL name to "my_custom_client.dll"
set_target_properties(client4 PROPERTIES OUTPUT_NAME "simple_client")

# Mark this as a DynamoRIO client (sets flags, includes, etc.)
configure_DynamoRIO_client(client4)

# Add this line to include and link drmgr and drwrap
use_DynamoRIO_extension(client4 drmgr)
use_DynamoRIO_extension(client4 drwrap)
use_DynamoRIO_extension(client4 drsyms)

# Link the DynamoRIO library to your client. 
# Link against DynamoRIO runtime library
target_link_libraries(client4 PRIVATE ${DynamoRIO_LIBRARIES})  

# Compiler settings for MSVC (Windows):
# Define target OS and architecture for DynamoRIO (needed for Windows builds)
target_compile_definitions(client4 PRIVATE WINDOWS X86_64)  # Use X86_32 for 32-bit targets
if(MSVC)
    # Enable higher warning level and multi-processor compilation
    target_compile_options(client4 PRIVATE /W4 /MP)  
endif()

# Suppress "LNK4281: undesirable base address 0x72000000 for x64 image" waring
# DynamoRio uses set(preferred_base "0x71000000") in its CMakeLists.txt 
# file to keep its client DLL close to its own memory regions
target_link_options(client4 PRIVATE "/IGNORE:4281")

# For debugging build process 
get_target_property(LINK_LIBS client4 LINK_LIBRARIES)
message(STATUS "client4 Linked Libraries: ${LINK_LIBS}")

# Optionally install the resulting DLL somewhere
install(TARGETS client4 DESTINATION bin)

