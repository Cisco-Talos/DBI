# CMakeLists.txt for SimpleClient2 
# 
# Build (Open Developer Prompt 2019):
# 
# cmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release
# cmake --build build --config Release
# 
# Test: 
# <PathToDynRioInstall>\bin64\drrun.exe -c "<Path>\tracer.dll"  -- "<Path>\sample.exe"

cmake_minimum_required(VERSION 3.14)
project(tracer C CXX)

# Path to your DynamoRIO folder
set(DR_BASE "C:/tools/DynamoRIO-Windows-11.3.0")

# Add this to let CMake find the DynamoRIOConfig.cmake
list(APPEND CMAKE_PREFIX_PATH "${DR_BASE}/cmake")

# Find the DynamoRIO package (uses the config file in the path above)
find_package(DynamoRIO REQUIRED CONFIG)

# Define the client as a shared library
add_library(tracer SHARED tracer.c)

# Mark this as a DynamoRIO client (sets flags, includes, etc.)
configure_DynamoRIO_client(tracer)

# Manually add include path for extensions
target_include_directories(tracer PRIVATE
	 "${DR_BASE}/include"
     "${DR_BASE}/ext/include" 
)

target_compile_definitions(tracer PRIVATE NOMINMAX)

# # Manually link the drwrap library
# target_link_libraries(tracer
#     "${DR_BASE}/ext/lib64/release/drwrap.lib"
# )

# Add this line to include and link drmgr and drwrap
use_DynamoRIO_extension(tracer drmgr)
#use_DynamoRIO_extension(tracer drwrap)
#use_DynamoRIO_extension(tracer drsyms)
use_DynamoRIO_extension(tracer drutil)
use_DynamoRIO_extension(tracer drreg)

if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(_bit "64")
else()
    set(_bit "32")
endif()

set_target_properties(tracer PROPERTIES
    OUTPUT_NAME "tracer${_bit}"        # -> tracer32.dll / tracer64.dll
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/../bin/"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/../bin/"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/../bin/"
)

# For debugging build process 
# get_target_property(WRAP_LIBS tracer INTERFACE_LINK_LIBRARIES)
# message(STATUS "Linked libraries for tracer: ${WRAP_LIBS}")
# message(STATUS "C Compiler flags: ${CMAKE_C_FLAGS}")
# message(STATUS "C++ Compiler flags: ${CMAKE_CXX_FLAGS}")
# message(STATUS "Linker flags (exe): ${CMAKE_EXE_LINKER_FLAGS}")

# Optionally install the resulting DLL somewhere
install(TARGETS tracer DESTINATION bin)

# Suppress "LNK4281: undesirable base address 0x72000000 for x64 image" waring
# DynamoRio uses set(preferred_base "0x71000000") in its CMakeLists.txt 
# file to keep its client DLL close to its own memory regions
target_link_options(tracer PRIVATE "/IGNORE:4281")

add_custom_command(
  TARGET tracer
  POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E echo DLL: $<TARGET_FILE:tracer>
  COMMAND ${CMAKE_COMMAND} -E echo LIB : $<TARGET_LINKER_FILE:tracer>
  VERBATIM
)