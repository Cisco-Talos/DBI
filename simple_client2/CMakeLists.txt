# Simple CMakeLists.txt for DynamoRIO-Windows-11.3.0 clients
#
# Build:
# 
# Open MS Developer Prompt 2019:
#
# If "build" directory already exists, delete it
#
# cmake -S . -B build -G "Visual Studio 16 2019" -A Win32 -DCMAKE_BUILD_TYPE=Release    # 32 bit
# cmake -S . -B build -G "Visual Studio 16 2019" -A x64   -DCMAKE_BUILD_TYPE=Release    # 64 bit
# cmake --build build --config Release --verbose
#
# Run:
# <PathToDynRioInstall>\bin32\drrun.exe -c "<Path>\my.dll"  -- "<Path>\sample.exe"
# <PathToDynRioInstall>\bin64\drrun.exe -c "<Path>\my.dll"  -- "<Path>\sample.exe"

cmake_minimum_required(VERSION 3.14)
project(DRclient C CXX)

# --------------------------------
# Customizable filenames and paths
# --------------------------------

# Basename of DLL binary
set(OUTPUT_BASENAME "simpleclient2_")

# Source code filename 
set(SRCFILE "client2.c")

# Path to your DynamoRIO folder
set(DR_BASE "C:/tools/DynamoRIO-Windows-11.3.0")


# --- You should not need to change anything below this line ----

# Add this to let CMake find the DynamoRIOConfig.cmake
list(APPEND CMAKE_PREFIX_PATH "${DR_BASE}/cmake")

# Find the DynamoRIO package (uses the config file in the path above)
find_package(DynamoRIO REQUIRED CONFIG)

# Define the client as a shared library
add_library(${OUTPUT_BASENAME} SHARED ${SRCFILE})

# Mark this as a DynamoRIO client (sets flags, includes, etc.)
configure_DynamoRIO_client(${OUTPUT_BASENAME})

# Manually add include path for extensions
target_include_directories(${OUTPUT_BASENAME} PRIVATE
    "${DR_BASE}/include"
    "${DR_BASE}/ext/include"
)

target_compile_definitions(${OUTPUT_BASENAME} PRIVATE NOMINMAX)

# Add this line to include and link drmgr and drwrap
use_DynamoRIO_extension(${OUTPUT_BASENAME} drmgr)
use_DynamoRIO_extension(${OUTPUT_BASENAME} drutil)
use_DynamoRIO_extension(${OUTPUT_BASENAME} drreg)

if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(_bit "64")
else()
    set(_bit "32")
endif()

set_target_properties(${OUTPUT_BASENAME} PROPERTIES
    OUTPUT_NAME "${OUTPUT_BASENAME}${_bit}"  # e.g. mytracer32.dll / mytracer64.dll
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/../bin/"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/../bin/"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/../bin/"
)

# Install the resulting DLL somewhere
install(TARGETS ${OUTPUT_BASENAME} DESTINATION bin)

# Optional: Suppress:
#   LNK4281: undesirable base address" warning, it is normal for DR clients
#   LNK4075: ignoring '/INCREMENTAL' due to '/OPT:ICF' specification
target_link_options(${OUTPUT_BASENAME} PRIVATE "/IGNORE:4281")
target_link_options(${OUTPUT_BASENAME} PRIVATE "/IGNORE:4075")

# Optional: Print out filepath again after build
add_custom_command(
  TARGET ${OUTPUT_BASENAME}
  POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E echo DLL: $<TARGET_FILE:${OUTPUT_BASENAME}>
  COMMAND ${CMAKE_COMMAND} -E echo LIB : $<TARGET_LINKER_FILE:${OUTPUT_BASENAME}>
  VERBATIM
)
