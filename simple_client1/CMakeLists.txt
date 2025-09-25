# This is the most simple CMake file 
# It is kept as simple as possible to mak eit easier to 
# understand the basics.
# Check out the CMakeLists.txt file in simpleclient2
# for a more comprehensive make file

cmake_minimum_required(VERSION 3.14)
project(simple_client C CXX)

# Add this to let CMake find the DynamoRIOConfig.cmake
list(APPEND CMAKE_PREFIX_PATH "C:/tools/DynamoRIO-Windows-11.3.0/cmake")

# Find the DynamoRIO package (uses the config file in the path above)
find_package(DynamoRIO REQUIRED CONFIG)

# Define the client as a shared library
add_library(simple_client SHARED client.c)

# Mark this as a DynamoRIO client (sets flags, includes, etc.)
configure_DynamoRIO_client(simple_client)

# Optionally install the resulting DLL somewhere
install(TARGETS simple_client DESTINATION bin)

# Optional: Suppress:
#   LNK4281: undesirable base address" warning, it is normal for DR clients
#   LNK4075: ignoring '/INCREMENTAL' due to '/OPT:ICF' specification
target_link_options(simple_client PRIVATE "/IGNORE:4281")
target_link_options(simple_client PRIVATE "/IGNORE:4075")
