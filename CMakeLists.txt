cmake_minimum_required(VERSION 3.14)
project(SymbolicExecutor VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(CAPSTONE REQUIRED capstone)
find_package(Z3 REQUIRED)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CAPSTONE_INCLUDE_DIRS}
    ${Z3_INCLUDE_DIR}
)

# Link directories
link_directories(
    ${CAPSTONE_LIBRARY_DIRS}
    ${Z3_LIBRARY_DIRS}
)

# Source files
set(SOURCES
    src/main.cpp
    src/ELFParser.cpp
    src/Disassembler.cpp
    src/CFGBuilder.cpp
    src/MemoryModel.cpp
    src/State.cpp
    src/PathConstraint.cpp
    src/SymbolicExecutor.cpp
    src/TestCaseGenerator.cpp
    src/Statistics.cpp
)

# Create executable
add_executable(symexec ${SOURCES})

# Link libraries
target_link_libraries(symexec
    ${CAPSTONE_LIBRARIES}
    ${Z3_LIBRARIES}
    dl
)

# Compiler flags
target_compile_options(symexec PRIVATE
    -Wall
    -Wextra
    -O2
    ${CAPSTONE_CFLAGS_OTHER}
)

# Install target
install(TARGETS symexec DESTINATION bin)
