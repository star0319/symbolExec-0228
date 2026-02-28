cmake_minimum_required(VERSION 3.14)
project(SymbolicExecutor VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Find required packages
#find_package(PkgConfig REQUIRED)
#pkg_check_modules(CAPSTONE REQUIRED capstone)
#find_package(Z3 REQUIRED)

# Include directories
include_directories(
        AFTER
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/external/include
)

# Link directories
link_directories(
        BEFORE
        ${CMAKE_SOURCE_DIR}/external/lib
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
        z3
        capstone
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
