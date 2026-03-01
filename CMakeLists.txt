cmake_minimum_required(VERSION 3.14)
project(SymbolicExecutor VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include_directories(
    AFTER
    ${CMAKE_CURRENT_SOURCE_DIR}/external/include
)

link_directories(
    BEFORE
    ${CMAKE_SOURCE_DIR}/external/lib
)

add_executable(symexec src/main.cpp)

target_link_libraries(symexec
    z3
    capstone
    dl
)

target_compile_options(symexec PRIVATE
    -Wall
    -Wextra
    -O2
)
