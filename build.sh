#!/bin/bash
# Build script for Symbolic Execution Engine

set -e

echo "=== Building Symbolic Execution Engine ==="

# Check for required tools
command -v cmake >/dev/null 2>&1 || { echo "cmake is required but not installed."; exit 1; }
command -v make >/dev/null 2>&1 || { echo "make is required but not installed."; exit 1; }

# Create build directory
BUILD_DIR="build"
if [ ! -d "$BUILD_DIR" ]; then
    mkdir -p "$BUILD_DIR"
fi

cd "$BUILD_DIR"

# Run cmake
echo "Running cmake..."
cmake .. -DCMAKE_BUILD_TYPE=Release

# Build
echo "Building..."
make -j$(nproc)

# Check if build succeeded
if [ -f "symexec" ]; then
    echo ""
    echo "=== Build Successful ==="
    echo "Binary: $BUILD_DIR/symexec"
    echo ""
    echo "Run with: ./$BUILD_DIR/symexec --help"
else
    echo "Build failed!"
    exit 1
fi
