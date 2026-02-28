# Symbolic Execution Engine

A complete binary symbolic execution engine implemented in C++.

## Features

- **ELF Parser**: Parses 32/64-bit ELF binaries, extracts symbols, sections, and segments
- **Disassembler**: Capstone-based disassembly for x86/x86_64/ARM/ARM64 architectures
- **CFG Builder**: Constructs Control Flow Graphs from binary code
- **Memory Model**: Symbolic memory with concrete and symbolic values
- **State Management**: Efficient execution state management with forking
- **Path Constraints**: Z3-based constraint solving for path exploration
- **Test Case Generation**: Generates concrete test cases from symbolic execution paths

## Requirements

- CMake 3.14+
- C++17 compatible compiler (GCC 8+, Clang 7+)
- Capstone disassembly framework
- Z3 theorem prover

### Installing Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get install libcapstone-dev libz3-dev cmake build-essential
```

**macOS:**
```bash
brew install capstone z3 cmake
```

**Fedora/RHEL:**
```bash
sudo dnf install capstone-devel z3-devel cmake gcc-c++
```

## Building

```bash
cd symexec
mkdir build && cd build
cmake ..
make -j$(nproc)
```

## Usage

```bash
./symexec [OPTIONS] <binary_file>
```

### Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message |
| `-o, --output <dir>` | Output directory for results |
| `-d, --depth <n>` | Maximum execution depth (default: 50) |
| `-i, --instructions <n>` | Maximum instructions per path (default: 10000) |
| `-s, --states <n>` | Maximum concurrent states (default: 1000) |
| `-t, --timeout <n>` | Timeout in seconds (default: 60) |
| `-a, --address <addr>` | Start execution at address |
| `-e, --end <addr>` | End execution at address |
| `--symbolic <name>` | Make input symbolic (e.g., rdi, [0x1000]) |
| `--target <addr>` | Target address to reach |
| `--format <fmt>` | Output format: txt, json, xml, csv |
| `--no-testcases` | Don't generate test cases |
| `--cfg` | Export CFG to DOT format |
| `--verbose` | Enable verbose output |

### Examples

```bash
# Basic execution
./symexec ./target_binary

# With custom limits
./symexec -d 100 -t 120 ./target_binary

# Start from specific address with symbolic input
./symexec -a 0x401000 --symbolic rdi ./target_binary

# Reach target address and generate JSON output
./symexec --target 0x401234 --format json ./target_binary

# Export CFG and enable verbose output
./symexec --cfg --verbose ./target_binary
```

## Architecture

```
symexec/
├── include/
│   ├── ELFParser.h          # ELF binary parsing
│   ├── Disassembler.h       # Capstone wrapper
│   ├── CFGBuilder.h         # Control Flow Graph construction
│   ├── MemoryModel.h        # Symbolic memory and values
│   ├── State.h              # Execution state management
│   ├── PathConstraint.h     # Path constraints with Z3
│   ├── SymbolicExecutor.h   # Main execution engine
│   └── TestCaseGenerator.h  # Test case generation
├── src/
│   ├── main.cpp             # CLI entry point
│   ├── ELFParser.cpp
│   ├── Disassembler.cpp
│   ├── CFGBuilder.cpp
│   ├── MemoryModel.cpp
│   ├── State.cpp
│   ├── PathConstraint.cpp
│   ├── SymbolicExecutor.cpp
│   └── TestCaseGenerator.cpp
└── CMakeLists.txt
```

## Core Components

### ELF Parser
Parses ELF headers, program headers, section headers, and symbol tables. Supports both 32-bit and 64-bit ELF formats.

### Disassembler
Wraps Capstone to provide instruction disassembly with semantic analysis (branch detection, operand parsing, etc.).

### CFG Builder
Partitions disassembled code into basic blocks and builds edges based on control flow analysis.

### Memory Model
Implements a symbolic memory model with:
- Concrete and symbolic values
- Register file emulation
- Stack/heap/global region management
- Memory read/write operations

### State Management
Manages execution states with:
- State forking for path exploration
- DFS/BFS/random search strategies
- State pruning for infeasible paths

### Path Constraints
Uses Z3 to:
- Track path constraints
- Check feasibility of branches
- Generate concrete values from models

### Test Case Generator
Produces test cases in multiple formats:
- Text reports
- JSON/XML structured data
- Shell scripts for testing
- Python test runners
- C test harnesses

## Example Test Program

Create a simple test program to analyze:

```c
// example/target.c
#include <stdio.h>
#include <string.h>

int check_password(const char* input) {
    if (strlen(input) != 8) {
        return 0;
    }
    
    if (input[0] != 's' || input[1] != 'e' || 
        input[2] != 'c' || input[3] != 'r' ||
        input[4] != 'e' || input[5] != 't' ||
        input[6] != '1' || input[7] != '2') {
        return 0;
    }
    
    return 1;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <password>\n", argv[0]);
        return 1;
    }
    
    if (check_password(argv[1])) {
        printf("Access granted!\n");
        return 0;
    } else {
        printf("Access denied!\n");
        return 1;
    }
}
```

Compile and analyze:
```bash
gcc -o example/target example/target.c
./symexec --symbolic rdi ./example/target
```

## API Usage

```cpp
#include "SymbolicExecutor.h"
#include "TestCaseGenerator.h"

using namespace symexec;

int main() {
    // Create executor
    SymbolicExecutor executor;
    
    // Load binary
    if (!executor.loadBinary("./target_binary")) {
        return 1;
    }
    
    // Configure execution
    SymExecConfig config;
    config.maxDepth = 100;
    config.timeout = 120;
    executor.setConfig(config);
    
    // Execute
    ExecResult result = executor.execute();
    
    // Generate test cases
    TestCaseGenerator generator(executor.getZ3Context());
    auto states = executor.getTerminatedStates();
    auto testCases = generator.generateFromStates(states);
    
    // Export test cases
    generator.writeTestFile("tests.json", testCases, "json");
    
    return 0;
}
```

## Output

The tool generates:
- Execution statistics (paths explored, branches taken, solver queries)
- Test cases with concrete inputs for each path
- Coverage information
- Multiple output formats (TXT, JSON, XML, CSV)
- Executable test scripts (Shell, Python, C)

## Limitations

- No support for self-modifying code
- Limited handling of system calls
- No loop bound analysis (uses depth limit)
- Simplified memory model (no full address space emulation)
- x86/x86_64 instruction coverage is partial

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## Acknowledgments

- [Capstone](https://www.capstone-engine.org/) - Disassembly framework
- [Z3](https://github.com/Z3Prover/z3) - Theorem prover
# symbolExec-0228
