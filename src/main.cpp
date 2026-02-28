#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <getopt.h>

#include "ELFParser.h"
#include "Disassembler.h"
#include "CFGBuilder.h"
#include "MemoryModel.h"
#include "State.h"
#include "PathConstraint.h"
#include "SymbolicExecutor.h"
#include "TestCaseGenerator.h"

using namespace symexec;

// Print usage information
void printUsage(const char* program) {
    std::cout << "Usage: " << program << " [OPTIONS] <binary_file>\n";
    std::cout << "\nSymbolic Execution Engine for Binary Analysis\n\n";
    std::cout << "Options:\n";
    std::cout << "  -h, --help              Show this help message\n";
    std::cout << "  -o, --output <dir>      Output directory for results\n";
    std::cout << "  -d, --depth <n>         Maximum execution depth (default: 50)\n";
    std::cout << "  -i, --instructions <n>  Maximum instructions per path (default: 10000)\n";
    std::cout << "  -s, --states <n>        Maximum concurrent states (default: 1000)\n";
    std::cout << "  -t, --timeout <n>       Timeout in seconds (default: 60)\n";
    std::cout << "  -a, --address <addr>    Start execution at address\n";
    std::cout << "  -e, --end <addr>        End execution at address\n";
    std::cout << "  --symbolic <name>       Make input symbolic (e.g., rdi, [0x1000])\n";
    std::cout << "  --target <addr>         Target address to reach\n";
    std::cout << "  --format <fmt>          Output format: txt, json, xml, csv (default: txt)\n";
    std::cout << "  --no-testcases          Don't generate test cases\n";
    std::cout << "  --cfg                   Export CFG to DOT format\n";
    std::cout << "  --verbose               Enable verbose output\n";
    std::cout << "  --version               Show version information\n";
    std::cout << "\nExamples:\n";
    std::cout << "  " << program << " ./target_binary\n";
    std::cout << "  " << program << " -d 100 -t 120 ./target_binary\n";
    std::cout << "  " << program << " -a 0x401000 --symbolic rdi ./target_binary\n";
    std::cout << "  " << program << " --target 0x401234 --format json ./target_binary\n";
}

// Print version
void printVersion() {
    std::cout << "Symbolic Executor v1.0.0\n";
    std::cout << "A binary symbolic execution engine\n";
    std::cout << "Features:\n";
    std::cout << "  - ELF binary parsing\n";
    std::cout << "  - Capstone disassembly\n";
    std::cout << "  - CFG construction\n";
    std::cout << "  - Symbolic execution with Z3\n";
    std::cout << "  - Test case generation\n";
}

// Parse command line arguments
struct Config {
    std::string binaryPath;
    std::string outputDir;
    std::string format;
    uint64_t startAddr;
    uint64_t endAddr;
    uint64_t targetAddr;
    size_t maxDepth;
    size_t maxInstructions;
    size_t maxStates;
    size_t timeout;
    bool generateTestCases;
    bool exportCFG;
    bool verbose;
    std::vector<std::string> symbolicInputs;
    
    Config() : startAddr(0), endAddr(0), targetAddr(0),
               maxDepth(50), maxInstructions(10000), maxStates(1000),
               timeout(60), generateTestCases(true), exportCFG(false),
               verbose(false) {}
};

Config parseArgs(int argc, char* argv[]) {
    Config config;
    
    static struct option long_options[] = {
        {"help",        no_argument,       nullptr, 'h'},
        {"output",      required_argument, nullptr, 'o'},
        {"depth",       required_argument, nullptr, 'd'},
        {"instructions",required_argument, nullptr, 'i'},
        {"states",      required_argument, nullptr, 's'},
        {"timeout",     required_argument, nullptr, 't'},
        {"address",     required_argument, nullptr, 'a'},
        {"end",         required_argument, nullptr, 'e'},
        {"symbolic",    required_argument, nullptr, 'S'},
        {"target",      required_argument, nullptr, 'T'},
        {"format",      required_argument, nullptr, 'f'},
        {"no-testcases",no_argument,       nullptr, 'n'},
        {"cfg",         no_argument,       nullptr, 'c'},
        {"verbose",     no_argument,       nullptr, 'v'},
        {"version",     no_argument,       nullptr, 'V'},
        {nullptr,       0,                 nullptr, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "ho:d:i:s:t:a:e:S:T:f:ncvV", 
                               long_options, nullptr)) != -1) {
        switch (opt) {
            case 'h':
                printUsage(argv[0]);
                exit(0);
                
            case 'o':
                config.outputDir = optarg;
                break;
                
            case 'd':
                config.maxDepth = std::stoul(optarg);
                break;
                
            case 'i':
                config.maxInstructions = std::stoul(optarg);
                break;
                
            case 's':
                config.maxStates = std::stoul(optarg);
                break;
                
            case 't':
                config.timeout = std::stoul(optarg);
                break;
                
            case 'a':
                config.startAddr = std::stoull(optarg, nullptr, 0);
                break;
                
            case 'e':
                config.endAddr = std::stoull(optarg, nullptr, 0);
                break;
                
            case 'S':
                config.symbolicInputs.push_back(optarg);
                break;
                
            case 'T':
                config.targetAddr = std::stoull(optarg, nullptr, 0);
                break;
                
            case 'f':
                config.format = optarg;
                break;
                
            case 'n':
                config.generateTestCases = false;
                break;
                
            case 'c':
                config.exportCFG = true;
                break;
                
            case 'v':
                config.verbose = true;
                break;
                
            case 'V':
                printVersion();
                exit(0);
                
            default:
                printUsage(argv[0]);
                exit(1);
        }
    }
    
    if (optind < argc) {
        config.binaryPath = argv[optind];
    } else {
        std::cerr << "Error: No binary file specified\n\n";
        printUsage(argv[0]);
        exit(1);
    }
    
    return config;
}

// Main entry point
int main(int argc, char* argv[]) {
    Config config = parseArgs(argc, argv);
    
    std::cout << "=== Symbolic Execution Engine ===\n\n";
    
    // Load and parse binary
    std::cout << "Loading binary: " << config.binaryPath << "\n";
    
    ELFParser parser;
    ELFInfo elfInfo = parser.parseFile(config.binaryPath);
    
    if (!elfInfo.isValid) {
        std::cerr << "Error: " << elfInfo.errorMessage << std::endl;
        return 1;
    }
    
    std::cout << "  Architecture: " << ELFParser::getArchitectureString(elfInfo.machine) << "\n";
    std::cout << "  Type: " << ELFParser::getELFTypeString(elfInfo.elfType) << "\n";
    std::cout << "  Entry Point: 0x" << std::hex << elfInfo.entryPoint << std::dec << "\n";
    std::cout << "  Is PIE: " << (elfInfo.isPIE ? "Yes" : "No") << "\n";
    std::cout << "  Symbols: " << elfInfo.symbols.size() << "\n";
    std::cout << "  Segments: " << elfInfo.segments.size() << "\n\n";
    
    // Build CFG
    std::cout << "Building Control Flow Graph...\n";
    CFGBuilder cfgBuilder;
    ControlFlowGraph cfg = cfgBuilder.buildCFG(elfInfo, 
        std::vector<uint8_t>(1024));  // Would need actual binary data
    
    std::cout << "  Basic Blocks: " << cfg.basicBlocks.size() << "\n";
    std::cout << "  Edges: " << cfg.edges.size() << "\n";
    std::cout << "  Functions: " << cfg.functions.size() << "\n\n";
    
    // Export CFG if requested
    if (config.exportCFG) {
        std::string cfgPath = config.outputDir.empty() ? "cfg.dot" : 
                              config.outputDir + "/cfg.dot";
        std::ofstream cfgFile(cfgPath);
        if (cfgFile.is_open()) {
            cfgFile << cfgBuilder.toDOT(cfg);
            cfgFile.close();
            std::cout << "Exported CFG to: " << cfgPath << "\n";
        }
    }
    
    // Setup symbolic executor
    std::cout << "Initializing symbolic executor...\n";
    
    SymbolicExecutor executor;
    SymExecConfig execConfig;
    execConfig.maxDepth = config.maxDepth;
    execConfig.maxInstructions = config.maxInstructions;
    execConfig.maxStates = config.maxStates;
    execConfig.timeout = config.timeout;
    execConfig.generateTestCases = config.generateTestCases;
    
    if (config.targetAddr != 0) {
        execConfig.targetAddresses.insert(config.targetAddr);
    }
    
    executor.setConfig(execConfig);
    
    // Register callbacks for verbose output
    if (config.verbose) {
        executor.registerCallback(EventType::INSTRUCTION_EXECUTED,
            [](ExecutionState& state, EventType type, const std::string& data) {
                std::cout << "  [INST] 0x" << std::hex << state.getPC() << std::dec
                          << ": " << data << "\n";
            });
        
        executor.registerCallback(EventType::STATE_FORKED,
            [](ExecutionState& state, EventType type, const std::string& data) {
                std::cout << "  [FORK] State #" << state.getId() << ": " << data << "\n";
            });
    }
    
    // Load binary into executor
    if (!executor.loadBinary(config.binaryPath)) {
        std::cerr << "Failed to load binary into executor" << std::endl;
        return 1;
    }
    
    // Make inputs symbolic if specified
    for (const auto& symInput : config.symbolicInputs) {
        if (symInput[0] == 'r' || symInput[0] == 'e') {
            // Register input
            executor.makeRegisterSymbolic(symInput, symInput);
        } else if (symInput.substr(0, 2) == "0x") {
            // Memory input
            uint64_t addr = std::stoull(symInput, nullptr, 0);
            executor.makeInputSymbolic("mem_input", addr, 8);
        }
    }
    
    // Execute
    std::cout << "\nStarting symbolic execution...\n";
    std::cout << "  Max Depth: " << config.maxDepth << "\n";
    std::cout << "  Max Instructions: " << config.maxInstructions << "\n";
    std::cout << "  Max States: " << config.maxStates << "\n";
    std::cout << "  Timeout: " << config.timeout << "s\n";
    
    if (config.startAddr != 0) {
        std::cout << "  Start Address: 0x" << std::hex << config.startAddr << std::dec << "\n";
    }
    if (config.endAddr != 0) {
        std::cout << "  End Address: 0x" << std::hex << config.endAddr << std::dec << "\n";
    }
    if (config.targetAddr != 0) {
        std::cout << "  Target Address: 0x" << std::hex << config.targetAddr << std::dec << "\n";
    }
    
    std::cout << "\n";
    
    auto startTime = std::chrono::high_resolution_clock::now();
    
    ExecResult result;
    if (config.startAddr != 0) {
        result = executor.executeFrom(config.startAddr, config.endAddr);
    } else {
        result = executor.execute();
    }
    
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        endTime - startTime).count();
    
    // Print results
    std::cout << "\n=== Execution Results ===\n\n";
    
    switch (result) {
        case ExecResult::SUCCESS:
            std::cout << "Status: Completed successfully\n";
            break;
        case ExecResult::TIMEOUT:
            std::cout << "Status: Timeout reached\n";
            break;
        case ExecResult::MAX_STATES_REACHED:
            std::cout << "Status: Maximum states reached\n";
            break;
        case ExecResult::MAX_DEPTH_REACHED:
            std::cout << "Status: Maximum depth reached\n";
            break;
        case ExecResult::ERROR:
            std::cout << "Status: Error occurred\n";
            break;
        default:
            std::cout << "Status: Unknown\n";
    }
    
    std::cout << "Execution Time: " << duration << " ms\n\n";
    
    // Print statistics
    executor.printStats();
    
    // Generate test cases
    if (config.generateTestCases) {
        std::cout << "\n=== Generating Test Cases ===\n\n";
        
        TestCaseGenerator generator(executor.getZ3Context());
        
        auto terminatedStates = executor.getTerminatedStates();
        auto testCases = generator.generateFromStates(terminatedStates);
        
        std::cout << "Generated " << testCases.size() << " test cases\n";
        
        // Print test case statistics
        auto tcStats = generator.calculateStats(testCases);
        std::cout << tcStats.toString() << "\n\n";
        
        // Print sample test cases
        size_t printCount = std::min(testCases.size(), size_t(5));
        for (size_t i = 0; i < printCount; ++i) {
            std::cout << "--- Test Case " << i << " ---\n";
            std::cout << testCases[i].toString() << "\n";
        }
        
        if (testCases.size() > printCount) {
            std::cout << "... and " << (testCases.size() - printCount) << " more test cases\n";
        }
        
        // Write test cases to file
        std::string outputPath = config.outputDir.empty() ? "." : config.outputDir;
        
        std::string txtPath = outputPath + "/test_cases.txt";
        generator.writeTestFile(txtPath, testCases, "txt");
        
        if (config.format == "json" || config.format == "all") {
            std::string jsonPath = outputPath + "/test_cases.json";
            generator.writeTestFile(jsonPath, testCases, "json");
        }
        
        if (config.format == "xml" || config.format == "all") {
            std::string xmlPath = outputPath + "/test_cases.xml";
            generator.writeTestFile(xmlPath, testCases, "xml");
        }
        
        // Generate test scripts
        std::string shPath = outputPath + "/run_tests.sh";
        generator.generateShellScript(shPath, testCases, config.binaryPath);
        
        std::string pyPath = outputPath + "/test_runner.py";
        generator.generatePythonScript(pyPath, testCases, config.binaryPath);
        
        std::string cPath = outputPath + "/test_harness.c";
        generator.generateCHarness(cPath, testCases, "target_function");
        
        std::cout << "\nGenerated files:\n";
        std::cout << "  - " << txtPath << "\n";
        if (config.format == "json" || config.format == "all") {
            std::cout << "  - " << jsonPath << "\n";
        }
        if (config.format == "xml" || config.format == "all") {
            std::cout << "  - " << xmlPath << "\n";
        }
        std::cout << "  - " << shPath << "\n";
        std::cout << "  - " << pyPath << "\n";
        std::cout << "  - " << cPath << "\n";
    }
    
    std::cout << "\n=== Done ===\n";
    
    return 0;
}
