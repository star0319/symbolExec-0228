#ifndef TEST_CASE_GENERATOR_H
#define TEST_CASE_GENERATOR_H

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <z3/z3++.h>
#include "State.h"
#include "PathConstraint.h"
#include "SymbolicExecutor.h"

namespace symexec {

// Test case input format
enum class InputFormat {
    BINARY,     // Raw binary input
    TEXT,       // Text/string input
    STRUCTURED, // Structured (JSON, XML, etc.)
    CUSTOM      // Custom format
};

// Single test input value
struct TestInput {
    std::string name;
    uint64_t address;     // Memory address or register
    size_t size;          // Size in bytes
    std::vector<uint8_t> concreteValue;
    bool isSymbolic;
    std::string symbolicName;
    
    TestInput() : address(0), size(0), isSymbolic(false) {}
    
    std::string toString() const;
    std::string toHex() const;
    std::string toStringValue() const;
};

// Complete test case for one path
struct TestCase {
    uint64_t pathId;
    std::string pathDescription;
    std::vector<TestInput> inputs;
    std::vector<uint64_t> branchAddresses;
    std::vector<bool> branchDecisions;
    z3::model solutionModel;
    bool isFeasible;
    std::string coverageInfo;
    
    TestCase() : pathId(0), isFeasible(true) {}
    
    std::string toString() const;
    std::string toCCode() const;
    std::string toPythonCode() const;
    std::string toJSON() const;
};

// Coverage information
struct CoverageInfo {
    std::set<uint64_t> coveredBlocks;
    std::set<uint64_t> coveredEdges;
    std::set<uint64_t> coveredFunctions;
    double blockCoverage;
    double edgeCoverage;
    double functionCoverage;
    
    CoverageInfo() : blockCoverage(0), edgeCoverage(0), functionCoverage(0) {}
    
    std::string toString() const;
};

// Test case generator
class TestCaseGenerator {
public:
    TestCaseGenerator();
    explicit TestCaseGenerator(z3::context& ctx);
    ~TestCaseGenerator() = default;
    
    // Generate test cases from execution states
    std::vector<TestCase> generateFromStates(
        const std::vector<ExecutionState*>& states);
    
    // Generate test case from single state
    TestCase generateFromState(ExecutionState* state);
    
    // Extract concrete inputs from model
    std::vector<TestInput> extractInputs(
        ExecutionState* state, 
        z3::model& model);
    
    // Generate test file
    void writeTestFile(const std::string& filepath, 
                       const std::vector<TestCase>& testCases,
                       const std::string& format = "txt");
    
    // Generate C test harness
    void generateCHarness(const std::string& filepath,
                          const std::vector<TestCase>& testCases,
                          const std::string& functionName = "target");
    
    // Generate Python test script
    void generatePythonScript(const std::string& filepath,
                              const std::vector<TestCase>& testCases,
                              const std::string& binaryPath = "");
    
    // Generate shell script for testing
    void generateShellScript(const std::string& filepath,
                             const std::vector<TestCase>& testCases,
                             const std::string& binaryPath = "");
    
    // Calculate coverage
    CoverageInfo calculateCoverage(
        const std::vector<TestCase>& testCases,
        const ControlFlowGraph& cfg);
    
    // Get test case statistics
    struct TestCaseStats {
        size_t totalTestCases;
        size_t feasibleTestCases;
        size_t infeasibleTestCases;
        size_t totalInputs;
        size_t uniquePaths;
        double avgPathLength;
        
        TestCaseStats() : totalTestCases(0), feasibleTestCases(0),
                          infeasibleTestCases(0), totalInputs(0),
                          uniquePaths(0), avgPathLength(0) {}
        
        std::string toString() const;
    };
    
    TestCaseStats calculateStats(const std::vector<TestCase>& testCases) const;
    
    // Export test cases in various formats
    std::string toXML(const std::vector<TestCase>& testCases) const;
    std::string toJSON(const std::vector<TestCase>& testCases) const;
    std::string toCSV(const std::vector<TestCase>& testCases) const;
    
    // Set input format preference
    void setInputFormat(InputFormat format) { inputFormat = format; }
    
    // Filter test cases
    std::vector<TestCase> filterByCoverage(
        const std::vector<TestCase>& testCases,
        uint64_t minCoverage);
    
    std::vector<TestCase> filterByPathLength(
        const std::vector<TestCase>& testCases,
        size_t minLength, size_t maxLength);
    
    // Minimize test cases (remove redundant inputs)
    std::vector<TestCase> minimizeTestCases(
        const std::vector<TestCase>& testCases);

private:
    z3::context* ctx;
    InputFormat inputFormat;
    
    // Helper methods
    std::vector<uint8_t> extractConcreteValue(z3::model& model, 
                                               z3::expr& expr,
                                               size_t size);
    std::string formatBytes(const std::vector<uint8_t>& bytes) const;
    void escapeString(std::string& str) const;
};

// Test runner - executes test cases against binary
class TestRunner {
public:
    TestRunner(const std::string& binaryPath);
    ~TestRunner();
    
    // Run single test case
    bool runTestCase(const TestCase& testCase, int timeout = 5);
    
    // Run all test cases
    struct TestResults {
        size_t total;
        size_t passed;
        size_t failed;
        size_t crashed;
        size_t timeout;
        std::vector<std::pair<TestCase, std::string>> failures;
        
        std::string toString() const;
    };
    
    TestResults runAllTests(const std::vector<TestCase>& testCases,
                            int timeout = 5);
    
    // Check if input causes crash
    bool causesCrash(const std::vector<uint8_t>& input, int timeout = 5);
    
    // Get crash information
    std::string getCrashInfo() const { return crashInfo; }
    
    // Set working directory
    void setWorkDir(const std::string& dir) { workDir = dir; }
    
    // Set environment variables
    void setEnv(const std::map<std::string, std::string>& env) { environment = env; }

private:
    std::string binaryPath;
    std::string workDir;
    std::string crashInfo;
    std::map<std::string, std::string> environment;
};

} // namespace symexec

#endif // TEST_CASE_GENERATOR_H
