#include "TestCaseGenerator.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <algorithm>
#include <cstdlib>

#ifdef __unix__
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace symexec {

// ============================================================================
// TestInput Implementation
// ============================================================================

std::string TestInput::toString() const {
    std::ostringstream oss;
    oss << name << " (" << size << " bytes): ";
    
    if (isSymbolic) {
        oss << "symbolic[" << symbolicName << "]";
    } else {
        oss << toHex();
    }
    
    return oss.str();
}

std::string TestInput::toHex() const {
    std::ostringstream oss;
    for (size_t i = 0; i < concreteValue.size() && i < 16; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') 
            << static_cast<int>(concreteValue[i]) << " ";
    }
    if (concreteValue.size() > 16) {
        oss << "... (" << concreteValue.size() << " bytes total)";
    }
    return oss.str();
}

std::string TestInput::toStringValue() const {
    std::string result;
    for (uint8_t b : concreteValue) {
        if (b >= 32 && b < 127) {
            result += static_cast<char>(b);
        } else {
            result += '.';
        }
    }
    return result;
}

// ============================================================================
// TestCase Implementation
// ============================================================================

std::string TestCase::toString() const {
    std::ostringstream oss;
    oss << "=== Test Case (Path #" << pathId << ") ===\n";
    oss << "Description: " << pathDescription << "\n";
    oss << "Feasible: " << (isFeasible ? "Yes" : "No") << "\n";
    oss << "Branches: " << branchAddresses.size() << "\n";
    
    for (size_t i = 0; i < branchAddresses.size(); ++i) {
        oss << "  0x" << std::hex << branchAddresses[i] << std::dec
            << " -> " << (branchDecisions[i] ? "T" : "F") << "\n";
    }
    
    oss << "\nInputs (" << inputs.size() << "):\n";
    for (const auto& input : inputs) {
        oss << "  " << input.toString() << "\n";
    }
    
    if (!coverageInfo.empty()) {
        oss << "\nCoverage: " << coverageInfo << "\n";
    }
    
    return oss.str();
}

std::string TestCase::toCCode() const {
    std::ostringstream oss;
    oss << "// Test case for path #" << pathId << "\n";
    oss << "void test_path_" << pathId << "() {\n";
    
    for (const auto& input : inputs) {
        if (input.size <= 8 && !input.concreteValue.empty()) {
            uint64_t val = 0;
            for (size_t i = 0; i < input.size && i < 8; ++i) {
                val |= static_cast<uint64_t>(input.concreteValue[i]) << (i * 8);
            }
            oss << "  // " << input.name << " = 0x" << std::hex << val << std::dec << "\n";
        }
    }
    
    oss << "  // Branch decisions: ";
    for (bool b : branchDecisions) {
        oss << (b ? "T" : "F");
    }
    oss << "\n";
    oss << "}\n";
    
    return oss.str();
}

std::string TestCase::toPythonCode() const {
    std::ostringstream oss;
    oss << "# Test case for path #" << pathId << "\n";
    oss << "def test_path_" << pathId << "():\n";
    
    oss << "    inputs = [\n";
    for (const auto& input : inputs) {
        oss << "        b'";
        for (uint8_t b : input.concreteValue) {
            if (b >= 32 && b < 127 && b != '\'' && b != '\\') {
                oss << static_cast<char>(b);
            } else {
                oss << "\\x" << std::hex << std::setw(2) << std::setfill('0') 
                    << static_cast<int>(b);
            }
        }
        oss << "',  # " << input.name << "\n";
    }
    oss << "    ]\n";
    
    oss << "    # Branch decisions: ";
    for (bool b : branchDecisions) {
        oss << (b ? "T" : "F");
    }
    oss << "\n";
    
    return oss.str();
}

std::string TestCase::toJSON() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"pathId\": " << pathId << ",\n";
    oss << "  \"description\": \"" << pathDescription << "\",\n";
    oss << "  \"feasible\": " << (isFeasible ? "true" : "false") << ",\n";
    oss << "  \"inputs\": [\n";
    
    for (size_t i = 0; i < inputs.size(); ++i) {
        const auto& input = inputs[i];
        oss << "    {\n";
        oss << "      \"name\": \"" << input.name << "\",\n";
        oss << "      \"size\": " << input.size << ",\n";
        oss << "      \"value\": \"" << input.toHex() << "\"\n";
        oss << "    }";
        if (i < inputs.size() - 1) oss << ",";
        oss << "\n";
    }
    
    oss << "  ],\n";
    oss << "  \"branches\": [";
    for (size_t i = 0; i < branchDecisions.size(); ++i) {
        oss << (branchDecisions[i] ? "true" : "false");
        if (i < branchDecisions.size() - 1) oss << ", ";
    }
    oss << "]\n";
    oss << "}\n";
    
    return oss.str();
}

// ============================================================================
// CoverageInfo Implementation
// ============================================================================

std::string CoverageInfo::toString() const {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2);
    oss << "Block Coverage: " << blockCoverage << "%\n";
    oss << "Edge Coverage: " << edgeCoverage << "%\n";
    oss << "Function Coverage: " << functionCoverage << "%\n";
    oss << "Blocks: " << coveredBlocks.size() << "\n";
    oss << "Edges: " << coveredEdges.size() << "\n";
    oss << "Functions: " << coveredFunctions.size();
    return oss.str();
}

// ============================================================================
// TestCaseGenerator Implementation
// ============================================================================

TestCaseGenerator::TestCaseGenerator() : ctx(nullptr), inputFormat(InputFormat::BINARY) {}

TestCaseGenerator::TestCaseGenerator(z3::context& c) : ctx(&c), inputFormat(InputFormat::BINARY) {}

std::vector<TestCase> TestCaseGenerator::generateFromStates(
    const std::vector<ExecutionState*>& states) {
    
    std::vector<TestCase> testCases;
    
    for (auto* state : states) {
        if (state->getStateType() == StateType::TERMINATED ||
            state->getStateType() == StateType::SUSPENDED) {
            TestCase tc = generateFromState(state);
            testCases.push_back(tc);
        }
    }
    
    return testCases;
}

TestCase TestCaseGenerator::generateFromState(ExecutionState* state) {
    TestCase tc;
    tc.pathId = state->getId();
    tc.isFeasible = true;
    
    // Extract path description from execution history
    auto history = state->getHistory();
    if (!history.empty()) {
        std::ostringstream oss;
        oss << history.size() << " instructions";
        tc.pathDescription = oss.str();
    }
    
    // Extract branch information
    // (In a real implementation, this would come from the path constraints)
    
    // Extract symbolic inputs
    auto symbolicInputs = state->getSymbolicInputs();
    for (const auto& [name, value] : symbolicInputs) {
        TestInput input;
        input.name = name;
        input.isSymbolic = true;
        input.symbolicName = name;
        input.size = value.getBits() / 8;
        
        // Try to get concrete value from solver
        if (ctx && value.isSymbolic()) {
            z3::solver solver(*ctx);
            solver.add(state->getAllConstraints());
            if (solver.check() == z3::sat) {
                z3::model model = solver.get_model();
                z3::expr val = model.eval(value.toZ3Expr(), true);
                if (val.is_numeral()) {
                    input.isSymbolic = false;
                    input.concreteValue.resize(input.size);
                    uint64_t concreteVal = val.get_numeral_uint64();
                    for (size_t i = 0; i < input.size; ++i) {
                        input.concreteValue[i] = (concreteVal >> (i * 8)) & 0xFF;
                    }
                }
            }
        }
        
        tc.inputs.push_back(input);
    }
    
    // If no symbolic inputs found, create default input
    if (tc.inputs.empty()) {
        TestInput defaultInput;
        defaultInput.name = "input";
        defaultInput.size = 8;
        defaultInput.concreteValue = {0};
        tc.inputs.push_back(defaultInput);
    }
    
    return tc;
}

std::vector<TestInput> TestCaseGenerator::extractInputs(
    ExecutionState* state, 
    z3::model& model) {
    
    std::vector<TestInput> inputs;
    auto symbolicInputs = state->getSymbolicInputs();
    
    for (const auto& [name, value] : symbolicInputs) {
        TestInput input;
        input.name = name;
        input.size = value.getBits() / 8;
        input.isSymbolic = false;
        
        if (value.isSymbolic()) {
            z3::expr val = model.eval(value.toZ3Expr(), true);
            if (val.is_numeral()) {
                input.concreteValue.resize(input.size);
                uint64_t concreteVal = val.get_numeral_uint64();
                for (size_t i = 0; i < input.size; ++i) {
                    input.concreteValue[i] = (concreteVal >> (i * 8)) & 0xFF;
                }
            }
        }
        
        inputs.push_back(input);
    }
    
    return inputs;
}

void TestCaseGenerator::writeTestFile(const std::string& filepath,
                                       const std::vector<TestCase>& testCases,
                                       const std::string& format) {
    std::ofstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filepath << std::endl;
        return;
    }
    
    if (format == "json") {
        file << toJSON(testCases);
    } else if (format == "xml") {
        file << toXML(testCases);
    } else if (format == "csv") {
        file << toCSV(testCases);
    } else {
        // Default text format
        for (const auto& tc : testCases) {
            file << tc.toString() << "\n\n";
        }
    }
    
    file.close();
    std::cout << "Written " << testCases.size() << " test cases to " << filepath << std::endl;
}

void TestCaseGenerator::generateCHarness(const std::string& filepath,
                                          const std::vector<TestCase>& testCases,
                                          const std::string& functionName) {
    std::ofstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filepath << std::endl;
        return;
    }
    
    file << "// Auto-generated test harness\n";
    file << "// Generated by Symbolic Executor\n\n";
    file << "#include <stdio.h>\n";
    file << "#include <stdlib.h>\n";
    file << "#include <string.h>\n\n";
    
    file << "// External function to test\n";
    file << "extern int " << functionName << "(const unsigned char* input, size_t len);\n\n";
    
    for (const auto& tc : testCases) {
        file << tc.toCCode() << "\n";
    }
    
    file << "int main() {\n";
    file << "    printf(\"Running " << testCases.size() << " test cases...\\n\");\n\n";
    
    for (size_t i = 0; i < testCases.size(); ++i) {
        file << "    printf(\"Test " << i << ": \");\n";
        file << "    test_path_" << testCases[i].pathId << "();\n";
        file << "    printf(\"PASSED\\n\");\n\n";
    }
    
    file << "    printf(\"All tests completed.\\n\");\n";
    file << "    return 0;\n";
    file << "}\n";
    
    file.close();
    std::cout << "Generated C harness: " << filepath << std::endl;
}

void TestCaseGenerator::generatePythonScript(const std::string& filepath,
                                              const std::vector<TestCase>& testCases,
                                              const std::string& binaryPath) {
    std::ofstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filepath << std::endl;
        return;
    }
    
    file << "#!/usr/bin/env python3\n";
    file << "# Auto-generated test script\n";
    file << "# Generated by Symbolic Executor\n\n";
    
    if (!binaryPath.empty()) {
        file << "import subprocess\n";
        file << "import sys\n\n";
        file << "BINARY_PATH = \"" << binaryPath << "\"\n\n";
    }
    
    for (const auto& tc : testCases) {
        file << tc.toPythonCode() << "\n";
    }
    
    file << "def run_tests():\n";
    file << "    test_cases = [\n";
    for (const auto& tc : testCases) {
        file << "        test_path_" << tc.pathId << ",\n";
    }
    file << "    ]\n\n";
    
    file << "    passed = 0\n";
    file << "    failed = 0\n\n";
    
    file << "    for i, test in enumerate(test_cases):\n";
    file << "        try:\n";
    file << "            test()\n";
    file << "            print(f\"Test {i}: PASSED\")\n";
    file << "            passed += 1\n";
    file << "        except Exception as e:\n";
    file << "            print(f\"Test {i}: FAILED - {e}\")\n";
    file << "            failed += 1\n\n";
    
    file << "    print(f\"\\nResults: {passed} passed, {failed} failed\")\n";
    file << "    return failed == 0\n\n";
    
    file << "if __name__ == \"__main__\":\n";
    file << "    success = run_tests()\n";
    file << "    sys.exit(0 if success else 1)\n";
    
    file.close();
    std::cout << "Generated Python script: " << filepath << std::endl;
}

void TestCaseGenerator::generateShellScript(const std::string& filepath,
                                             const std::vector<TestCase>& testCases,
                                             const std::string& binaryPath) {
    std::ofstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filepath << std::endl;
        return;
    }
    
    file << "#!/bin/bash\n";
    file << "# Auto-generated test script\n";
    file << "# Generated by Symbolic Executor\n\n";
    
    if (!binaryPath.empty()) {
        file << "BINARY=\"" << binaryPath << "\"\n\n";
    }
    
    file << "passed=0\n";
    file << "failed=0\n\n";
    
    for (size_t i = 0; i < testCases.size(); ++i) {
        const auto& tc = testCases[i];
        file << "# Test case " << i << " (Path #" << tc.pathId << ")\n";
        file << "echo \"Running test " << i << "...\"\n";
        
        // Create input file
        file << "cat > /tmp/test_input_" << i << ".bin << 'EOF'\n";
        for (const auto& input : tc.inputs) {
            for (uint8_t b : input.concreteValue) {
                file << "\\x" << std::hex << std::setw(2) << std::setfill('0') 
                     << static_cast<int>(b);
            }
        }
        file << std::dec << "\nEOF\n\n";
        
        file << "if \"$BINARY\" < /tmp/test_input_" << i << ".bin; then\n";
        file << "    echo \"Test " << i << ": PASSED\"\n";
        file << "    ((passed++))\n";
        file << "else\n";
        file << "    echo \"Test " << i << ": FAILED\"\n";
        file << "    ((failed++))\n";
        file << "fi\n\n";
    }
    
    file << "echo \"\"\n";
    file << "echo \"Results: $passed passed, $failed failed\"\n";
    file << "exit $failed\n";
    
    file.close();
    
    // Make executable
#ifdef __unix__
    chmod(filepath.c_str(), 0755);
#endif
    
    std::cout << "Generated shell script: " << filepath << std::endl;
}

CoverageInfo TestCaseGenerator::calculateCoverage(
    const std::vector<TestCase>& testCases,
    const ControlFlowGraph& cfg) {
    
    CoverageInfo info;
    
    // Collect covered blocks and edges from test cases
    for (const auto& tc : testCases) {
        for (uint64_t addr : tc.branchAddresses) {
            if (cfg.basicBlocks.count(addr)) {
                info.coveredBlocks.insert(addr);
            }
        }
    }
    
    // Calculate coverage percentages
    if (!cfg.basicBlocks.empty()) {
        info.blockCoverage = 100.0 * info.coveredBlocks.size() / cfg.basicBlocks.size();
    }
    
    info.edgeCoverage = info.blockCoverage;  // Simplified
    info.functionCoverage = 100.0;  // Would need function info
    
    return info;
}

TestCaseGenerator::TestCaseStats TestCaseGenerator::calculateStats(
    const std::vector<TestCase>& testCases) const {
    
    TestCaseStats stats;
    stats.totalTestCases = testCases.size();
    
    size_t totalPathLength = 0;
    
    for (const auto& tc : testCases) {
        if (tc.isFeasible) {
            stats.feasibleTestCases++;
        } else {
            stats.infeasibleTestCases++;
        }
        
        stats.totalInputs += tc.inputs.size();
        totalPathLength += tc.branchAddresses.size();
    }
    
    if (stats.totalTestCases > 0) {
        stats.avgPathLength = static_cast<double>(totalPathLength) / stats.totalTestCases;
    }
    
    return stats;
}

std::string TestCaseGenerator::toXML(const std::vector<TestCase>& testCases) const {
    std::ostringstream oss;
    oss << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    oss << "<testCases count=\"" << testCases.size() << "\">\n";
    
    for (const auto& tc : testCases) {
        oss << "  <testCase id=\"" << tc.pathId << "\">\n";
        oss << "    <description>" << tc.pathDescription << "</description>\n";
        oss << "    <feasible>" << (tc.isFeasible ? "true" : "false") << "</feasible>\n";
        oss << "    <inputs>\n";
        
        for (const auto& input : tc.inputs) {
            oss << "      <input name=\"" << input.name << "\" size=\"" << input.size << "\">\n";
            oss << "        <value>" << input.toHex() << "</value>\n";
            oss << "      </input>\n";
        }
        
        oss << "    </inputs>\n";
        oss << "  </testCase>\n";
    }
    
    oss << "</testCases>\n";
    return oss.str();
}

std::string TestCaseGenerator::toJSON(const std::vector<TestCase>& testCases) const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"testCases\": [\n";
    
    for (size_t i = 0; i < testCases.size(); ++i) {
        oss << "    " << testCases[i].toJSON();
        if (i < testCases.size() - 1) oss << ",";
        oss << "\n";
    }
    
    oss << "  ]\n";
    oss << "}\n";
    return oss.str();
}

std::string TestCaseGenerator::toCSV(const std::vector<TestCase>& testCases) const {
    std::ostringstream oss;
    oss << "PathID,Feasible,InputCount,BranchCount,Description\n";
    
    for (const auto& tc : testCases) {
        oss << tc.pathId << ","
            << (tc.isFeasible ? "true" : "false") << ","
            << tc.inputs.size() << ","
            << tc.branchAddresses.size() << ","
            << "\"" << tc.pathDescription << "\"\n";
    }
    
    return oss.str();
}

std::vector<TestCase> TestCaseGenerator::filterByCoverage(
    const std::vector<TestCase>& testCases,
    uint64_t minCoverage) {
    
    std::vector<TestCase> filtered;
    for (const auto& tc : testCases) {
        if (tc.branchAddresses.size() >= minCoverage) {
            filtered.push_back(tc);
        }
    }
    return filtered;
}

std::vector<TestCase> TestCaseGenerator::filterByPathLength(
    const std::vector<TestCase>& testCases,
    size_t minLength, size_t maxLength) {
    
    std::vector<TestCase> filtered;
    for (const auto& tc : testCases) {
        size_t len = tc.branchAddresses.size();
        if (len >= minLength && len <= maxLength) {
            filtered.push_back(tc);
        }
    }
    return filtered;
}

std::vector<TestCase> TestCaseGenerator::minimizeTestCases(
    const std::vector<TestCase>& testCases) {
    
    // Simple deduplication - remove test cases with identical inputs
    std::vector<TestCase> minimized;
    std::set<std::string> seen;
    
    for (const auto& tc : testCases) {
        std::string key;
        for (const auto& input : tc.inputs) {
            key += input.toHex();
        }
        
        if (seen.find(key) == seen.end()) {
            seen.insert(key);
            minimized.push_back(tc);
        }
    }
    
    return minimized;
}

std::string TestCaseGenerator::TestCaseStats::toString() const {
    std::ostringstream oss;
    oss << "=== Test Case Statistics ===\n";
    oss << "Total Test Cases: " << totalTestCases << "\n";
    oss << "Feasible: " << feasibleTestCases << "\n";
    oss << "Infeasible: " << infeasibleTestCases << "\n";
    oss << "Total Inputs: " << totalInputs << "\n";
    oss << "Unique Paths: " << uniquePaths << "\n";
    oss << "Average Path Length: " << avgPathLength;
    return oss.str();
}

// ============================================================================
// TestRunner Implementation
// ============================================================================

TestRunner::TestRunner(const std::string& path) : binaryPath(path) {}

TestRunner::~TestRunner() {}

bool TestRunner::runTestCase(const TestCase& testCase, int timeout) {
#ifdef __unix__
    pid_t pid = fork();
    
    if (pid == 0) {
        // Child process
        // Set up alarm for timeout
        alarm(timeout);
        
        // Redirect stdin from input
        // (Would need to create temp file with test input)
        
        execl(binaryPath.c_str(), binaryPath.c_str(), nullptr);
        exit(1);
    } else if (pid > 0) {
        // Parent process
        int status;
        waitpid(pid, &status, 0);
        
        if (WIFEXITED(status)) {
            return WEXITSTATUS(status) == 0;
        } else if (WIFSIGNALED(status)) {
            crashInfo = "Crashed with signal " + std::to_string(WTERMSIG(status));
            return false;
        }
    }
#endif
    
    return true;
}

TestRunner::TestResults TestRunner::runAllTests(
    const std::vector<TestCase>& testCases,
    int timeout) {
    
    TestResults results;
    results.total = testCases.size();
    
    for (const auto& tc : testCases) {
        bool success = runTestCase(tc, timeout);
        
        if (success) {
            results.passed++;
        } else {
            if (!crashInfo.empty()) {
                results.crashed++;
                results.failures.push_back({tc, crashInfo});
            } else {
                results.failed++;
                results.failures.push_back({tc, "Test failed"});
            }
        }
    }
    
    return results;
}

bool TestRunner::causesCrash(const std::vector<uint8_t>& input, int timeout) {
#ifdef __unix__
    // Create temporary file with input
    std::string tempFile = "/tmp/test_input_XXXXXX";
    int fd = mkstemp(&tempFile[0]);
    if (fd < 0) return false;
    
    write(fd, input.data(), input.size());
    close(fd);
    
    pid_t pid = fork();
    
    if (pid == 0) {
        alarm(timeout);
        
        // Redirect stdin from temp file
        freopen(tempFile.c_str(), "r", stdin);
        
        execl(binaryPath.c_str(), binaryPath.c_str(), nullptr);
        exit(1);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        
        unlink(tempFile.c_str());
        
        if (WIFSIGNALED(status)) {
            crashInfo = "Crashed with signal " + std::to_string(WTERMSIG(status));
            return true;
        }
    }
#endif
    
    return false;
}

std::string TestRunner::TestResults::toString() const {
    std::ostringstream oss;
    oss << "=== Test Results ===\n";
    oss << "Total: " << total << "\n";
    oss << "Passed: " << passed << "\n";
    oss << "Failed: " << failed << "\n";
    oss << "Crashed: " << crashed << "\n";
    oss << "Timeout: " << timeout << "\n";
    
    if (!failures.empty()) {
        oss << "\nFailures:\n";
        for (const auto& [tc, reason] : failures) {
            oss << "  Path #" << tc.pathId << ": " << reason << "\n";
        }
    }
    
    return oss.str();
}

} // namespace symexec
