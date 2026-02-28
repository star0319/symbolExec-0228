#ifndef SYMBOLIC_EXECUTOR_H
#define SYMBOLIC_EXECUTOR_H

#include <string>
#include <vector>
#include <map>
#include <set>
#include <cstdint>
#include <functional>
#include <z3++.h>
#include "ELFParser.h"
#include "Disassembler.h"
#include "CFGBuilder.h"
#include "MemoryModel.h"
#include "State.h"
#include "PathConstraint.h"

namespace symexec {

// Execution result
enum class ExecResult {
    SUCCESS,
    CONFLICT,
    TIMEOUT,
    ERROR,
    MAX_DEPTH_REACHED,
    MAX_STATES_REACHED
};

// Execution event types
enum class EventType {
    INSTRUCTION_EXECUTED,
    BRANCH_TAKEN,
    STATE_FORKED,
    STATE_MERGED,
    CONSTRAINT_ADDED,
    SYMBOLIC_READ,
    SYMBOLIC_WRITE,
    FUNCTION_CALL,
    FUNCTION_RETURN,
    PATH_TERMINATED
};

// Event callback type
using EventCallback = std::function<void(ExecutionState&, EventType, const std::string&)>;

// Symbolic execution configuration
struct SymExecConfig {
    size_t maxDepth;           // Maximum branch depth
    size_t maxInstructions;    // Maximum instructions per path
    size_t maxStates;          // Maximum concurrent states
    size_t timeout;            // Timeout in seconds
    bool exploreAllPaths;      // Whether to explore all paths
    bool mergeStates;          // Whether to merge equivalent states
    bool generateTestCases;    // Whether to generate test cases
    std::set<uint64_t> targetAddresses;  // Target addresses to reach
    std::set<std::string> symbolicInputs; // Names of symbolic inputs
    
    SymExecConfig() 
        : maxDepth(50), maxInstructions(10000), maxStates(1000),
          timeout(60), exploreAllPaths(true), mergeStates(false),
          generateTestCases(true) {}
};

// Execution statistics
struct ExecutionStats {
    uint64_t totalStates;
    uint64_t exploredPaths;
    uint64_t totalInstructions;
    uint64_t totalBranches;
    uint64_t feasibleBranches;
    uint64_t infeasibleBranches;
    uint64_t symbolicReads;
    uint64_t symbolicWrites;
    uint64_t solverQueries;
    uint64_t solverSat;
    uint64_t solverUnsat;
    double totalTime;
    double avgPathLength;
    
    ExecutionStats() 
        : totalStates(0), exploredPaths(0), totalInstructions(0),
          totalBranches(0), feasibleBranches(0), infeasibleBranches(0),
          symbolicReads(0), symbolicWrites(0), solverQueries(0),
          solverSat(0), solverUnsat(0), totalTime(0), avgPathLength(0) {}
    
    std::string toString() const;
};

// Main symbolic execution engine
class SymbolicExecutor {
public:
    SymbolicExecutor();
    ~SymbolicExecutor();
    
    // Load binary file
    bool loadBinary(const std::string& filepath);
    
    // Initialize execution state
    void initializeState(ExecutionState& state);
    
    // Set configuration
    void setConfig(const SymExecConfig& config) { cfg = config; }
    const SymExecConfig& getConfig() const { return cfg; }
    
    // Register event callback
    void registerCallback(EventType type, EventCallback callback);
    
    // Execute symbolically
    ExecResult execute();
    ExecResult executeFrom(uint64_t startAddr, uint64_t endAddr = 0);
    
    // Execute single instruction in state
    ExecResult executeInstruction(ExecutionState& state);
    
    // Execute single step (one instruction)
    ExecResult step(ExecutionState& state);
    
    // Stop execution
    void stop() { running = false; }
    bool isRunning() const { return running; }
    
    // Get current state
    ExecutionState* getCurrentState() { return currentState; }
    
    // Get all terminated states (for test case generation)
    std::vector<ExecutionState*> getTerminatedStates() const;
    
    // Get statistics
    const ExecutionStats& getStats() const { return stats; }
    
    // Get Z3 context
    z3::context& getZ3Context() { return ctx; }
    z3::solver& getSolver() { return solver; }
    
    // Make input symbolic
    void makeInputSymbolic(const std::string& name, uint64_t addr, size_t size = 8);
    void makeRegisterSymbolic(const std::string& name, const std::string& reg);
    
    // Add path constraint
    void addPathConstraint(const z3::expr& constraint);
    
    // Check if address is a branch
    bool isBranchAddress(uint64_t addr) const;
    
    // Get CFG
    const ControlFlowGraph& getCFG() const { return cfgGraph; }
    
    // Get ELF info
    const ELFInfo& getELFInfo() const { return elfInfo; }
    
    // Export execution trace
    std::string getExecutionTrace() const;
    
    // Print statistics
    void printStats() const;

private:
    // Binary loading
    ELFInfo elfInfo;
    std::vector<uint8_t> binaryData;
    ControlFlowGraph cfgGraph;
    Disassembler disassembler;
    CFGBuilder cfgBuilder;
    
    // Symbolic execution state
    z3::context ctx;
    z3::solver solver;
    StateManager stateManager;
    ExecutionState* currentState;
    PathConstraintManager constraintManager;
    
    // Configuration
    SymExecConfig cfg;
    ExecutionStats stats;
    
    // Execution control
    bool running;
    bool initialized;
    uint64_t instructionCount;
    
    // Event callbacks
    std::map<EventType, std::vector<EventCallback>> callbacks;
    
    // Symbolic inputs
    std::map<std::string, SymbolicValue> symbolicInputs;
    
    // Helper methods
    void emitEvent(EventType type, const std::string& data);
    bool checkFeasibility(const z3::expr& constraint);
    void forkState(ExecutionState& state, const z3::expr& condition,
                   uint64_t trueTarget, uint64_t falseTarget);
    ExecResult handleBranch(ExecutionState& state, const Instruction& inst);
    ExecResult handleCall(ExecutionState& state, const Instruction& inst);
    ExecResult handleReturn(ExecutionState& state, const Instruction& inst);
    ExecResult handleMemoryRead(ExecutionState& state, const Instruction& inst);
    ExecResult handleMemoryWrite(ExecutionState& state, const Instruction& inst);
    ExecResult handleArithmetic(ExecutionState& state, const Instruction& inst);
    ExecResult handleMove(ExecutionState& state, const Instruction& inst);
    ExecResult handleCompare(ExecutionState& state, const Instruction& inst);
    
    // Instruction handlers
    void executeMOV(ExecutionState& state, const Instruction& inst);
    void executeADD(ExecutionState& state, const Instruction& inst);
    void executeSUB(ExecutionState& state, const Instruction& inst);
    void executeMUL(ExecutionState& state, const Instruction& inst);
    void executeDIV(ExecutionState& state, const Instruction& inst);
    void executeAND(ExecutionState& state, const Instruction& inst);
    void executeOR(ExecutionState& state, const Instruction& inst);
    void executeXOR(ExecutionState& state, const Instruction& inst);
    void executeSHL(ExecutionState& state, const Instruction& inst);
    void executeSHR(ExecutionState& state, const Instruction& inst);
    void executeCMP(ExecutionState& state, const Instruction& inst);
    void executeTEST(ExecutionState& state, const Instruction& inst);
    void executePUSH(ExecutionState& state, const Instruction& inst);
    void executePOP(ExecutionState& state, const Instruction& inst);
    void executeLEA(ExecutionState& state, const Instruction& inst);
    void executeJMP(ExecutionState& state, const Instruction& inst);
    void executeJcc(ExecutionState& state, const Instruction& inst);
    void executeCALL(ExecutionState& state, const Instruction& inst);
    void executeRET(ExecutionState& state, const Instruction& inst);
    void executeNOP(ExecutionState& state, const Instruction& inst);
    
    // Utility
    SymbolicValue getOperandValue(ExecutionState& state, const Operand& op);
    void setOperandValue(ExecutionState& state, const Operand& op, const SymbolicValue& val);
    uint64_t resolveMemoryAddress(ExecutionState& state, const Operand& op);
    void updateFlags(ExecutionState& state, const SymbolicValue& result, 
                     const SymbolicValue& left, const SymbolicValue& right);
    
    // Path management
    void recordPath(ExecutionState& state);
    bool shouldTerminate(const ExecutionState& state) const;
};

} // namespace symexec

#endif // SYMBOLIC_EXECUTOR_H
