#ifndef STATE_H
#define STATE_H

#include <string>
#include <vector>
#include <map>
#include <set>
#include <cstdint>
#include <memory>
#include <z3/z3++.h>
#include "MemoryModel.h"
#include "Disassembler.h"

namespace symexec {

// Execution state type
enum class StateType {
    ACTIVE,      // Currently executing
    SUSPENDED,   // Waiting in worklist
    TERMINATED,  // Execution finished
    FORKED       // State was forked
};

// Call stack frame
struct StackFrame {
    uint64_t returnAddress;
    uint64_t basePointer;
    uint64_t stackPointer;
    std::string functionName;
    std::map<std::string, SymbolicValue> locals;
    
    StackFrame() : returnAddress(0), basePointer(0), stackPointer(0) {}
    StackFrame(uint64_t retAddr, uint64_t baseAddr, uint64_t stackAddr)
        : returnAddress(retAddr), basePointer(baseAddr), stackPointer(stackAddr) {}
};

// Execution state - represents a single path through the program
class ExecutionState {
public:
    ExecutionState();
    explicit ExecutionState(z3::context& ctx);
    ~ExecutionState() = default;
    
    // State identification
    uint64_t getId() const { return stateId; }
    void setId(uint64_t id) { stateId = id; }
    
    StateType getStateType() const { return stateType; }
    void setStateType(StateType type) { stateType = type; }
    
    // Register file access
    RegisterFile& getRegisters() { return registers; }
    const RegisterFile& getRegisters() const { return registers; }
    void setRegisters(const RegisterFile& regs) { registers = regs; }
    
    // Memory access
    MemoryModel& getMemory() { return memory; }
    const MemoryModel& getMemory() const { return memory; }
    void setMemory(const MemoryModel& mem) { memory = mem; }
    
    // Path constraints
    void addConstraint(const z3::expr& constraint);
    void addConstraint(const SymbolicValue& value);
    std::vector<z3::expr> getConstraints() const { return pathConstraints; }
    z3::expr getAllConstraints() const;
    
    // Call stack
    void pushFrame(const StackFrame& frame) { callStack.push_back(frame); }
    StackFrame popFrame();
    StackFrame& getCurrentFrame() { return callStack.back(); }
    const StackFrame& getCurrentFrame() const { return callStack.back(); }
    bool hasFrame() const { return !callStack.empty(); }
    size_t getStackDepth() const { return callStack.size(); }
    
    // Program counter
    uint64_t getPC() const;
    void setPC(uint64_t addr);
    void setPC(const SymbolicValue& addr);
    
    // Symbolic inputs tracking
    void addSymbolicInput(const std::string& name, const SymbolicValue& value);
    std::map<std::string, SymbolicValue> getSymbolicInputs() const { return symbolicInputs; }
    
    // Execution history (for debugging and statistics)
    void recordInstruction(uint64_t addr, const std::string& mnemonic);
    std::vector<std::pair<uint64_t, std::string>> getHistory() const { return executionHistory; }
    size_t getInstructionCount() const { return executionHistory.size(); }
    
    // Fork this state (create a copy)
    ExecutionState fork() const;
    
    // Clone state
    ExecutionState clone() const;
    
    // Check if state is feasible (constraints are satisfiable)
    bool isFeasible(z3::solver& solver) const;
    
    // Get depth (number of branches taken)
    size_t getDepth() const { return branchDepth; }
    void incrementDepth() { branchDepth++; }
    
    // String representation
    std::string toString() const;
    std::string dump() const;

private:
    uint64_t stateId;
    StateType stateType;
    RegisterFile registers;
    MemoryModel memory;
    std::vector<z3::expr> pathConstraints;
    std::vector<StackFrame> callStack;
    std::map<std::string, SymbolicValue> symbolicInputs;
    std::vector<std::pair<uint64_t, std::string>> executionHistory;
    size_t branchDepth;
    static uint64_t nextId;
};

// State manager - manages all execution states
class StateManager {
public:
    StateManager();
    explicit StateManager(z3::context& ctx);
    ~StateManager() = default;
    
    // Create new state
    ExecutionState& createState();
    
    // Add state to worklist
    void addToWorklist(ExecutionState* state);
    
    // Get next state from worklist (for BFS/DFS)
    ExecutionState* getNextState();
    
    // Remove state
    void removeState(ExecutionState* state);
    
    // Check if there are more states to explore
    bool hasWork() const { return !worklist.empty(); }
    
    // Get all active states
    std::vector<ExecutionState*> getActiveStates();
    
    // Get all states
    std::vector<ExecutionState*> getAllStates() { return allStates; }
    
    // Get state by ID
    ExecutionState* getStateById(uint64_t id);
    
    // Statistics
    size_t getWorklistSize() const { return worklist.size(); }
    size_t getTotalStates() const { return allStates.size(); }
    size_t getTerminatedStates() const;
    size_t getActiveStateCount() const;
    
    // Search strategy
    enum class SearchStrategy {
        BFS,  // Breadth-first
        DFS,  // Depth-first
        RANDOM // Random
    };
    
    void setSearchStrategy(SearchStrategy strategy) { searchStrategy = strategy; }
    
    // State pruning
    void pruneInfeasibleStates(z3::solver& solver);
    
    // Clear all states
    void clear();

private:
    std::vector<ExecutionState*> allStates;
    std::vector<ExecutionState*> worklist;
    SearchStrategy searchStrategy;
    z3::context* ctx;
    uint64_t stateCounter;
};

} // namespace symexec

#endif // STATE_H
