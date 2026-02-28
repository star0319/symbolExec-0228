#include "State.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <random>
#include <iostream>

namespace symexec {

uint64_t ExecutionState::nextId = 0;

// ============================================================================
// ExecutionState Implementation
// ============================================================================

ExecutionState::ExecutionState() 
    : stateId(nextId++), stateType(StateType::ACTIVE), branchDepth(0) {}

ExecutionState::ExecutionState(z3::context& ctx) 
    : stateId(nextId++), stateType(StateType::ACTIVE), 
      registers(ctx), memory(ctx), branchDepth(0) {}

void ExecutionState::addConstraint(const z3::expr& constraint) {
    pathConstraints.push_back(constraint);
}

void ExecutionState::addConstraint(const SymbolicValue& value) {
    if (value.isSymbolic()) {
        // For symbolic values, we assume they should be non-zero
        pathConstraints.push_back(value.toZ3Expr() != 0);
    }
}

z3::expr ExecutionState::getAllConstraints() const {
    if (pathConstraints.empty()) {
        return z3::bool_val(true);
    }
    
    z3::expr all = pathConstraints[0];
    for (size_t i = 1; i < pathConstraints.size(); ++i) {
        all = all && pathConstraints[i];
    }
    return all;
}

StackFrame ExecutionState::popFrame() {
    if (callStack.empty()) {
        return StackFrame();
    }
    StackFrame frame = callStack.back();
    callStack.pop_back();
    return frame;
}

uint64_t ExecutionState::getPC() const {
    return registers.getInstructionPointer();
}

void ExecutionState::setPC(uint64_t addr) {
    registers.setInstructionPointer(SymbolicValue(addr));
}

void ExecutionState::setPC(const SymbolicValue& addr) {
    registers.setInstructionPointer(addr);
}

void ExecutionState::addSymbolicInput(const std::string& name, const SymbolicValue& value) {
    symbolicInputs[name] = value;
}

void ExecutionState::recordInstruction(uint64_t addr, const std::string& mnemonic) {
    executionHistory.push_back({addr, mnemonic});
    
    // Limit history size to prevent memory issues
    if (executionHistory.size() > 10000) {
        executionHistory.erase(executionHistory.begin());
    }
}

ExecutionState ExecutionState::fork() const {
    ExecutionState newState;
    newState.stateId = nextId++;
    newState.stateType = StateType::SUSPENDED;
    newState.registers = registers.clone();
    newState.memory = memory.clone();
    newState.pathConstraints = pathConstraints;
    newState.callStack = callStack;
    newState.symbolicInputs = symbolicInputs;
    newState.branchDepth = branchDepth;
    return newState;
}

ExecutionState ExecutionState::clone() const {
    return fork();
}

bool ExecutionState::isFeasible(z3::solver& solver) const {
    z3::expr all = getAllConstraints();
    solver.push();
    solver.add(all);
    z3::check_result result = solver.check();
    solver.pop();
    return result == z3::sat;
}

std::string ExecutionState::toString() const {
    std::ostringstream oss;
    oss << "State #" << stateId;
    switch (stateType) {
        case StateType::ACTIVE: oss << " (ACTIVE)"; break;
        case StateType::SUSPENDED: oss << " (SUSPENDED)"; break;
        case StateType::TERMINATED: oss << " (TERMINATED)"; break;
        case StateType::FORKED: oss << " (FORKED)"; break;
    }
    oss << "\n";
    oss << "  PC: 0x" << std::hex << getPC() << std::dec << "\n";
    oss << "  Depth: " << branchDepth << "\n";
    oss << "  Constraints: " << pathConstraints.size() << "\n";
    oss << "  Stack frames: " << callStack.size() << "\n";
    return oss.str();
}

std::string ExecutionState::dump() const {
    std::ostringstream oss;
    oss << "=== Execution State #" << stateId << " ===\n";
    oss << "Type: ";
    switch (stateType) {
        case StateType::ACTIVE: oss << "ACTIVE"; break;
        case StateType::SUSPENDED: oss << "SUSPENDED"; break;
        case StateType::TERMINATED: oss << "TERMINATED"; break;
        case StateType::FORKED: oss << "FORKED"; break;
    }
    oss << "\n\n";
    
    oss << "Registers:\n" << registers.toString() << "\n\n";
    
    oss << "Memory:\n" << memory.toString() << "\n\n";
    
    oss << "Path Constraints (" << pathConstraints.size() << "):\n";
    for (size_t i = 0; i < pathConstraints.size() && i < 10; ++i) {
        oss << "  " << i << ": " << pathConstraints[i] << "\n";
    }
    if (pathConstraints.size() > 10) {
        oss << "  ... and " << (pathConstraints.size() - 10) << " more\n";
    }
    oss << "\n";
    
    oss << "Call Stack (" << callStack.size() << " frames):\n";
    for (size_t i = 0; i < callStack.size(); ++i) {
        const auto& frame = callStack[i];
        oss << "  Frame " << i << ": " << frame.functionName 
            << " @ 0x" << std::hex << frame.returnAddress << std::dec << "\n";
    }
    oss << "\n";
    
    oss << "Symbolic Inputs (" << symbolicInputs.size() << "):\n";
    for (const auto& [name, value] : symbolicInputs) {
        oss << "  " << name << ": " << value.toString() << "\n";
    }
    oss << "\n";
    
    oss << "Execution History (last " << executionHistory.size() << " instructions):\n";
    size_t start = executionHistory.size() > 20 ? executionHistory.size() - 20 : 0;
    for (size_t i = start; i < executionHistory.size(); ++i) {
        oss << "  0x" << std::hex << executionHistory[i].first << std::dec
            << ": " << executionHistory[i].second << "\n";
    }
    
    return oss.str();
}

// ============================================================================
// StateManager Implementation
// ============================================================================

StateManager::StateManager() : searchStrategy(SearchStrategy::DFS), 
                                ctx(nullptr), stateCounter(0) {}

StateManager::StateManager(z3::context& c) : searchStrategy(SearchStrategy::DFS), 
                                              ctx(&c), stateCounter(0) {}

ExecutionState& StateManager::createState() {
    ExecutionState* state = new ExecutionState();
    state->setId(stateCounter++);
    allStates.push_back(state);
    return *state;
}

void StateManager::addToWorklist(ExecutionState* state) {
    if (state) {
        state->setStateType(StateType::SUSPENDED);
        worklist.push_back(state);
    }
}

ExecutionState* StateManager::getNextState() {
    if (worklist.empty()) {
        return nullptr;
    }
    
    ExecutionState* state = nullptr;
    
    switch (searchStrategy) {
        case SearchStrategy::BFS:
            state = worklist.front();
            worklist.erase(worklist.begin());
            break;
            
        case SearchStrategy::DFS:
            state = worklist.back();
            worklist.pop_back();
            break;
            
        case SearchStrategy::RANDOM: {
            static std::random_device rd;
            static std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, worklist.size() - 1);
            size_t idx = dis(gen);
            state = worklist[idx];
            worklist.erase(worklist.begin() + idx);
            break;
        }
    }
    
    if (state) {
        state->setStateType(StateType::ACTIVE);
    }
    
    return state;
}

void StateManager::removeState(ExecutionState* state) {
    if (!state) return;
    
    // Remove from worklist
    auto wit = std::find(worklist.begin(), worklist.end(), state);
    if (wit != worklist.end()) {
        worklist.erase(wit);
    }
    
    // Mark as terminated
    state->setStateType(StateType::TERMINATED);
}

std::vector<ExecutionState*> StateManager::getActiveStates() {
    std::vector<ExecutionState*> active;
    for (auto* state : allStates) {
        if (state->getStateType() == StateType::ACTIVE ||
            state->getStateType() == StateType::SUSPENDED) {
            active.push_back(state);
        }
    }
    return active;
}

ExecutionState* StateManager::getStateById(uint64_t id) {
    for (auto* state : allStates) {
        if (state->getId() == id) {
            return state;
        }
    }
    return nullptr;
}

size_t StateManager::getTerminatedStates() const {
    size_t count = 0;
    for (const auto* state : allStates) {
        if (state->getStateType() == StateType::TERMINATED) {
            count++;
        }
    }
    return count;
}

size_t StateManager::getActiveStateCount() const {
    size_t count = 0;
    for (const auto* state : allStates) {
        if (state->getStateType() == StateType::ACTIVE ||
            state->getStateType() == StateType::SUSPENDED) {
            count++;
        }
    }
    return count;
}

void StateManager::pruneInfeasibleStates(z3::solver& solver) {
    auto it = worklist.begin();
    while (it != worklist.end()) {
        ExecutionState* state = *it;
        if (!state->isFeasible(solver)) {
            state->setStateType(StateType::TERMINATED);
            it = worklist.erase(it);
            std::cout << "Pruned infeasible state #" << state->getId() << std::endl;
        } else {
            ++it;
        }
    }
}

void StateManager::clear() {
    for (auto* state : allStates) {
        delete state;
    }
    allStates.clear();
    worklist.clear();
    stateCounter = 0;
}

} // namespace symexec
