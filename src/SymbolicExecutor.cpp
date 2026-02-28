#include "SymbolicExecutor.h"
#include <iostream>
#include <chrono>
#include <sstream>
#include <algorithm>
#include <iomanip>

namespace symexec {

// ============================================================================
// ExecutionStats Implementation
// ============================================================================

std::string ExecutionStats::toString() const {
    std::ostringstream oss;
    oss << "=== Symbolic Execution Statistics ===\n";
    oss << "Total States Created: " << totalStates << "\n";
    oss << "Explored Paths: " << exploredPaths << "\n";
    oss << "Total Instructions: " << totalInstructions << "\n";
    oss << "Total Branches: " << totalBranches << "\n";
    oss << "  Feasible: " << feasibleBranches << "\n";
    oss << "  Infeasible: " << infeasibleBranches << "\n";
    oss << "Symbolic Memory Operations:\n";
    oss << "  Reads: " << symbolicReads << "\n";
    oss << "  Writes: " << symbolicWrites << "\n";
    oss << "Solver Statistics:\n";
    oss << "  Queries: " << solverQueries << "\n";
    oss << "  SAT: " << solverSat << "\n";
    oss << "  UNSAT: " << solverUnsat << "\n";
    oss << "Time: " << std::fixed << std::setprecision(2) << totalTime << " seconds\n";
    oss << "Average Path Length: " << std::fixed << std::setprecision(2) << avgPathLength << "\n";
    return oss.str();
}

// ============================================================================
// SymbolicExecutor Implementation
// ============================================================================

SymbolicExecutor::SymbolicExecutor() 
    : currentState(nullptr), running(false), initialized(false), 
      instructionCount(0) {
    stateManager = StateManager(ctx);
}

SymbolicExecutor::~SymbolicExecutor() {}

bool SymbolicExecutor::loadBinary(const std::string& filepath) {
    // Parse ELF file
    ELFParser parser;
    elfInfo = parser.parseFile(filepath);
    
    if (!elfInfo.isValid) {
        std::cerr << "Failed to load binary: " << elfInfo.errorMessage << std::endl;
        return false;
    }
    
    // Read binary data
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Failed to open binary file" << std::endl;
        return false;
    }
    
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    binaryData.resize(fileSize);
    file.read(reinterpret_cast<char*>(binaryData.data()), fileSize);
    
    // Initialize disassembler
    disassembler.initialize(elfInfo.machine, elfInfo.elfClass == ELFClass::ELF64);
    
    // Build CFG
    cfgGraph = cfgBuilder.buildCFG(elfInfo, binaryData);
    
    // Setup memory model
    for (const auto& seg : elfInfo.segments) {
        MemoryRegionType type = MemoryRegionType::UNKNOWN;
        if (seg.executable) type = MemoryRegionType::CODE;
        else if (seg.writable) type = MemoryRegionType::GLOBAL;
        
        currentState->getMemory().addRegion(
            seg.vaddr, seg.vaddr + seg.size, type,
            seg.readable, seg.writable, seg.executable
        );
        
        if (!seg.data.empty()) {
            currentState->getMemory().initializeFromBinary(
                seg.vaddr, seg.data.data(), seg.data.size()
            );
        }
    }
    
    // Setup stack
    uint64_t stackBase = 0x7ffff0000000;
    uint64_t stackSize = 0x100000;  // 1MB
    currentState->getMemory().addRegion(
        stackBase - stackSize, stackBase, MemoryRegionType::STACK,
        true, true, false, "[stack]"
    );
    currentState->getRegisters().setStackPointer(SymbolicValue(stackBase - 8));
    
    // Setup heap
    uint64_t heapBase = 0x600000000000;
    uint64_t heapSize = 0x10000000;  // 256MB
    currentState->getMemory().addRegion(
        heapBase, heapBase + heapSize, MemoryRegionType::HEAP,
        true, true, false, "[heap]"
    );
    
    initialized = true;
    std::cout << "Loaded binary: " << filepath << "\n";
    std::cout << "  Architecture: " << ELFParser::getArchitectureString(elfInfo.machine) << "\n";
    std::cout << "  Type: " << ELFParser::getELFTypeString(elfInfo.elfType) << "\n";
    std::cout << "  Entry Point: 0x" << std::hex << elfInfo.entryPoint << std::dec << "\n";
    std::cout << "  Basic Blocks: " << cfgGraph.basicBlocks.size() << "\n";
    
    return true;
}

void SymbolicExecutor::initializeState(ExecutionState& state) {
    // Set entry point
    state.setPC(elfInfo.entryPoint);
    
    // Initialize registers
    auto& regs = state.getRegisters();
    regs.setStackPointer(SymbolicValue(0x7ffff0000000 - 8));
    
    // Setup initial stack frame
    StackFrame frame;
    frame.returnAddress = 0;  // No return address for main
    frame.basePointer = 0x7ffff0000000;
    frame.stackPointer = 0x7ffff0000000 - 8;
    state.pushFrame(frame);
    
    // Setup memory regions
    auto& mem = state.getMemory();
    for (const auto& seg : elfInfo.segments) {
        MemoryRegionType type = MemoryRegionType::UNKNOWN;
        if (seg.executable) type = MemoryRegionType::CODE;
        else if (seg.writable) type = MemoryRegionType::GLOBAL;
        
        mem.addRegion(seg.vaddr, seg.vaddr + seg.size, type,
                      seg.readable, seg.writable, seg.executable);
        
        if (!seg.data.empty()) {
            mem.initializeFromBinary(seg.vaddr, seg.data.data(), seg.data.size());
        }
    }
    
    // Stack region
    uint64_t stackBase = 0x7ffff0000000;
    uint64_t stackSize = 0x100000;
    mem.addRegion(stackBase - stackSize, stackBase, MemoryRegionType::STACK,
                  true, true, false, "[stack]");
    
    // Heap region
    uint64_t heapBase = 0x600000000000;
    uint64_t heapSize = 0x10000000;
    mem.addRegion(heapBase, heapBase + heapSize, MemoryRegionType::HEAP,
                  true, true, false, "[heap]");
}

void SymbolicExecutor::registerCallback(EventType type, EventCallback callback) {
    callbacks[type].push_back(callback);
}

ExecResult SymbolicExecutor::execute() {
    return executeFrom(elfInfo.entryPoint);
}

ExecResult SymbolicExecutor::executeFrom(uint64_t startAddr, uint64_t endAddr) {
    if (!initialized) {
        std::cerr << "Executor not initialized" << std::endl;
        return ExecResult::ERROR;
    }
    
    auto startTime = std::chrono::high_resolution_clock::now();
    running = true;
    
    // Create initial state
    ExecutionState& initialState = stateManager.createState();
    initializeState(initialState);
    initialState.setPC(startAddr);
    stateManager.addToWorklist(&initialState);
    
    stats.totalStates = 1;
    
    // Main execution loop
    while (running && stateManager.hasWork()) {
        // Check timeout
        auto currentTime = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            currentTime - startTime).count();
        if (elapsed > cfg.timeout) {
            std::cout << "Timeout reached (" << cfg.timeout << "s)" << std::endl;
            return ExecResult::TIMEOUT;
        }
        
        // Check max states
        if (stateManager.getTotalStates() >= cfg.maxStates) {
            std::cout << "Maximum states reached (" << cfg.maxStates << ")" << std::endl;
            return ExecResult::MAX_STATES_REACHED;
        }
        
        // Get next state
        currentState = stateManager.getNextState();
        if (!currentState) break;
        
        instructionCount = 0;
        
        // Execute state until termination or branch
        while (running && currentState && 
               instructionCount < cfg.maxInstructions) {
            
            uint64_t pc = currentState->getPC();
            
            // Check if we reached end address
            if (endAddr != 0 && pc == endAddr) {
                stateManager.removeState(currentState);
                stats.exploredPaths++;
                break;
            }
            
            // Check target addresses
            if (!cfg.targetAddresses.empty() && 
                cfg.targetAddresses.count(pc)) {
                std::cout << "Reached target address: 0x" << std::hex << pc << std::dec << std::endl;
            }
            
            // Execute instruction
            ExecResult result = executeInstruction(*currentState);
            
            if (result == ExecResult::ERROR) {
                std::cerr << "Error executing instruction at 0x" << std::hex << pc << std::dec << std::endl;
                stateManager.removeState(currentState);
                break;
            }
            
            instructionCount++;
            stats.totalInstructions++;
        }
    }
    
    running = false;
    
    auto endTime = std::chrono::high_resolution_clock::now();
    stats.totalTime = std::chrono::duration<double>(endTime - startTime).count();
    
    if (stateManager.getTotalStates() > 0) {
        stats.avgPathLength = static_cast<double>(stats.totalInstructions) / 
                              stateManager.getTerminatedStates();
    }
    
    std::cout << "\nSymbolic execution completed.\n";
    std::cout << "States created: " << stateManager.getTotalStates() << "\n";
    std::cout << "Paths explored: " << stats.exploredPaths << "\n";
    
    return ExecResult::SUCCESS;
}

ExecResult SymbolicExecutor::executeInstruction(ExecutionState& state) {
    uint64_t pc = state.getPC();
    
    // Get code section
    auto [code, codeSize] = cfgBuilder.getCodeSection(elfInfo, binaryData);
    if (!code || pc < elfInfo.baseAddr) {
        return ExecResult::ERROR;
    }
    
    size_t offset = pc - elfInfo.baseAddr;
    if (offset >= codeSize) {
        return ExecResult::ERROR;
    }
    
    // Disassemble instruction
    Instruction inst = disassembler.getInstructionAt(code, codeSize, pc, elfInfo.baseAddr);
    
    if (inst.address == 0) {
        std::cerr << "Failed to disassemble at 0x" << std::hex << pc << std::dec << std::endl;
        return ExecResult::ERROR;
    }
    
    // Record instruction
    state.recordInstruction(inst.address, inst.mnemonic + " " + inst.opStr);
    
    emitEvent(EventType::INSTRUCTION_EXECUTED, inst.mnemonic + " " + inst.opStr);
    
    // Execute based on instruction type
    ExecResult result = ExecResult::SUCCESS;
    
    if (inst.isMove && !inst.isMemoryAccess) {
        executeMOV(state, inst);
    } else if (inst.mnemonic == "lea" || inst.mnemonic == "leaq") {
        executeLEA(state, inst);
    } else if (inst.mnemonic == "push" || inst.mnemonic == "pushq") {
        executePUSH(state, inst);
    } else if (inst.mnemonic == "pop" || inst.mnemonic == "popq") {
        executePOP(state, inst);
    } else if (inst.mnemonic == "add" || inst.mnemonic == "addq" || 
               inst.mnemonic == "addl") {
        executeADD(state, inst);
    } else if (inst.mnemonic == "sub" || inst.mnemonic == "subq" ||
               inst.mnemonic == "subl") {
        executeSUB(state, inst);
    } else if (inst.mnemonic == "imul" || inst.mnemonic == "mul") {
        executeMUL(state, inst);
    } else if (inst.mnemonic == "idiv" || inst.mnemonic == "div") {
        executeDIV(state, inst);
    } else if (inst.mnemonic == "and" || inst.mnemonic == "andq" ||
               inst.mnemonic == "andl") {
        executeAND(state, inst);
    } else if (inst.mnemonic == "or" || inst.mnemonic == "orq" ||
               inst.mnemonic == "orl") {
        executeOR(state, inst);
    } else if (inst.mnemonic == "xor" || inst.mnemonic == "xorq" ||
               inst.mnemonic == "xorl") {
        executeXOR(state, inst);
    } else if (inst.mnemonic == "shl" || inst.mnemonic == "shll" ||
               inst.mnemonic == "sal" || inst.mnemonic == "sall") {
        executeSHL(state, inst);
    } else if (inst.mnemonic == "shr" || inst.mnemonic == "shrq" ||
               inst.mnemonic == "shr") {
        executeSHR(state, inst);
    } else if (inst.isCompare) {
        executeCMP(state, inst);
    } else if (inst.mnemonic == "test" || inst.mnemonic == "testq" ||
               inst.mnemonic == "testl") {
        executeTEST(state, inst);
    } else if (inst.mnemonic == "jmp" || inst.mnemonic == "jmpl") {
        executeJMP(state, inst);
    } else if (inst.isBranch && !inst.isCall) {
        executeJcc(state, inst);
    } else if (inst.isCall) {
        executeCALL(state, inst);
    } else if (inst.isReturn) {
        executeRET(state, inst);
    } else if (inst.mnemonic == "nop" || inst.mnemonic == "nopw" ||
               inst.mnemonic == "nopl") {
        executeNOP(state, inst);
    } else {
        // Unknown instruction - skip
        state.setPC(pc + inst.size);
    }
    
    return result;
}

ExecResult SymbolicExecutor::step(ExecutionState& state) {
    return executeInstruction(state);
}

void SymbolicExecutor::makeInputSymbolic(const std::string& name, uint64_t addr, size_t size) {
    SymbolicValue symVal = SymbolicValue::makeSymbolic(ctx, name, size * 8);
    symbolicInputs[name] = symVal;
    
    if (currentState) {
        currentState->addSymbolicInput(name, symVal);
        currentState->getMemory().write(addr, symVal, size);
    }
    
    std::cout << "Made input symbolic: " << name << " at 0x" << std::hex << addr << std::dec << std::endl;
}

void SymbolicExecutor::makeRegisterSymbolic(const std::string& name, const std::string& reg) {
    if (!currentState) return;
    
    SymbolicValue symVal = SymbolicValue::makeSymbolic(ctx, name, 64);
    symbolicInputs[name] = symVal;
    currentState->addSymbolicInput(name, symVal);
    currentState->getRegisters().set(reg, symVal);
    
    std::cout << "Made register symbolic: " << name << " = " << reg << std::endl;
}

void SymbolicExecutor::addPathConstraint(const z3::expr& constraint) {
    if (currentState) {
        currentState->addConstraint(constraint);
        constraintManager.addConstraint(constraint, "");
    }
}

std::vector<ExecutionState*> SymbolicExecutor::getTerminatedStates() const {
    std::vector<ExecutionState*> terminated;
    for (auto* state : stateManager.getAllStates()) {
        if (state->getStateType() == StateType::TERMINATED) {
            terminated.push_back(state);
        }
    }
    return terminated;
}

bool SymbolicExecutor::checkFeasibility(const z3::expr& constraint) {
    stats.solverQueries++;
    
    solver.push();
    solver.add(constraint);
    z3::check_result result = solver.check();
    solver.pop();
    
    if (result == z3::sat) {
        stats.solverSat++;
        return true;
    } else {
        stats.solverUnsat++;
        return false;
    }
}

void SymbolicExecutor::forkState(ExecutionState& state, const z3::expr& condition,
                                  uint64_t trueTarget, uint64_t falseTarget) {
    stats.totalBranches++;
    
    // Check if true branch is feasible
    bool trueFeasible = checkFeasibility(state.getAllConstraints() && condition);
    bool falseFeasible = checkFeasibility(state.getAllConstraints() && !condition);
    
    if (!trueFeasible && !falseFeasible) {
        std::cerr << "Both branches infeasible at 0x" << std::hex << state.getPC() << std::dec << std::endl;
        stateManager.removeState(&state);
        return;
    }
    
    if (trueFeasible && falseFeasible) {
        // Fork: create new state for one branch
        ExecutionState* newState = new ExecutionState(state.fork());
        newState->setId(stateManager.getTotalStates());
        stats.totalStates++;
        
        // Add constraints
        state.addConstraint(condition);
        newState->addConstraint(!condition);
        
        // Set different PCs
        state.setPC(trueTarget);
        newState->setPC(falseTarget);
        
        // Add to worklist
        stateManager.addToWorklist(newState);
        
        emitEvent(EventType::STATE_FORKED, "Fork at 0x" + 
                  std::to_string(state.getPC()));
        
        std::cout << "Forked state #" << newState->getId() 
                  << " at 0x" << std::hex << state.getPC() << std::dec << std::endl;
    } else if (trueFeasible) {
        state.addConstraint(condition);
        state.setPC(trueTarget);
    } else {
        state.addConstraint(!condition);
        state.setPC(falseTarget);
    }
}

ExecResult SymbolicExecutor::handleBranch(ExecutionState& state, const Instruction& inst) {
    // Handled by executeJcc
    return ExecResult::SUCCESS;
}

ExecResult SymbolicExecutor::handleCall(ExecutionState& state, const Instruction& inst) {
    // Handled by executeCALL
    return ExecResult::SUCCESS;
}

ExecResult SymbolicExecutor::handleReturn(ExecutionState& state, const Instruction& inst) {
    // Handled by executeRET
    return ExecResult::SUCCESS;
}

// Instruction implementations
void SymbolicExecutor::executeMOV(ExecutionState& state, const Instruction& inst) {
    if (inst.operands.size() < 2) {
        state.setPC(state.getPC() + inst.size);
        return;
    }
    
    SymbolicValue src = getOperandValue(state, inst.operands[1]);
    setOperandValue(state, inst.operands[0], src);
    state.setPC(state.getPC() + inst.size);
}

void SymbolicExecutor::executeADD(ExecutionState& state, const Instruction& inst) {
    if (inst.operands.size() < 2) {
        state.setPC(state.getPC() + inst.size);
        return;
    }
    
    SymbolicValue dst = getOperandValue(state, inst.operands[0]);
    SymbolicValue src = getOperandValue(state, inst.operands[1]);
    SymbolicValue result = dst.add(src);
    
    setOperandValue(state, inst.operands[0], result);
    updateFlags(state, result, dst, src);
    state.setPC(state.getPC() + inst.size);
}

void SymbolicExecutor::executeSUB(ExecutionState& state, const Instruction& inst) {
    if (inst.operands.size() < 2) {
        state.setPC(state.getPC() + inst.size);
        return;
    }
    
    SymbolicValue dst = getOperandValue(state, inst.operands[0]);
    SymbolicValue src = getOperandValue(state, inst.operands[1]);
    SymbolicValue result = dst.sub(src);
    
    setOperandValue(state, inst.operands[0], result);
    updateFlags(state, result, dst, src);
    state.setPC(state.getPC() + inst.size);
}

void SymbolicExecutor::executeMUL(ExecutionState& state, const Instruction& inst) {
    if (inst.operands.empty()) {
        state.setPC(state.getPC() + inst.size);
        return;
    }
    
    SymbolicValue dst = getOperandValue(state, inst.operands[0]);
    SymbolicValue src = inst.operands.size() > 1 ? 
                        getOperandValue(state, inst.operands[1]) : 
                        state.getRegisters().get("rax");
    
    SymbolicValue result = dst.mul(src);
    setOperandValue(state, inst.operands[0], result);
    state.setPC(state.getPC() + inst.size);
}

void SymbolicExecutor::executeDIV(ExecutionState& state, const Instruction& inst) {
    // Simplified division handling
    state.setPC(state.getPC() + inst.size);
}

void SymbolicExecutor::executeAND(ExecutionState& state, const Instruction& inst) {
    if (inst.operands.size() < 2) {
        state.setPC(state.getPC() + inst.size);
        return;
    }
    
    SymbolicValue dst = getOperandValue(state, inst.operands[0]);
    SymbolicValue src = getOperandValue(state, inst.operands[1]);
    SymbolicValue result = dst.bitwise_and(src);
    
    setOperandValue(state, inst.operands[0], result);
    state.setPC(state.getPC() + inst.size);
}

void SymbolicExecutor::executeOR(ExecutionState& state, const Instruction& inst) {
    if (inst.operands.size() < 2) {
        state.setPC(state.getPC() + inst.size);
        return;
    }
    
    SymbolicValue dst = getOperandValue(state, inst.operands[0]);
    SymbolicValue src = getOperandValue(state, inst.operands[1]);
    SymbolicValue result = dst.bitwise_or(src);
    
    setOperandValue(state, inst.operands[0], result);
    state.setPC(state.getPC() + inst.size);
}

void SymbolicExecutor::executeXOR(ExecutionState& state, const Instruction& inst) {
    if (inst.operands.size() < 2) {
        state.setPC(state.getPC() + inst.size);
        return;
    }
    
    SymbolicValue dst = getOperandValue(state, inst.operands[0]);
    SymbolicValue src = getOperandValue(state, inst.operands[1]);
    SymbolicValue result = dst.bitwise_xor(src);
    
    setOperandValue(state, inst.operands[0], result);
    state.setPC(state.getPC() + inst.size);
}

void SymbolicExecutor::executeSHL(ExecutionState& state, const Instruction& inst) {
    if (inst.operands.size() < 2) {
        state.setPC(state.getPC() + inst.size);
        return;
    }
    
    SymbolicValue dst = getOperandValue(state, inst.operands[0]);
    SymbolicValue src = getOperandValue(state, inst.operands[1]);
    SymbolicValue result = dst.shl(src);
    
    setOperandValue(state, inst.operands[0], result);
    state.setPC(state.getPC() + inst.size);
}

void SymbolicExecutor::executeSHR(ExecutionState& state, const Instruction& inst) {
    if (inst.operands.size() < 2) {
        state.setPC(state.getPC() + inst.size);
        return;
    }
    
    SymbolicValue dst = getOperandValue(state, inst.operands[0]);
    SymbolicValue src = getOperandValue(state, inst.operands[1]);
    SymbolicValue result = dst.lshr(src);
    
    setOperandValue(state, inst.operands[0], result);
    state.setPC(state.getPC() + inst.size);
}

void SymbolicExecutor::executeCMP(ExecutionState& state, const Instruction& inst) {
    if (inst.operands.size() < 2) {
        state.setPC(state.getPC() + inst.size);
        return;
    }
    
    SymbolicValue left = getOperandValue(state, inst.operands[0]);
    SymbolicValue right = getOperandValue(state, inst.operands[1]);
    SymbolicValue result = left.sub(right);
    
    updateFlags(state, result, left, right);
    state.setPC(state.getPC() + inst.size);
}

void SymbolicExecutor::executeTEST(ExecutionState& state, const Instruction& inst) {
    if (inst.operands.size() < 2) {
        state.setPC(state.getPC() + inst.size);
        return;
    }
    
    SymbolicValue left = getOperandValue(state, inst.operands[0]);
    SymbolicValue right = getOperandValue(state, inst.operands[1]);
    SymbolicValue result = left.bitwise_and(right);
    
    updateFlags(state, result, left, right);
    state.setPC(state.getPC() + inst.size);
}

void SymbolicExecutor::executePUSH(ExecutionState& state, const Instruction& inst) {
    if (inst.operands.empty()) {
        state.setPC(state.getPC() + inst.size);
        return;
    }
    
    SymbolicValue value = getOperandValue(state, inst.operands[0]);
    state.getMemory().push(value, 8);
    state.getRegisters().setStackPointer(state.getRegisters().get("rsp").sub(SymbolicValue(8)));
    state.setPC(state.getPC() + inst.size);
}

void SymbolicExecutor::executePOP(ExecutionState& state, const Instruction& inst) {
    if (inst.operands.empty()) {
        state.setPC(state.getPC() + inst.size);
        return;
    }
    
    SymbolicValue value = state.getMemory().pop(8);
    setOperandValue(state, inst.operands[0], value);
    state.getRegisters().setStackPointer(state.getRegisters().get("rsp").add(SymbolicValue(8)));
    state.setPC(state.getPC() + inst.size);
}

void SymbolicExecutor::executeLEA(ExecutionState& state, const Instruction& inst) {
    if (inst.operands.size() < 2) {
        state.setPC(state.getPC() + inst.size);
        return;
    }
    
    // LEA computes effective address
    uint64_t addr = resolveMemoryAddress(state, inst.operands[1]);
    setOperandValue(state, inst.operands[0], SymbolicValue(addr));
    state.setPC(state.getPC() + inst.size);
}

void SymbolicExecutor::executeJMP(ExecutionState& state, const Instruction& inst) {
    if (inst.operands.empty()) {
        state.setPC(state.getPC() + inst.size);
        return;
    }
    
    uint64_t target = inst.operands[0].isImm() ? 
                      inst.operands[0].value : state.getPC() + inst.size;
    state.setPC(target);
}

void SymbolicExecutor::executeJcc(ExecutionState& state, const Instruction& inst) {
    if (inst.operands.empty()) {
        state.setPC(state.getPC() + inst.size);
        return;
    }
    
    uint64_t target = inst.operands[0].isImm() ? 
                      inst.operands[0].value : state.getPC() + inst.size;
    uint64_t fallthrough = state.getPC() + inst.size;
    
    // Get condition based on flags and branch type
    z3::expr condition = z3::bool_val(true);
    auto& regs = state.getRegisters();
    
    if (inst.mnemonic == "je" || inst.mnemonic == "jz") {
        condition = regs.getZF().toZ3Expr() != 0;
    } else if (inst.mnemonic == "jne" || inst.mnemonic == "jnz") {
        condition = regs.getZF().toZ3Expr() == 0;
    } else if (inst.mnemonic == "jb" || inst.mnemonic == "jc") {
        condition = regs.getCF().toZ3Expr() != 0;
    } else if (inst.mnemonic == "jae" || inst.mnemonic == "jnc") {
        condition = regs.getCF().toZ3Expr() == 0;
    } else if (inst.mnemonic == "ja" || inst.mnemonic == "jnbe") {
        condition = (regs.getCF().toZ3Expr() == 0) && (regs.getZF().toZ3Expr() == 0);
    } else if (inst.mnemonic == "jbe" || inst.mnemonic == "jna") {
        condition = (regs.getCF().toZ3Expr() != 0) || (regs.getZF().toZ3Expr() != 0);
    } else if (inst.mnemonic == "jl" || inst.mnemonic == "jnge") {
        condition = regs.getSF().toZ3Expr() != regs.getOF().toZ3Expr();
    } else if (inst.mnemonic == "jge" || inst.mnemonic == "jnl") {
        condition = regs.getSF().toZ3Expr() == regs.getOF().toZ3Expr();
    } else if (inst.mnemonic == "jle" || inst.mnemonic == "jng") {
        condition = (regs.getZF().toZ3Expr() != 0) || 
                    (regs.getSF().toZ3Expr() != regs.getOF().toZ3Expr());
    } else if (inst.mnemonic == "jg" || inst.mnemonic == "jnle") {
        condition = (regs.getZF().toZ3Expr() == 0) && 
                    (regs.getSF().toZ3Expr() == regs.getOF().toZ3Expr());
    }
    
    forkState(state, condition, target, fallthrough);
}

void SymbolicExecutor::executeCALL(ExecutionState& state, const Instruction& inst) {
    uint64_t pc = state.getPC();
    
    // Create stack frame
    StackFrame frame;
    frame.returnAddress = pc + inst.size;
    frame.basePointer = state.getRegisters().getBasePointer();
    frame.stackPointer = state.getRegisters().getStackPointer();
    state.pushFrame(frame);
    
    // Get call target
    uint64_t target = 0;
    if (!inst.operands.empty() && inst.operands[0].isImm()) {
        target = inst.operands[0].value;
    }
    
    state.setPC(target);
    emitEvent(EventType::FUNCTION_CALL, "CALL 0x" + std::to_string(target));
}

void SymbolicExecutor::executeRET(ExecutionState& state, const Instruction& inst) {
    if (state.getStackDepth() > 0) {
        StackFrame frame = state.popFrame();
        state.setPC(frame.returnAddress);
        state.getRegisters().setBasePointer(SymbolicValue(frame.basePointer));
        emitEvent(EventType::FUNCTION_RETURN, "RET to 0x" + std::to_string(frame.returnAddress));
    } else {
        // End of execution
        stateManager.removeState(&state);
        stats.exploredPaths++;
    }
}

void SymbolicExecutor::executeNOP(ExecutionState& state, const Instruction& inst) {
    state.setPC(state.getPC() + inst.size);
}

SymbolicValue SymbolicExecutor::getOperandValue(ExecutionState& state, const Operand& op) {
    switch (op.type) {
        case OperandType::REGISTER:
            return state.getRegisters().get(op.regName);
        case OperandType::IMMEDIATE:
            return SymbolicValue(op.value);
        case OperandType::MEMORY: {
            uint64_t addr = resolveMemoryAddress(state, op);
            return state.getMemory().read(addr, op.size);
        }
        default:
            return SymbolicValue(0);
    }
}

void SymbolicExecutor::setOperandValue(ExecutionState& state, const Operand& op, 
                                        const SymbolicValue& val) {
    switch (op.type) {
        case OperandType::REGISTER:
            state.getRegisters().set(op.regName, val);
            break;
        case OperandType::MEMORY: {
            uint64_t addr = resolveMemoryAddress(state, op);
            state.getMemory().write(addr, val, op.size);
            break;
        }
        default:
            break;
    }
}

uint64_t SymbolicExecutor::resolveMemoryAddress(ExecutionState& state, const Operand& op) {
    uint64_t base = 0;
    
    if (op.type == OperandType::MEMORY) {
        if (!op.regName.empty()) {
            base = state.getRegisters().get(op.regName).getConcrete();
        }
        return base + op.disp;
    }
    
    return 0;
}

void SymbolicExecutor::updateFlags(ExecutionState& state, const SymbolicValue& result,
                                    const SymbolicValue& left, const SymbolicValue& right) {
    auto& regs = state.getRegisters();
    
    // Zero flag
    if (result.isConcrete()) {
        regs.setZF(SymbolicValue(result.getConcrete() == 0 ? 1 : 0));
    }
    
    // Sign flag (MSB)
    if (result.isConcrete()) {
        regs.setSF(SymbolicValue((result.getConcrete() >> 63) & 1));
    }
}

void SymbolicExecutor::emitEvent(EventType type, const std::string& data) {
    auto it = callbacks.find(type);
    if (it != callbacks.end()) {
        for (const auto& callback : it->second) {
            if (currentState) {
                callback(*currentState, type, data);
            }
        }
    }
}

void SymbolicExecutor::recordPath(ExecutionState& state) {
    // Record path for later analysis
}

bool SymbolicExecutor::shouldTerminate(const ExecutionState& state) const {
    // Check depth limit
    if (state.getDepth() >= cfg.maxDepth) {
        return true;
    }
    
    // Check instruction limit
    if (state.getInstructionCount() >= cfg.maxInstructions) {
        return true;
    }
    
    return false;
}

std::string SymbolicExecutor::getExecutionTrace() const {
    std::ostringstream oss;
    if (currentState) {
        auto history = currentState->getHistory();
        for (const auto& [addr, mnemonic] : history) {
            oss << "0x" << std::hex << addr << std::dec << ": " << mnemonic << "\n";
        }
    }
    return oss.str();
}

void SymbolicExecutor::printStats() const {
    std::cout << stats.toString() << std::endl;
}

} // namespace symexec
