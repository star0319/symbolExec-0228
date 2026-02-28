#include "CFGBuilder.h"
#include <algorithm>
#include <sstream>
#include <iostream>

namespace symexec {

CFGBuilder::CFGBuilder() {}

ControlFlowGraph CFGBuilder::buildCFG(const ELFInfo& elfInfo, 
                                       const std::vector<uint8_t>& binaryData) {
    ControlFlowGraph cfg;
    cfg.entryPoint = elfInfo.entryPoint;
    
    // Initialize disassembler
    disassembler.initialize(elfInfo.machine, elfInfo.elfClass == ELFClass::ELF64);
    
    // Get code section
    auto [code, codeSize] = getCodeSection(elfInfo, binaryData);
    if (!code || codeSize == 0) {
        return cfg;
    }
    
    // Identify functions
    cfg.functions = {};
    auto funcInfos = identifyFunctions(elfInfo, binaryData);
    for (const auto& func : funcInfos) {
        cfg.functions[func.address] = func;
    }
    
    // Disassemble entire code section
    std::vector<Instruction> allInstructions = disassembler.disassembleRegion(
        code, codeSize, elfInfo.baseAddr);
    
    if (allInstructions.empty()) {
        return cfg;
    }
    
    // Find basic block leaders
    std::set<uint64_t> leaders = findLeaders(allInstructions, elfInfo.baseAddr);
    
    // Ensure entry point is a leader
    leaders.insert(elfInfo.entryPoint);
    
    // Partition into basic blocks
    cfg.basicBlocks = partitionIntoBasicBlocks(allInstructions);
    
    // Build edges
    buildEdges(cfg);
    
    return cfg;
}

ControlFlowGraph CFGBuilder::buildFunctionCFG(const ELFInfo& elfInfo,
                                               const std::vector<uint8_t>& binaryData,
                                               uint64_t funcAddr) {
    ControlFlowGraph cfg;
    cfg.entryPoint = funcAddr;
    
    disassembler.initialize(elfInfo.machine, elfInfo.elfClass == ELFClass::ELF64);
    
    auto [code, codeSize] = getCodeSection(elfInfo, binaryData);
    if (!code || codeSize == 0) {
        return cfg;
    }
    
    // Find function offset
    uint64_t funcOffset = funcAddr - elfInfo.baseAddr;
    if (funcOffset >= codeSize) {
        return cfg;
    }
    
    // Disassemble function
    std::vector<Instruction> instructions = disassembler.disassembleFunction(
        code, codeSize, funcAddr, funcOffset);
    
    if (instructions.empty()) {
        return cfg;
    }
    
    // Partition into basic blocks
    cfg.basicBlocks = partitionIntoBasicBlocks(instructions);
    
    // Build edges
    buildEdges(cfg);
    
    return cfg;
}

ControlFlowGraph CFGBuilder::buildFromInstructions(const std::vector<Instruction>& instructions,
                                                    uint64_t baseAddr) {
    ControlFlowGraph cfg;
    
    if (instructions.empty()) {
        return cfg;
    }
    
    cfg.entryPoint = instructions[0].address;
    
    // Partition into basic blocks
    cfg.basicBlocks = partitionIntoBasicBlocks(instructions);
    
    // Build edges
    buildEdges(cfg);
    
    return cfg;
}

std::vector<FunctionInfo> CFGBuilder::identifyFunctions(const ELFInfo& elfInfo,
                                                         const std::vector<uint8_t>& binaryData) {
    std::vector<FunctionInfo> functions;
    
    // Use symbols to identify functions
    for (const auto& sym : elfInfo.symbols) {
        if (sym.isFunc && sym.value != 0) {
            FunctionInfo func;
            func.address = sym.value;
            func.name = sym.name;
            func.size = sym.size;
            func.isExternal = (sym.shndx == 0);
            functions.push_back(func);
        }
    }
    
    // If no symbols found, try entry point
    if (functions.empty()) {
        FunctionInfo mainFunc;
        mainFunc.address = elfInfo.entryPoint;
        mainFunc.name = "entry";
        mainFunc.size = 0;  // Unknown
        functions.push_back(mainFunc);
    }
    
    return functions;
}

std::pair<const uint8_t*, size_t> CFGBuilder::getCodeSection(const ELFInfo& elfInfo,
                                                              const std::vector<uint8_t>& binaryData) {
    // Find executable segment
    for (const auto& seg : elfInfo.segments) {
        if (seg.executable && !seg.data.empty()) {
            return {seg.data.data(), seg.data.size()};
        }
    }
    
    // Fallback: find .text section
    for (const auto& sec : elfInfo.sectionHeaders) {
        if (sec.nameStr == ".text" && sec.size > 0) {
            if (sec.offset + sec.size <= binaryData.size()) {
                return {&binaryData[sec.offset], sec.size};
            }
        }
    }
    
    // Last resort: use first executable segment
    for (const auto& ph : elfInfo.programHeaders) {
        if (ph.type == 1 && (ph.flags & 1)) {  // Executable
            if (ph.offset + ph.filesz <= binaryData.size() && ph.filesz > 0) {
                return {&binaryData[ph.offset], ph.filesz};
            }
        }
    }
    
    return {nullptr, 0};
}

std::set<uint64_t> CFGBuilder::findLeaders(const std::vector<Instruction>& instructions,
                                            uint64_t baseAddr) {
    std::set<uint64_t> leaders;
    
    if (instructions.empty()) return leaders;
    
    // First instruction is always a leader
    leaders.insert(instructions[0].address);
    
    for (const auto& inst : instructions) {
        // Target of branch/call is a leader
        if (inst.isBranch || inst.isCall) {
            uint64_t target = resolveBranchTarget(inst, inst.address);
            if (target != 0) {
                leaders.insert(target);
            }
        }
        
        // Instruction after branch/call is a leader
        uint64_t nextAddr = inst.address + inst.size;
        leaders.insert(nextAddr);
        
        // Target of indirect branch (conservative)
        if (inst.isIndirectBranch) {
            // Can't determine target statically
        }
    }
    
    return leaders;
}

std::map<uint64_t, BasicBlock> CFGBuilder::partitionIntoBasicBlocks(
    const std::vector<Instruction>& instructions) {
    
    std::map<uint64_t, BasicBlock> blocks;
    
    if (instructions.empty()) return blocks;
    
    // Find leaders
    std::set<uint64_t> leaders = findLeaders(instructions, instructions[0].address);
    
    // Create basic blocks
    BasicBlock* currentBlock = nullptr;
    uint64_t currentStart = 0;
    
    for (const auto& inst : instructions) {
        // Check if this instruction starts a new block
        if (leaders.count(inst.address)) {
            // Finish previous block
            if (currentBlock && !currentBlock->instructions.empty()) {
                currentBlock->endAddr = currentBlock->instructions.back().address + 
                                        currentBlock->instructions.back().size;
            }
            
            // Start new block
            blocks[inst.address] = BasicBlock();
            currentBlock = &blocks[inst.address];
            currentBlock->startAddr = inst.address;
        }
        
        if (currentBlock) {
            currentBlock->instructions.push_back(inst);
        }
    }
    
    // Finish last block
    if (currentBlock && !currentBlock->instructions.empty()) {
        currentBlock->endAddr = currentBlock->instructions.back().address + 
                                currentBlock->instructions.back().size;
    }
    
    return blocks;
}

void CFGBuilder::buildEdges(ControlFlowGraph& cfg) {
    for (auto& [addr, block] : cfg.basicBlocks) {
        if (block.instructions.empty()) continue;
        
        const Instruction& lastInst = block.instructions.back();
        uint64_t nextAddr = lastInst.address + lastInst.size;
        
        // Handle different instruction types
        if (lastInst.isReturn) {
            block.isExit = true;
            // No successors for return
        } else if (lastInst.isBranch) {
            if (lastInst.mnemonic == "jmp" || lastInst.mnemonic == "jmpl") {
                // Unconditional jump
                uint64_t target = resolveBranchTarget(lastInst, lastInst.address);
                if (target != 0 && cfg.basicBlocks.count(target)) {
                    block.successors.push_back(target);
                    cfg.basicBlocks[target].predecessors.push_back(addr);
                    cfg.edges.emplace_back(addr, target, EdgeType::UNCONDITIONAL, lastInst.address);
                }
            } else if (Disassembler::isCompareInstruction(lastInst.mnemonic) ||
                       lastInst.mnemonic.find('j') == 0) {
                // Conditional branch
                uint64_t target = resolveBranchTarget(lastInst, lastInst.address);
                
                // True branch
                if (target != 0 && cfg.basicBlocks.count(target)) {
                    block.successors.push_back(target);
                    cfg.basicBlocks[target].predecessors.push_back(addr);
                    cfg.edges.emplace_back(addr, target, EdgeType::CONDITIONAL_TRUE, lastInst.address);
                }
                
                // False branch (fall-through)
                if (cfg.basicBlocks.count(nextAddr)) {
                    block.successors.push_back(nextAddr);
                    cfg.basicBlocks[nextAddr].predecessors.push_back(addr);
                    cfg.edges.emplace_back(addr, nextAddr, EdgeType::CONDITIONAL_FALSE, lastInst.address);
                }
            }
        } else if (lastInst.isCall) {
            // Call: successor is next instruction
            // (call target is handled separately in symbolic execution)
            if (cfg.basicBlocks.count(nextAddr)) {
                block.successors.push_back(nextAddr);
                cfg.basicBlocks[nextAddr].predecessors.push_back(addr);
                cfg.edges.emplace_back(addr, nextAddr, EdgeType::CALL, lastInst.address);
            }
        } else {
            // Fall-through
            if (cfg.basicBlocks.count(nextAddr)) {
                block.successors.push_back(nextAddr);
                cfg.basicBlocks[nextAddr].predecessors.push_back(addr);
                cfg.edges.emplace_back(addr, nextAddr, EdgeType::UNCONDITIONAL, lastInst.address);
            }
        }
    }
}

uint64_t CFGBuilder::resolveBranchTarget(const Instruction& inst, uint64_t currentAddr) const {
    if (inst.operands.empty()) return 0;
    
    // Direct branch: target is immediate operand
    if (!inst.operands.empty() && inst.operands[0].isImm()) {
        return inst.operands[0].value;
    }
    
    // For x86, check immediate operand
    for (const auto& op : inst.operands) {
        if (op.type == OperandType::IMMEDIATE) {
            return op.value;
        }
    }
    
    return 0;  // Indirect branch
}

bool CFGBuilder::isInCodeRange(uint64_t addr, uint64_t codeStart, size_t codeSize) const {
    return addr >= codeStart && addr < codeStart + codeSize;
}

void CFGBuilder::printCFG(const ControlFlowGraph& cfg) const {
    std::cout << "=== Control Flow Graph ===" << std::endl;
    std::cout << "Entry Point: 0x" << std::hex << cfg.entryPoint << std::endl;
    std::cout << "Basic Blocks: " << cfg.basicBlocks.size() << std::endl;
    std::cout << "Edges: " << cfg.edges.size() << std::endl;
    std::cout << std::endl;
    
    for (const auto& [addr, block] : cfg.basicBlocks) {
        std::cout << "Block @ 0x" << std::hex << addr << std::dec
                  << " (size: " << block.instructions.size() << " instructions)" << std::endl;
        std::cout << "  Predecessors: ";
        for (uint64_t pred : block.predecessors) {
            std::cout << "0x" << std::hex << pred << std::dec << " ";
        }
        std::cout << std::endl;
        std::cout << "  Successors: ";
        for (uint64_t succ : block.successors) {
            std::cout << "0x" << std::hex << succ << std::dec << " ";
        }
        std::cout << std::endl;
        
        // Print first few instructions
        size_t printCount = std::min(block.instructions.size(), size_t(3));
        for (size_t i = 0; i < printCount; ++i) {
            const auto& inst = block.instructions[i];
            std::cout << "    0x" << std::hex << inst.address << std::dec
                      << ": " << inst.mnemonic << " " << inst.opStr << std::endl;
        }
        if (block.instructions.size() > printCount) {
            std::cout << "    ... (" << (block.instructions.size() - printCount) << " more)" << std::endl;
        }
        std::cout << std::endl;
    }
}

std::string CFGBuilder::toDOT(const ControlFlowGraph& cfg) const {
    std::ostringstream dot;
    
    dot << "digraph CFG {\n";
    dot << "  rankdir=TB;\n";
    dot << "  node [shape=box, fontname=\"Courier\"];\n";
    dot << "  edge [fontname=\"Courier\", fontsize=10];\n";
    dot << "\n";
    
    // Create nodes
    for (const auto& [addr, block] : cfg.basicBlocks) {
        dot << "  bb_0x" << std::hex << addr << std::dec << " [label=\"";
        dot << "0x" << std::hex << addr << std::dec << "\\n";
        
        // Add instructions (limit to first 5)
        size_t count = 0;
        for (const auto& inst : block.instructions) {
            if (count >= 5) {
                dot << "...\\n";
                break;
            }
            dot << inst.mnemonic << " " << inst.opStr << "\\n";
            count++;
        }
        dot << "\"];\n";
    }
    
    dot << "\n";
    
    // Create edges
    for (const auto& edge : cfg.edges) {
        dot << "  bb_0x" << std::hex << edge.source << std::dec
            << " -> bb_0x" << edge.target << std::dec;
        
        switch (edge.type) {
            case EdgeType::UNCONDITIONAL:
                dot << " [label=\"uncond\"]";
                break;
            case EdgeType::CONDITIONAL_TRUE:
                dot << " [label=\"T\", color=green]";
                break;
            case EdgeType::CONDITIONAL_FALSE:
                dot << " [label=\"F\", color=red]";
                break;
            case EdgeType::CALL:
                dot << " [label=\"call\", style=dashed]";
                break;
            case EdgeType::RETURN:
                dot << " [label=\"ret\", style=dotted]";
                break;
        }
        dot << ";\n";
    }
    
    dot << "}\n";
    
    return dot.str();
}

} // namespace symexec
