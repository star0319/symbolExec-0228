#ifndef CFG_BUILDER_H
#define CFG_BUILDER_H

#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <cstdint>
#include "Disassembler.h"
#include "ELFParser.h"

namespace symexec {

// Edge type in CFG
enum class EdgeType {
    UNCONDITIONAL,    // Direct jump or fall-through
    CONDITIONAL_TRUE, // Branch taken
    CONDITIONAL_FALSE,// Branch not taken
    CALL,             // Function call
    RETURN            // Function return
};

// CFG edge
struct CFGEdge {
    uint64_t source;      // Source basic block address
    uint64_t target;      // Target basic block address
    EdgeType type;
    uint64_t instructionAddr;  // Address of the branching instruction
    
    CFGEdge() : source(0), target(0), type(EdgeType::UNCONDITIONAL), instructionAddr(0) {}
    CFGEdge(uint64_t src, uint64_t tgt, EdgeType t, uint64_t instAddr)
        : source(src), target(tgt), type(t), instructionAddr(instAddr) {}
};

// Function information
struct FunctionInfo {
    uint64_t address;
    std::string name;
    uint64_t size;
    std::set<uint64_t> basicBlocks;
    std::set<uint64_t> calls;
    bool isExternal;
    bool isLibrary;
    
    FunctionInfo() : address(0), size(0), isExternal(false), isLibrary(false) {}
};

// Control Flow Graph
struct ControlFlowGraph {
    std::map<uint64_t, BasicBlock> basicBlocks;  // Address -> BasicBlock
    std::vector<CFGEdge> edges;
    std::map<uint64_t, FunctionInfo> functions;
    uint64_t entryPoint;
    std::string moduleName;
    
    ControlFlowGraph() : entryPoint(0) {}
    
    // Get basic block containing address
    BasicBlock* getBlockContaining(uint64_t addr) {
        for (auto& [blockAddr, block] : basicBlocks) {
            if (addr >= block.startAddr && addr < block.endAddr) {
                return &block;
            }
        }
        return nullptr;
    }
    
    // Get all basic blocks in order
    std::vector<BasicBlock> getBlocksInOrder() const {
        std::vector<BasicBlock> blocks;
        for (const auto& [addr, block] : basicBlocks) {
            blocks.push_back(block);
        }
        return blocks;
    }
    
    // Get successors of a block
    std::vector<uint64_t> getSuccessors(uint64_t blockAddr) const {
        auto it = basicBlocks.find(blockAddr);
        if (it != basicBlocks.end()) {
            return it->second.successors;
        }
        return {};
    }
    
    // Get predecessors of a block
    std::vector<uint64_t> getPredecessors(uint64_t blockAddr) const {
        auto it = basicBlocks.find(blockAddr);
        if (it != basicBlocks.end()) {
            return it->second.predecessors;
        }
        return {};
    }
};

// CFG Builder class
class CFGBuilder {
public:
    CFGBuilder();
    ~CFGBuilder() = default;
    
    // Build CFG from binary
    ControlFlowGraph buildCFG(const ELFInfo& elfInfo, const std::vector<uint8_t>& binaryData);
    
    // Build CFG for a specific function
    ControlFlowGraph buildFunctionCFG(const ELFInfo& elfInfo, 
                                       const std::vector<uint8_t>& binaryData,
                                       uint64_t funcAddr);
    
    // Build CFG from disassembled instructions
    ControlFlowGraph buildFromInstructions(const std::vector<Instruction>& instructions,
                                           uint64_t baseAddr);
    
    // Identify functions in binary
    std::vector<FunctionInfo> identifyFunctions(const ELFInfo& elfInfo,
                                                 const std::vector<uint8_t>& binaryData);
    
    // Get code section data
    std::pair<const uint8_t*, size_t> getCodeSection(const ELFInfo& elfInfo,
                                                      const std::vector<uint8_t>& binaryData);
    
    // Print CFG (for debugging)
    void printCFG(const ControlFlowGraph& cfg) const;
    
    // Export CFG to DOT format
    std::string toDOT(const ControlFlowGraph& cfg) const;

private:
    Disassembler disassembler;
    
    // Partition instructions into basic blocks
    std::map<uint64_t, BasicBlock> partitionIntoBasicBlocks(
        const std::vector<Instruction>& instructions);
    
    // Build edges between basic blocks
    void buildEdges(ControlFlowGraph& cfg);
    
    // Find basic block leaders
    std::set<uint64_t> findLeaders(const std::vector<Instruction>& instructions,
                                    uint64_t baseAddr);
    
    // Resolve branch target
    uint64_t resolveBranchTarget(const Instruction& inst, uint64_t currentAddr) const;
    
    // Check if address is in code range
    bool isInCodeRange(uint64_t addr, uint64_t codeStart, size_t codeSize) const;
};

} // namespace symexec

#endif // CFG_BUILDER_H
