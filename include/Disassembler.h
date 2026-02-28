#ifndef DISASSEMBLER_H
#define DISASSEMBLER_H

#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <capstone/capstone.h>
#include "ELFParser.h"

namespace symexec {

// Instruction operand type
enum class OperandType {
    NONE,
    REGISTER,
    IMMEDIATE,
    MEMORY
};

// Instruction operand
struct Operand {
    OperandType type;
    uint64_t value;      // For immediate or register id
    int64_t disp;        // For memory displacement
    uint8_t size;        // Operand size in bytes
    std::string regName; // Register name if applicable
    
    bool isReg() const { return type == OperandType::REGISTER; }
    bool isImm() const { return type == OperandType::IMMEDIATE; }
    bool isMem() const { return type == OperandType::MEMORY; }
};

// Instruction structure
struct Instruction {
    uint64_t address;
    uint64_t size;
    std::string mnemonic;
    std::string opStr;
    std::vector<uint8_t> bytes;
    std::vector<Operand> operands;
    
    // Instruction categories
    bool isBranch;
    bool isCall;
    bool isReturn;
    bool isCompare;
    bool isMove;
    bool isArithmetic;
    bool isMemoryAccess;
    
    // Branch targets
    uint64_t branchTarget;    // For direct branches
    bool isIndirectBranch;    // For indirect branches/calls
    
    // Read/write info
    std::vector<int> readsRegs;
    std::vector<int> writesRegs;
    bool readsMemory;
    bool writesMemory;
    
    Instruction() : address(0), size(0), isBranch(false), isCall(false),
                    isReturn(false), isCompare(false), isMove(false),
                    isArithmetic(false), isMemoryAccess(false),
                    branchTarget(0), isIndirectBranch(false),
                    readsMemory(false), writesMemory(false) {}
};

// Basic block structure
struct BasicBlock {
    uint64_t startAddr;
    uint64_t endAddr;
    std::vector<Instruction> instructions;
    std::vector<uint64_t> successors;
    std::vector<uint64_t> predecessors;
    bool isExit;
    
    BasicBlock() : startAddr(0), endAddr(0), isExit(false) {}
    
    uint64_t getEndAddress() const { return endAddr; }
    uint64_t getSize() const { return endAddr - startAddr; }
};

// Disassembler class
class Disassembler {
public:
    Disassembler();
    ~Disassembler();
    
    // Initialize for specific architecture
    bool initialize(ELFMachine machine, bool is64Bit = true);
    
    // Disassemble code region
    std::vector<Instruction> disassembleRegion(const uint8_t* code, size_t size, 
                                                uint64_t baseAddr, size_t maxInsts = 0);
    
    // Disassemble function
    std::vector<Instruction> disassembleFunction(const uint8_t* code, size_t size,
                                                  uint64_t funcAddr, uint64_t entryOffset);
    
    // Get instruction at specific address
    Instruction getInstructionAt(const uint8_t* code, size_t codeSize, 
                                  uint64_t addr, uint64_t baseAddr);
    
    // Check if instruction is a branch
    static bool isBranchInstruction(const std::string& mnemonic);
    
    // Check if instruction is a call
    static bool isCallInstruction(const std::string& mnemonic);
    
    // Check if instruction is a return
    static bool isReturnInstruction(const std::string& mnemonic);
    
    // Check if instruction is a compare
    static bool isCompareInstruction(const std::string& mnemonic);
    
    // Get branch target if direct
    static uint64_t getBranchTarget(const Instruction& inst);
    
    // Clean up
    void close();
    
    // Get architecture mode
    csh getHandle() const { return handle; }
    cs_mode getMode() const { return mode; }
    cs_arch getArch() const { return arch; }

private:
    csh handle;
    cs_mode mode;
    cs_arch arch;
    bool initialized;
    
    // Parse operands from capstone
    void parseOperands(const cs_insn* csInst, Instruction& inst);
    
    // Analyze instruction semantics
    void analyzeInstruction(Instruction& inst);
};

} // namespace symexec

#endif // DISASSEMBLER_H
