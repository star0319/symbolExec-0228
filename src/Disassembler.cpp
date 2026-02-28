#include "Disassembler.h"
#include <cstring>
#include <iostream>

namespace symexec {

Disassembler::Disassembler() : handle(0), mode(CS_MODE_LITTLE_ENDIAN), 
                                arch(CS_ARCH_X86), initialized(false) {}

Disassembler::~Disassembler() {
    close();
}

bool Disassembler::initialize(ELFMachine machine, bool is64Bit) {
    if (initialized) {
        close();
    }
    
    cs_err err;
    
    switch (machine) {
        case ELFMachine::X86:
            arch = CS_ARCH_X86;
            mode = is64Bit ? CS_MODE_64 : CS_MODE_32;
            break;
        case ELFMachine::X86_64:
            arch = CS_ARCH_X86;
            mode = CS_MODE_64;
            break;
        case ELFMachine::ARM:
            arch = CS_ARCH_ARM;
            mode = is64Bit ? CS_MODE_ARM : CS_MODE_ARM;
            break;
        case ELFMachine::AARCH64:
            arch = CS_ARCH_ARM64;
            mode = CS_MODE_LITTLE_ENDIAN;
            break;
        case ELFMachine::MIPS:
            arch = CS_ARCH_MIPS;
            mode = is64Bit ? CS_MODE_MIPS64 : CS_MODE_MIPS32;
            break;
        default:
            std::cerr << "Unsupported architecture" << std::endl;
            return false;
    }
    
    mode = static_cast<cs_mode>(mode | CS_MODE_LITTLE_ENDIAN);
    
    err = cs_open(arch, mode, &handle);
    if (err != CS_ERR_OK) {
        std::cerr << "Failed to initialize Capstone: " << cs_strerror(err) << std::endl;
        return false;
    }
    
    // Enable detail information
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
    
    initialized = true;
    return true;
}

std::vector<Instruction> Disassembler::disassembleRegion(const uint8_t* code, size_t size,
                                                          uint64_t baseAddr, size_t maxInsts) {
    std::vector<Instruction> instructions;
    
    if (!initialized || !code || size == 0) {
        return instructions;
    }
    
    cs_insn* insn = cs_malloc(handle);
    if (!insn) {
        return instructions;
    }
    
    size_t offset = 0;
    size_t count = 0;

    while (offset < size && (maxInsts == 0 || count < maxInsts)) {
        const uint8_t* codePtr = &code[offset];
        size_t remainingSize = size - offset;
        uint64_t currentAddr = baseAddr + offset;

        if (cs_disasm_iter(handle, &codePtr, &remainingSize, &currentAddr, insn)) {
            Instruction inst;
            inst.address = insn->address;
            inst.size = insn->size;
            inst.mnemonic = insn->mnemonic;
            inst.opStr = insn->op_str;
            inst.bytes.assign(insn->bytes, insn->bytes + insn->size);

            // Parse operands
            parseOperands(insn, inst);

            // Analyze instruction semantics
            analyzeInstruction(inst);

            instructions.push_back(inst);

            offset += insn->size;
            count++;
        } else {
            // Skip invalid bytes
            offset++;
        }
    }
    
    cs_free(insn, 1);
    return instructions;
}

std::vector<Instruction> Disassembler::disassembleFunction(const uint8_t* code, size_t size,
                                                            uint64_t funcAddr, uint64_t entryOffset) {
    // Linear sweep disassembly for the function
    std::vector<Instruction> instructions;
    
    if (!initialized || !code || size == 0) {
        return instructions;
    }
    
    cs_insn* insn = cs_malloc(handle);
    if (!insn) {
        return instructions;
    }
    
    size_t offset = entryOffset;
    
    while (offset < size) {
        const uint8_t* codePtr = &code[offset];
        size_t remainingSize = size - offset;
        uint64_t addr = funcAddr + offset;
        
        if (cs_disasm_iter(handle, &codePtr, &remainingSize, &addr, insn)) {
            Instruction inst;
            inst.address = insn->address;
            inst.size = insn->size;
            inst.mnemonic = insn->mnemonic;
            inst.opStr = insn->op_str;
            inst.bytes.assign(insn->bytes, insn->bytes + insn->size);
            
            parseOperands(insn, inst);
            analyzeInstruction(inst);
            
            instructions.push_back(inst);
            
            offset += insn->size;
            
            // Stop at return instruction
            if (isReturnInstruction(inst.mnemonic)) {
                break;
            }
        } else {
            offset++;
        }
    }
    
    cs_free(insn, 1);
    return instructions;
}

Instruction Disassembler::getInstructionAt(const uint8_t* code, size_t codeSize,
                                            uint64_t addr, uint64_t baseAddr) {
    Instruction inst;
    
    if (!initialized || !code || codeSize == 0) {
        return inst;
    }
    
    size_t offset = addr - baseAddr;
    if (offset >= codeSize) {
        return inst;
    }
    
    cs_insn* insn = cs_malloc(handle);
    if (!insn) {
        return inst;
    }
    
    const uint8_t* codePtr = &code[offset];
    size_t remainingSize = codeSize - offset;
    uint64_t currentAddr = addr;
    
    if (cs_disasm_iter(handle, &codePtr, &remainingSize, &currentAddr, insn)) {
        inst.address = insn->address;
        inst.size = insn->size;
        inst.mnemonic = insn->mnemonic;
        inst.opStr = insn->op_str;
        inst.bytes.assign(insn->bytes, insn->bytes + insn->size);
        
        parseOperands(insn, inst);
        analyzeInstruction(inst);
    }
    
    cs_free(insn, 1);
    return inst;
}

void Disassembler::parseOperands(const cs_insn* csInst, Instruction& inst) {
    cs_detail* detail = csInst->detail;
    if (!detail) return;
    
    switch (arch) {
        case CS_ARCH_X86: {
            cs_x86* x86 = &detail->x86;
            for (int i = 0; i < x86->op_count; ++i) {
                cs_x86_op& op = x86->operands[i];
                Operand operand;
                operand.size = op.size;
                
                switch (op.type) {
                    case X86_OP_REG:
                        operand.type = OperandType::REGISTER;
                        operand.value = op.reg;
                        operand.regName = cs_reg_name(handle, op.reg);
                        break;
                    case X86_OP_IMM:
                        operand.type = OperandType::IMMEDIATE;
                        operand.value = op.imm;
                        break;
                    case X86_OP_MEM:
                        operand.type = OperandType::MEMORY;
                        operand.disp = op.mem.disp;
                        if (op.mem.base != X86_REG_INVALID) {
                            operand.value = op.mem.base;
                            operand.regName = cs_reg_name(handle, op.mem.base);
                        }
                        if (op.mem.index != X86_REG_INVALID) {
                            // Has index register
                        }
                        break;
                }
                inst.operands.push_back(operand);
            }
            break;
        }
        case CS_ARCH_ARM64: {
            cs_arm64* arm64 = &detail->arm64;
            for (int i = 0; i < arm64->op_count; ++i) {
                cs_arm64_op& op = arm64->operands[i];
                Operand operand;
                // operand.size = op.size;
                
                switch (op.type) {
                    case ARM64_OP_REG:
                        operand.type = OperandType::REGISTER;
                        operand.value = op.reg;
                        operand.regName = cs_reg_name(handle, op.reg);
                        break;
                    case ARM64_OP_IMM:
                        operand.type = OperandType::IMMEDIATE;
                        operand.value = op.imm;
                        break;
                    case ARM64_OP_MEM:
                        operand.type = OperandType::MEMORY;
                        operand.disp = op.mem.disp;
                        break;
                    default:
                        break;
                }
                inst.operands.push_back(operand);
            }
            break;
        }
        default:
            break;
    }
}

void Disassembler::analyzeInstruction(Instruction& inst) {
    inst.isBranch = isBranchInstruction(inst.mnemonic);
    inst.isCall = isCallInstruction(inst.mnemonic);
    inst.isReturn = isReturnInstruction(inst.mnemonic);
    inst.isCompare = isCompareInstruction(inst.mnemonic);
    
    // Determine instruction category
    const std::string& mnem = inst.mnemonic;
    
    if (mnem == "mov" || mnem == "movl" || mnem == "movq" || mnem == "movzx" || 
        mnem == "movsx" || mnem == "lea" || mnem == "leaq") {
        inst.isMove = true;
    }
    
    if (mnem == "add" || mnem == "sub" || mnem == "mul" || mnem == "div" ||
        mnem == "imul" || mnem == "idiv" || mnem == "xor" || mnem == "and" ||
        mnem == "or" || mnem == "shl" || mnem == "shr" || mnem == "sal" ||
        mnem == "sar" || mnem == "rol" || mnem == "ror" || mnem == "neg" ||
        mnem == "inc" || mnem == "dec" || mnem == "not") {
        inst.isArithmetic = true;
    }
    
    // Check memory access
    for (const auto& op : inst.operands) {
        if (op.isMem()) {
            inst.isMemoryAccess = true;
            if (inst.isMove || inst.isArithmetic) {
                if (&op == &inst.operands[0]) {
                    inst.writesMemory = true;
                } else {
                    inst.readsMemory = true;
                }
            }
        }
    }
    
    // Get branch target
    if (inst.isBranch || inst.isCall) {
        inst.branchTarget = getBranchTarget(inst);
        inst.isIndirectBranch = (inst.branchTarget == 0);
    }
}

bool Disassembler::isBranchInstruction(const std::string& mnemonic) {
    return mnemonic == "jmp" || mnemonic == "je" || mnemonic == "jne" ||
           mnemonic == "jz" || mnemonic == "jnz" || mnemonic == "jb" ||
           mnemonic == "jae" || mnemonic == "ja" || mnemonic == "jbe" ||
           mnemonic == "jl" || mnemonic == "jge" || mnemonic == "jle" ||
           mnemonic == "jg" || mnemonic == "js" || mnemonic == "jns" ||
           mnemonic == "jo" || mnemonic == "jno" || mnemonic == "jp" ||
           mnemonic == "jnp" || mnemonic == "jc" || mnemonic == "jnc" ||
           mnemonic == "loop" || mnemonic == "loope" || mnemonic == "loopne" ||
           mnemonic == "jcxz" || mnemonic == "jecxz" || mnemonic == "jrcxz" ||
           mnemonic == "call" ||  // Call is also a branch for CFG purposes
           mnemonic == "b" || mnemonic == "beq" || mnemonic == "bne" ||  // ARM
           mnemonic == "bl" || mnemonic == "bx" || mnemonic == "blx";
}

bool Disassembler::isCallInstruction(const std::string& mnemonic) {
    return mnemonic == "call" || mnemonic == "callq" || mnemonic == "bl" || mnemonic == "blx";
}

bool Disassembler::isReturnInstruction(const std::string& mnemonic) {
    return mnemonic == "ret" || mnemonic == "retq" || mnemonic == "retf" ||
           mnemonic == "bx" || mnemonic == "blx";  // ARM returns
}

bool Disassembler::isCompareInstruction(const std::string& mnemonic) {
    return mnemonic == "cmp" || mnemonic == "cmpl" || mnemonic == "cmpq" ||
           mnemonic == "cmpb" || mnemonic == "cmpw" || mnemonic == "test" ||
           mnemonic == "testl" || mnemonic == "testq" || mnemonic == "testb" ||
           mnemonic == "tst";  // ARM
}

uint64_t Disassembler::getBranchTarget(const Instruction& inst) {
    if (inst.operands.empty()) return 0;
    
    // Direct branch: target is in the first operand (immediate)
    if (inst.operands[0].isImm()) {
        return inst.operands[0].value;
    }
    
    // For PC-relative, the target might need calculation
    // This is simplified - real implementation would handle PC-relative
    return 0;  // Indirect branch
}

void Disassembler::close() {
    if (initialized && handle != 0) {
        cs_close(&handle);
        handle = 0;
        initialized = false;
    }
}

} // namespace symexec
