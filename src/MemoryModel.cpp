#include "MemoryModel.h"
#include <sstream>
#include <iomanip>
#include <cstring>
#include <iostream>

namespace symexec {

// ============================================================================
// SymbolicValue Implementation
// ============================================================================

SymbolicValue::SymbolicValue() 
    : type(ValueType::TOP), concreteValue(0), bits(64) {}

SymbolicValue::SymbolicValue(uint64_t concrete) 
    : type(ValueType::CONCRETE), concreteValue(concrete), bits(64) {}

SymbolicValue::SymbolicValue(z3::expr symbolic) 
    : type(ValueType::SYMBOLIC), concreteValue(0), 
      symbolicValue(symbolic), bits(symbolic.get_sort()->bv_size()) {}

SymbolicValue SymbolicValue::makeSymbolic(z3::context& ctx, const std::string& name, size_t bits) {
    z3::sort sort = bits == 8 ? ctx.bv_sort(8) : 
                    bits == 32 ? ctx.bv_sort(32) : ctx.bv_sort(64);
    z3::expr expr = ctx.constant(name.c_str(), sort);
    SymbolicValue val(expr);
    val.bits = bits;
    return val;
}

SymbolicValue SymbolicValue::makeSymbolic8(z3::context& ctx, const std::string& name) {
    return makeSymbolic(ctx, name, 8);
}

SymbolicValue SymbolicValue::makeSymbolic32(z3::context& ctx, const std::string& name) {
    return makeSymbolic(ctx, name, 32);
}

SymbolicValue SymbolicValue::makeSymbolic64(z3::context& ctx, const std::string& name) {
    return makeSymbolic(ctx, name, 64);
}

SymbolicValue SymbolicValue::add(const SymbolicValue& other) const {
    if (type == ValueType::CONCRETE && other.type == ValueType::CONCRETE) {
        return SymbolicValue(concreteValue + other.concreteValue);
    }
    z3::expr left = toZ3Expr();
    z3::expr right = other.toZ3Expr();
    return SymbolicValue(left + right);
}

SymbolicValue SymbolicValue::sub(const SymbolicValue& other) const {
    if (type == ValueType::CONCRETE && other.type == ValueType::CONCRETE) {
        return SymbolicValue(concreteValue - other.concreteValue);
    }
    z3::expr left = toZ3Expr();
    z3::expr right = other.toZ3Expr();
    return SymbolicValue(left - right);
}

SymbolicValue SymbolicValue::mul(const SymbolicValue& other) const {
    if (type == ValueType::CONCRETE && other.type == ValueType::CONCRETE) {
        return SymbolicValue(concreteValue * other.concreteValue);
    }
    z3::expr left = toZ3Expr();
    z3::expr right = other.toZ3Expr();
    return SymbolicValue(left * right);
}

SymbolicValue SymbolicValue::div(const SymbolicValue& other) const {
    if (type == ValueType::CONCRETE && other.type == ValueType::CONCRETE) {
        if (other.concreteValue == 0) return SymbolicValue(0);  // Handle div by zero
        return SymbolicValue(concreteValue / other.concreteValue);
    }
    z3::expr left = toZ3Expr();
    z3::expr right = other.toZ3Expr();
    return SymbolicValue(z3::udiv(left, right));
}

SymbolicValue SymbolicValue::sdiv(const SymbolicValue& other) const {
    if (type == ValueType::CONCRETE && other.type == ValueType::CONCRETE) {
        if (other.concreteValue == 0) return SymbolicValue(0);
        return SymbolicValue(static_cast<int64_t>(concreteValue) / 
                             static_cast<int64_t>(other.concreteValue));
    }
    z3::expr left = toZ3Expr();
    z3::expr right = other.toZ3Expr();
    return SymbolicValue(left / right);
}

SymbolicValue SymbolicValue::mod(const SymbolicValue& other) const {
    if (type == ValueType::CONCRETE && other.type == ValueType::CONCRETE) {
        if (other.concreteValue == 0) return SymbolicValue(0);
        return SymbolicValue(concreteValue % other.concreteValue);
    }
    z3::expr left = toZ3Expr();
    z3::expr right = other.toZ3Expr();
    return SymbolicValue(z3::urem(left, right));
}

SymbolicValue SymbolicValue::smod(const SymbolicValue& other) const {
    if (type == ValueType::CONCRETE && other.type == ValueType::CONCRETE) {
        if (other.concreteValue == 0) return SymbolicValue(0);
        return SymbolicValue(static_cast<int64_t>(concreteValue) % 
                             static_cast<int64_t>(other.concreteValue));
    }
    z3::expr left = toZ3Expr();
    z3::expr right = other.toZ3Expr();
    return SymbolicValue(z3::srem(left, right));
}

SymbolicValue SymbolicValue::bitwise_and(const SymbolicValue& other) const {
    if (type == ValueType::CONCRETE && other.type == ValueType::CONCRETE) {
        return SymbolicValue(concreteValue & other.concreteValue);
    }
    z3::expr left = toZ3Expr();
    z3::expr right = other.toZ3Expr();
    return SymbolicValue(left & right);
}

SymbolicValue SymbolicValue::bitwise_or(const SymbolicValue& other) const {
    if (type == ValueType::CONCRETE && other.type == ValueType::CONCRETE) {
        return SymbolicValue(concreteValue | other.concreteValue);
    }
    z3::expr left = toZ3Expr();
    z3::expr right = other.toZ3Expr();
    return SymbolicValue(left | right);
}

SymbolicValue SymbolicValue::bitwise_xor(const SymbolicValue& other) const {
    if (type == ValueType::CONCRETE && other.type == ValueType::CONCRETE) {
        return SymbolicValue(concreteValue ^ other.concreteValue);
    }
    z3::expr left = toZ3Expr();
    z3::expr right = other.toZ3Expr();
    return SymbolicValue(left ^ right);
}

SymbolicValue SymbolicValue::bitwise_not() const {
    if (type == ValueType::CONCRETE) {
        return SymbolicValue(~concreteValue);
    }
    z3::expr expr = toZ3Expr();
    return SymbolicValue(~expr);
}

SymbolicValue SymbolicValue::shl(const SymbolicValue& other) const {
    if (type == ValueType::CONCRETE && other.type == ValueType::CONCRETE) {
        return SymbolicValue(concreteValue << other.concreteValue);
    }
    z3::expr left = toZ3Expr();
    z3::expr right = other.toZ3Expr();
    return SymbolicValue(z3::shl(left, right));
}

SymbolicValue SymbolicValue::lshr(const SymbolicValue& other) const {
    if (type == ValueType::CONCRETE && other.type == ValueType::CONCRETE) {
        return SymbolicValue(concreteValue >> other.concreteValue);
    }
    z3::expr left = toZ3Expr();
    z3::expr right = other.toZ3Expr();
    return SymbolicValue(z3::lshr(left, right));
}

SymbolicValue SymbolicValue::ashr(const SymbolicValue& other) const {
    if (type == ValueType::CONCRETE && other.type == ValueType::CONCRETE) {
        return SymbolicValue(static_cast<int64_t>(concreteValue) >> other.concreteValue);
    }
    z3::expr left = toZ3Expr();
    z3::expr right = other.toZ3Expr();
    return SymbolicValue(left >> right);
}

SymbolicValue SymbolicValue::eq(const SymbolicValue& other) const {
    if (type == ValueType::CONCRETE && other.type == ValueType::CONCRETE) {
        return SymbolicValue(concreteValue == other.concreteValue ? 1 : 0);
    }
    z3::expr left = toZ3Expr();
    z3::expr right = other.toZ3Expr();
    return SymbolicValue(z3::ite(left == right, z3::int_val(1), z3::int_val(0)));
}

SymbolicValue SymbolicValue::ne(const SymbolicValue& other) const {
    if (type == ValueType::CONCRETE && other.type == ValueType::CONCRETE) {
        return SymbolicValue(concreteValue != other.concreteValue ? 1 : 0);
    }
    z3::expr left = toZ3Expr();
    z3::expr right = other.toZ3Expr();
    return SymbolicValue(z3::ite(left != right, z3::int_val(1), z3::int_val(0)));
}

SymbolicValue SymbolicValue::ult(const SymbolicValue& other) const {
    if (type == ValueType::CONCRETE && other.type == ValueType::CONCRETE) {
        return SymbolicValue(concreteValue < other.concreteValue ? 1 : 0);
    }
    z3::expr left = toZ3Expr();
    z3::expr right = other.toZ3Expr();
    return SymbolicValue(z3::ite(z3::ult(left, right), z3::int_val(1), z3::int_val(0)));
}

SymbolicValue SymbolicValue::ule(const SymbolicValue& other) const {
    if (type == ValueType::CONCRETE && other.type == ValueType::CONCRETE) {
        return SymbolicValue(concreteValue <= other.concreteValue ? 1 : 0);
    }
    z3::expr left = toZ3Expr();
    z3::expr right = other.toZ3Expr();
    return SymbolicValue(z3::ite(z3::ule(left, right), z3::int_val(1), z3::int_val(0)));
}

SymbolicValue SymbolicValue::ugt(const SymbolicValue& other) const {
    if (type == ValueType::CONCRETE && other.type == ValueType::CONCRETE) {
        return SymbolicValue(concreteValue > other.concreteValue ? 1 : 0);
    }
    z3::expr left = toZ3Expr();
    z3::expr right = other.toZ3Expr();
    return SymbolicValue(z3::ite(z3::ugt(left, right), z3::int_val(1), z3::int_val(0)));
}

SymbolicValue SymbolicValue::uge(const SymbolicValue& other) const {
    if (type == ValueType::CONCRETE && other.type == ValueType::CONCRETE) {
        return SymbolicValue(concreteValue >= other.concreteValue ? 1 : 0);
    }
    z3::expr left = toZ3Expr();
    z3::expr right = other.toZ3Expr();
    return SymbolicValue(z3::ite(z3::uge(left, right), z3::int_val(1), z3::int_val(0)));
}

SymbolicValue SymbolicValue::slt(const SymbolicValue& other) const {
    if (type == ValueType::CONCRETE && other.type == ValueType::CONCRETE) {
        return SymbolicValue(static_cast<int64_t>(concreteValue) < 
                             static_cast<int64_t>(other.concreteValue) ? 1 : 0);
    }
    z3::expr left = toZ3Expr();
    z3::expr right = other.toZ3Expr();
    return SymbolicValue(z3::ite(left < right, z3::int_val(1), z3::int_val(0)));
}

SymbolicValue SymbolicValue::sle(const SymbolicValue& other) const {
    if (type == ValueType::CONCRETE && other.type == ValueType::CONCRETE) {
        return SymbolicValue(static_cast<int64_t>(concreteValue) <= 
                             static_cast<int64_t>(other.concreteValue) ? 1 : 0);
    }
    z3::expr left = toZ3Expr();
    z3::expr right = other.toZ3Expr();
    return SymbolicValue(z3::ite(left <= right, z3::int_val(1), z3::int_val(0)));
}

SymbolicValue SymbolicValue::sgt(const SymbolicValue& other) const {
    if (type == ValueType::CONCRETE && other.type == ValueType::CONCRETE) {
        return SymbolicValue(static_cast<int64_t>(concreteValue) > 
                             static_cast<int64_t>(other.concreteValue) ? 1 : 0);
    }
    z3::expr left = toZ3Expr();
    z3::expr right = other.toZ3Expr();
    return SymbolicValue(z3::ite(left > right, z3::int_val(1), z3::int_val(0)));
}

SymbolicValue SymbolicValue::sge(const SymbolicValue& other) const {
    if (type == ValueType::CONCRETE && other.type == ValueType::CONCRETE) {
        return SymbolicValue(static_cast<int64_t>(concreteValue) >= 
                             static_cast<int64_t>(other.concreteValue) ? 1 : 0);
    }
    z3::expr left = toZ3Expr();
    z3::expr right = other.toZ3Expr();
    return SymbolicValue(z3::ite(left >= right, z3::int_val(1), z3::int_val(0)));
}

SymbolicValue SymbolicValue::zeroExtend(size_t newBits) const {
    if (type == ValueType::CONCRETE) {
        return SymbolicValue(concreteValue);  // Value stays the same
    }
    z3::expr expr = toZ3Expr();
    return SymbolicValue(z3::zext(expr, newBits - bits));
}

SymbolicValue SymbolicValue::signExtend(size_t newBits) const {
    if (type == ValueType::CONCRETE) {
        // Sign extend concrete value
        if (bits == 8) {
            return SymbolicValue(static_cast<int64_t>(static_cast<int8_t>(concreteValue)));
        } else if (bits == 32) {
            return SymbolicValue(static_cast<int64_t>(static_cast<int32_t>(concreteValue)));
        }
        return SymbolicValue(concreteValue);
    }
    z3::expr expr = toZ3Expr();
    return SymbolicValue(z3::sext(expr, newBits - bits));
}

SymbolicValue SymbolicValue::extract(size_t high, size_t low) const {
    if (type == ValueType::CONCRETE) {
        uint64_t mask = ((1ULL << (high - low + 1)) - 1) << low;
        return SymbolicValue((concreteValue & mask) >> low);
    }
    z3::expr expr = toZ3Expr();
    return SymbolicValue(z3::extract(expr, high, low));
}

SymbolicValue SymbolicValue::concat(const SymbolicValue& other) const {
    if (type == ValueType::CONCRETE && other.type == ValueType::CONCRETE) {
        return SymbolicValue((concreteValue << other.bits) | other.concreteValue);
    }
    z3::expr left = toZ3Expr();
    z3::expr right = other.toZ3Expr();
    return SymbolicValue(z3::concat(left, right));
}

SymbolicValue SymbolicValue::ite(const SymbolicValue& cond, 
                                  const SymbolicValue& thenVal,
                                  const SymbolicValue& elseVal) {
    z3::expr condExpr = cond.toZ3Expr();
    z3::expr thenExpr = thenVal.toZ3Expr();
    z3::expr elseExpr = elseVal.toZ3Expr();
    return SymbolicValue(z3::ite(condExpr != 0, thenExpr, elseExpr));
}

z3::expr SymbolicValue::toZ3Expr() const {
    switch (type) {
        case ValueType::CONCRETE:
            return z3::int_val(concreteValue);
        case ValueType::SYMBOLIC:
            return symbolicValue;
        case ValueType::TOP:
        case ValueType::BOTTOM:
            return z3::int_val(0);
    }
    return z3::int_val(0);
}

std::string SymbolicValue::toString() const {
    std::ostringstream oss;
    switch (type) {
        case ValueType::CONCRETE:
            oss << "0x" << std::hex << concreteValue << std::dec;
            break;
        case ValueType::SYMBOLIC:
            oss << "sym(" << symbolicValue << ")";
            break;
        case ValueType::TOP:
            oss << "TOP";
            break;
        case ValueType::BOTTOM:
            oss << "BOTTOM";
            break;
    }
    return oss.str();
}

// ============================================================================
// RegisterFile Implementation
// ============================================================================

RegisterFile::RegisterFile() : ctx(nullptr) {
    initializeRegisters();
}

RegisterFile::RegisterFile(z3::context& c) : ctx(&c) {
    initializeRegisters();
}

void RegisterFile::initializeRegisters() {
    // x86-64 general purpose registers
    registers["rax"] = SymbolicValue(0);
    registers["rbx"] = SymbolicValue(0);
    registers["rcx"] = SymbolicValue(0);
    registers["rdx"] = SymbolicValue(0);
    registers["rsi"] = SymbolicValue(0);
    registers["rdi"] = SymbolicValue(0);
    registers["rbp"] = SymbolicValue(0);
    registers["rsp"] = SymbolicValue(0);
    registers["rip"] = SymbolicValue(0);
    registers["r8"] = SymbolicValue(0);
    registers["r9"] = SymbolicValue(0);
    registers["r10"] = SymbolicValue(0);
    registers["r11"] = SymbolicValue(0);
    registers["r12"] = SymbolicValue(0);
    registers["r13"] = SymbolicValue(0);
    registers["r14"] = SymbolicValue(0);
    registers["r15"] = SymbolicValue(0);
    
    // 32-bit aliases
    registers["eax"] = SymbolicValue(0);
    registers["ebx"] = SymbolicValue(0);
    registers["ecx"] = SymbolicValue(0);
    registers["edx"] = SymbolicValue(0);
    registers["esi"] = SymbolicValue(0);
    registers["edi"] = SymbolicValue(0);
    registers["ebp"] = SymbolicValue(0);
    registers["esp"] = SymbolicValue(0);
    
    // Flags
    registers["zf"] = SymbolicValue(0);  // Zero flag
    registers["sf"] = SymbolicValue(0);  // Sign flag
    registers["cf"] = SymbolicValue(0);  // Carry flag
    registers["of"] = SymbolicValue(0);  // Overflow flag
}

SymbolicValue RegisterFile::get(const std::string& regName) const {
    std::string name = regName;
    // Convert to lowercase for comparison
    for (auto& c : name) c = std::tolower(c);
    
    auto it = registers.find(name);
    if (it != registers.end()) {
        return it->second;
    }
    
    // Try to find 32-bit alias mapping to 64-bit
    // (simplified - real impl would handle partial register updates)
    return SymbolicValue(0);
}

void RegisterFile::set(const std::string& regName, const SymbolicValue& value) {
    std::string name = regName;
    for (auto& c : name) c = std::tolower(c);
    
    // Handle 32-bit to 64-bit register mapping
    if (name == "eax") {
        registers["rax"] = value.zeroExtend(64);
    } else if (name == "ebx") {
        registers["rbx"] = value.zeroExtend(64);
    } else if (name == "ecx") {
        registers["rcx"] = value.zeroExtend(64);
    } else if (name == "edx") {
        registers["rdx"] = value.zeroExtend(64);
    } else if (name == "esi") {
        registers["rsi"] = value.zeroExtend(64);
    } else if (name == "edi") {
        registers["rdi"] = value.zeroExtend(64);
    } else if (name == "ebp") {
        registers["rbp"] = value.zeroExtend(64);
    } else if (name == "esp") {
        registers["rsp"] = value.zeroExtend(64);
    } else {
        registers[name] = value;
    }
}

z3::expr RegisterFile::getExpr(const std::string& regName) const {
    return get(regName).toZ3Expr();
}

bool RegisterFile::hasRegister(const std::string& regName) const {
    return registers.count(regName) > 0;
}

std::vector<std::string> RegisterFile::getRegisterNames() const {
    std::vector<std::string> names;
    for (const auto& [name, _] : registers) {
        names.push_back(name);
    }
    return names;
}

uint64_t RegisterFile::getStackPointer() const {
    return get("rsp").getConcrete();
}

void RegisterFile::setStackPointer(const SymbolicValue& value) {
    set("rsp", value);
}

uint64_t RegisterFile::getInstructionPointer() const {
    return get("rip").getConcrete();
}

void RegisterFile::setInstructionPointer(const SymbolicValue& value) {
    set("rip", value);
}

uint64_t RegisterFile::getBasePointer() const {
    return get("rbp").getConcrete();
}

void RegisterFile::setBasePointer(const SymbolicValue& value) {
    set("rbp", value);
}

SymbolicValue RegisterFile::getFlag(const std::string& flagName) const {
    return get(flagName);
}

void RegisterFile::setFlag(const std::string& flagName, const SymbolicValue& value) {
    set(flagName, value);
}

SymbolicValue RegisterFile::getZF() const { return get("zf"); }
void RegisterFile::setZF(const SymbolicValue& value) { set("zf", value); }
SymbolicValue RegisterFile::getSF() const { return get("sf"); }
void RegisterFile::setSF(const SymbolicValue& value) { set("sf", value); }
SymbolicValue RegisterFile::getCF() const { return get("cf"); }
void RegisterFile::setCF(const SymbolicValue& value) { set("cf", value); }
SymbolicValue RegisterFile::getOF() const { return get("of"); }
void RegisterFile::setOF(const SymbolicValue& value) { set("of", value); }

RegisterFile RegisterFile::clone() const {
    RegisterFile copy;
    copy.registers = registers;
    copy.ctx = ctx;
    return copy;
}

std::string RegisterFile::toString() const {
    std::ostringstream oss;
    oss << "Register File:\n";
    oss << "  RAX: " << get("rax").toString() << "\n";
    oss << "  RBX: " << get("rbx").toString() << "\n";
    oss << "  RCX: " << get("rcx").toString() << "\n";
    oss << "  RDX: " << get("rdx").toString() << "\n";
    oss << "  RSI: " << get("rsi").toString() << "\n";
    oss << "  RDI: " << get("rdi").toString() << "\n";
    oss << "  RBP: " << get("rbp").toString() << "\n";
    oss << "  RSP: " << get("rsp").toString() << "\n";
    oss << "  RIP: " << get("rip").toString() << "\n";
    oss << "  ZF: " << getZF().getConcrete() << ", SF: " << getSF().getConcrete()
        << ", CF: " << getCF().getConcrete() << ", OF: " << getOF().getConcrete();
    return oss.str();
}

// ============================================================================
// MemoryModel Implementation
// ============================================================================

MemoryModel::MemoryModel() : ctx(nullptr), stackTop(0), stackBottom(0) {}

MemoryModel::MemoryModel(z3::context& c) : ctx(&c), stackTop(0), stackBottom(0) {}

SymbolicValue MemoryModel::read(uint64_t address, size_t size) const {
    auto it = memory.find(address);
    if (it != memory.end()) {
        return it->second.value;
    }
    return SymbolicValue(0);  // Return 0 for uninitialized memory
}

void MemoryModel::write(uint64_t address, const SymbolicValue& value, size_t size) {
    MemoryCell& cell = getCell(address);
    cell.value = value;
    cell.isSymbolic = value.isSymbolic();
}

SymbolicValue MemoryModel::readSymbolic(const SymbolicValue& address, size_t size) const {
    // For symbolic addresses, we would need to use array theory
    // This is a simplified version that returns a new symbolic value
    if (ctx) {
        return SymbolicValue::makeSymbolic(*ctx, "mem_read", size * 8);
    }
    return SymbolicValue(0);
}

void MemoryModel::writeSymbolic(const SymbolicValue& address, const SymbolicValue& value, size_t size) {
    // Simplified - real implementation would use Z3 array theory
    if (address.isConcrete()) {
        write(address.getConcrete(), value, size);
    }
}

void MemoryModel::addRegion(uint64_t start, uint64_t end, MemoryRegionType type,
                            bool readable, bool writable, bool executable,
                            const std::string& name) {
    MemoryRegion region;
    region.start = start;
    region.end = end;
    region.type = type;
    region.readable = readable;
    region.writable = writable;
    region.executable = executable;
    region.name = name;
    regions.push_back(region);
    
    if (type == MemoryRegionType::STACK) {
        stackBottom = start;
        stackTop = end;
    }
}

MemoryRegion* MemoryModel::getRegion(uint64_t address) {
    for (auto& region : regions) {
        if (region.contains(address)) {
            return &region;
        }
    }
    return nullptr;
}

const MemoryRegion* MemoryModel::getRegion(uint64_t address) const {
    for (const auto& region : regions) {
        if (region.contains(address)) {
            return &region;
        }
    }
    return nullptr;
}

bool MemoryModel::isValidAddress(uint64_t address) const {
    return getRegion(address) != nullptr;
}

bool MemoryModel::isReadable(uint64_t address) const {
    const MemoryRegion* region = getRegion(address);
    return region && region->readable;
}

bool MemoryModel::isWritable(uint64_t address) const {
    const MemoryRegion* region = getRegion(address);
    return region && region->writable;
}

bool MemoryModel::isExecutable(uint64_t address) const {
    const MemoryRegion* region = getRegion(address);
    return region && region->executable;
}

void MemoryModel::push(const SymbolicValue& value, size_t size) {
    if (stackTop == 0) {
        // Default stack setup
        stackBottom = 0x7ffff0000000;
        stackTop = stackBottom;
    }
    stackTop -= size;
    write(stackTop, value, size);
}

SymbolicValue MemoryModel::pop(size_t size) {
    SymbolicValue value = read(stackTop, size);
    stackTop += size;
    return value;
}

SymbolicValue MemoryModel::peek(size_t offset, size_t size) const {
    return read(stackTop + offset, size);
}

void MemoryModel::initializeFromBinary(uint64_t vaddr, const uint8_t* data, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        write(vaddr + i, SymbolicValue(data[i]), 1);
    }
}

std::vector<uint8_t> MemoryModel::getConcreteBytes(uint64_t address, size_t size) const {
    std::vector<uint8_t> bytes(size);
    for (size_t i = 0; i < size; ++i) {
        SymbolicValue val = read(address + i, 1);
        bytes[i] = val.isConcrete() ? static_cast<uint8_t>(val.getConcrete()) : 0;
    }
    return bytes;
}

MemoryModel MemoryModel::clone() const {
    MemoryModel copy;
    copy.memory = memory;
    copy.regions = regions;
    copy.ctx = ctx;
    copy.stackTop = stackTop;
    copy.stackBottom = stackBottom;
    return copy;
}

size_t MemoryModel::getMemoryUsage() const {
    return memory.size() * sizeof(MemoryCell);
}

size_t MemoryModel::getSymbolicCellCount() const {
    size_t count = 0;
    for (const auto& [addr, cell] : memory) {
        if (cell.isSymbolic) count++;
    }
    return count;
}

std::string MemoryModel::toString() const {
    std::ostringstream oss;
    oss << "Memory Model:\n";
    oss << "  Regions: " << regions.size() << "\n";
    oss << "  Used cells: " << memory.size() << "\n";
    oss << "  Symbolic cells: " << getSymbolicCellCount() << "\n";
    oss << "  Stack: 0x" << std::hex << stackBottom << " - 0x" << stackTop << std::dec;
    return oss.str();
}

std::string MemoryModel::dumpRegion(uint64_t start, size_t length) const {
    std::ostringstream oss;
    for (size_t i = 0; i < length; i += 16) {
        oss << std::hex << std::setw(8) << std::setfill('0') << (start + i) << ": ";
        for (size_t j = 0; j < 16 && i + j < length; ++j) {
            SymbolicValue val = read(start + i + j, 1);
            if (val.isConcrete()) {
                oss << std::setw(2) << std::setfill('0') << val.getConcrete() << " ";
            } else {
                oss << "?? ";
            }
        }
        oss << "\n";
    }
    return oss.str();
}

MemoryCell& MemoryModel::getCell(uint64_t address) {
    return memory[address];
}

const MemoryCell& MemoryModel::getCell(uint64_t address) const {
    static MemoryCell empty;
    auto it = memory.find(address);
    if (it != memory.end()) {
        return it->second;
    }
    return empty;
}

// ============================================================================
// SymbolicContext Implementation
// ============================================================================

SymbolicContext::SymbolicContext() : solver(ctx), symbolicVarCounter(0) {}

SymbolicContext::~SymbolicContext() {}

SymbolicValue SymbolicContext::makeSymbolic(const std::string& name, size_t bits) {
    std::string fullName = name + "_" + std::to_string(symbolicVarCounter++);
    return SymbolicValue::makeSymbolic(ctx, fullName, bits);
}

void SymbolicContext::pushSolverState() {
    solver.push();
}

void SymbolicContext::popSolverState() {
    solver.pop();
}

} // namespace symexec
