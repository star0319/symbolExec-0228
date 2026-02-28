#ifndef MEMORY_MODEL_H
#define MEMORY_MODEL_H

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <memory>
#include <z3/z3++.h>
#include <variant>

namespace symexec {

// Abstract value types
enum class ValueType {
    CONCRETE,    // Known concrete value
    SYMBOLIC,    // Symbolic expression
    TOP,         // Unknown/undefined (lattice top)
    BOTTOM       // Unreachable (lattice bottom)
};

// Forward declaration
class SymbolicValue;

// Memory region type
enum class MemoryRegionType {
    STACK,
    HEAP,
    GLOBAL,
    CODE,
    MMAP,
    UNKNOWN
};

// Memory region descriptor
struct MemoryRegion {
    uint64_t start;
    uint64_t end;
    MemoryRegionType type;
    bool readable;
    bool writable;
    bool executable;
    std::string name;
    
    MemoryRegion() : start(0), end(0), type(MemoryRegionType::UNKNOWN),
                     readable(true), writable(true), executable(false) {}
    
    uint64_t size() const { return end - start; }
    bool contains(uint64_t addr) const { return addr >= start && addr < end; }
};

// Symbolic value class - represents concrete or symbolic data
class SymbolicValue {
public:
    SymbolicValue();
    explicit SymbolicValue(uint64_t concrete);
    explicit SymbolicValue(z3::expr symbolic);
    
    // Create symbolic variable
    static SymbolicValue makeSymbolic(z3::context& ctx, const std::string& name, size_t bits = 64);
    static SymbolicValue makeSymbolic8(z3::context& ctx, const std::string& name);
    static SymbolicValue makeSymbolic32(z3::context& ctx, const std::string& name);
    static SymbolicValue makeSymbolic64(z3::context& ctx, const std::string& name);
    
    // Value type
    ValueType getType() const { return type; }
    
    // Check if concrete
    bool isConcrete() const { return type == ValueType::CONCRETE; }
    bool isSymbolic() const { return type == ValueType::SYMBOLIC; }
    
    // Get concrete value (undefined if symbolic)
    uint64_t getConcrete() const { return concreteValue; }
    
    // Get symbolic expression (undefined if concrete)
    z3::expr getSymbolic() const { return symbolicValue; }
    
    // Get bit width
    size_t getBits() const { return bits; }
    
    // Operations
    SymbolicValue add(const SymbolicValue& other) const;
    SymbolicValue sub(const SymbolicValue& other) const;
    SymbolicValue mul(const SymbolicValue& other) const;
    SymbolicValue div(const SymbolicValue& other) const;
    SymbolicValue sdiv(const SymbolicValue& other) const;  // Signed div
    SymbolicValue mod(const SymbolicValue& other) const;
    SymbolicValue smod(const SymbolicValue& other) const;  // Signed mod
    SymbolicValue bitwise_and(const SymbolicValue& other) const;
    SymbolicValue bitwise_or(const SymbolicValue& other) const;
    SymbolicValue bitwise_xor(const SymbolicValue& other) const;
    SymbolicValue bitwise_not() const;
    SymbolicValue shl(const SymbolicValue& other) const;
    SymbolicValue lshr(const SymbolicValue& other) const;  // Logical shift right
    SymbolicValue ashr(const SymbolicValue& other) const;  // Arithmetic shift right
    
    // Comparison (returns symbolic bool)
    SymbolicValue eq(const SymbolicValue& other) const;
    SymbolicValue ne(const SymbolicValue& other) const;
    SymbolicValue ult(const SymbolicValue& other) const;  // Unsigned less than
    SymbolicValue ule(const SymbolicValue& other) const;
    SymbolicValue ugt(const SymbolicValue& other) const;
    SymbolicValue uge(const SymbolicValue& other) const;
    SymbolicValue slt(const SymbolicValue& other) const;  // Signed less than
    SymbolicValue sle(const SymbolicValue& other) const;
    SymbolicValue sgt(const SymbolicValue& other) const;
    SymbolicValue sge(const SymbolicValue& other) const;
    
    // Sign/zero extension
    SymbolicValue zeroExtend(size_t newBits) const;
    SymbolicValue signExtend(size_t newBits) const;
    SymbolicValue extract(size_t high, size_t low) const;
    
    // Concatenation
    SymbolicValue concat(const SymbolicValue& other) const;
    
    // ITE (if-then-else)
    static SymbolicValue ite(const SymbolicValue& cond, 
                             const SymbolicValue& thenVal,
                             const SymbolicValue& elseVal);
    
    // Convert to Z3 expression (for constraint solving)
    z3::expr toZ3Expr() const;
    
    // String representation
    std::string toString() const;

private:
    ValueType type;
    uint64_t concreteValue;
    z3::expr symbolicValue;
    size_t bits;
};

// Memory cell - holds a symbolic value
struct MemoryCell {
    SymbolicValue value;
    bool isSymbolic;
    std::string symbolicName;
    
    MemoryCell() : isSymbolic(false) {}
    explicit MemoryCell(const SymbolicValue& v) : value(v), isSymbolic(v.isSymbolic()) {}
};

// Register file
class RegisterFile {
public:
    RegisterFile();
    explicit RegisterFile(z3::context& ctx);
    
    // Get/set registers
    SymbolicValue get(const std::string& regName) const;
    void set(const std::string& regName, const SymbolicValue& value);
    
    // Get register value as Z3 expr
    z3::expr getExpr(const std::string& regName) const;
    
    // Check if register exists
    bool hasRegister(const std::string& regName) const;
    
    // Get all register names
    std::vector<std::string> getRegisterNames() const;
    
    // Architecture-specific registers
    uint64_t getStackPointer() const;
    void setStackPointer(const SymbolicValue& value);
    uint64_t getInstructionPointer() const;
    void setInstructionPointer(const SymbolicValue& value);
    uint64_t getBasePointer() const;
    void setBasePointer(const SymbolicValue& value);
    
    // Flags
    SymbolicValue getFlag(const std::string& flagName) const;
    void setFlag(const std::string& flagName, const SymbolicValue& value);
    
    // Zero flag, sign flag, carry flag, overflow flag
    SymbolicValue getZF() const;
    void setZF(const SymbolicValue& value);
    SymbolicValue getSF() const;
    void setSF(const SymbolicValue& value);
    SymbolicValue getCF() const;
    void setCF(const SymbolicValue& value);
    SymbolicValue getOF() const;
    void setOF(const SymbolicValue& value);
    
    // Copy register file
    RegisterFile clone() const;
    
    // String representation
    std::string toString() const;

private:
    std::map<std::string, SymbolicValue> registers;
    z3::context* ctx;
    
    void initializeRegisters();
};

// Memory model
class MemoryModel {
public:
    MemoryModel();
    explicit MemoryModel(z3::context& ctx);
    
    // Memory operations
    SymbolicValue read(uint64_t address, size_t size) const;
    void write(uint64_t address, const SymbolicValue& value, size_t size);
    
    // Read/write with symbolic addresses (returns ITE expression)
    SymbolicValue readSymbolic(const SymbolicValue& address, size_t size) const;
    void writeSymbolic(const SymbolicValue& address, const SymbolicValue& value, size_t size);
    
    // Memory regions
    void addRegion(uint64_t start, uint64_t end, MemoryRegionType type,
                   bool readable = true, bool writable = true, bool executable = false,
                   const std::string& name = "");
    
    MemoryRegion* getRegion(uint64_t address);
    const MemoryRegion* getRegion(uint64_t address) const;
    
    // Check if address is valid
    bool isValidAddress(uint64_t address) const;
    bool isReadable(uint64_t address) const;
    bool isWritable(uint64_t address) const;
    bool isExecutable(uint64_t address) const;
    
    // Stack operations
    void push(const SymbolicValue& value, size_t size = 8);
    SymbolicValue pop(size_t size = 8);
    SymbolicValue peek(size_t offset = 0, size_t size = 8) const;
    
    // Initialize memory from binary data
    void initializeFromBinary(uint64_t vaddr, const uint8_t* data, size_t size);
    
    // Get concrete memory content (for concrete regions)
    std::vector<uint8_t> getConcreteBytes(uint64_t address, size_t size) const;
    
    // Clone memory model
    MemoryModel clone() const;
    
    // Statistics
    size_t getMemoryUsage() const;
    size_t getSymbolicCellCount() const;
    
    // String representation
    std::string toString() const;
    std::string dumpRegion(uint64_t start, size_t length) const;

private:
    std::map<uint64_t, MemoryCell> memory;  // Address -> Cell
    std::vector<MemoryRegion> regions;
    z3::context* ctx;
    uint64_t stackTop;
    uint64_t stackBottom;
    
    // Helper to get cell with default value
    MemoryCell& getCell(uint64_t address);
    const MemoryCell& getCell(uint64_t address) const;
};

// Global context for symbolic execution
class SymbolicContext {
public:
    SymbolicContext();
    ~SymbolicContext();
    
    z3::context& getZ3Context() { return ctx; }
    z3::solver& getSolver() { return solver; }
    
    // Create new symbolic variable
    SymbolicValue makeSymbolic(const std::string& name, size_t bits = 64);
    
    // Push/pop solver state
    void pushSolverState();
    void popSolverState();

private:
    z3::context ctx;
    z3::solver solver;
    uint64_t symbolicVarCounter;
};

} // namespace symexec

#endif // MEMORY_MODEL_H
