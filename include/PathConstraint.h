#ifndef PATH_CONSTRAINT_H
#define PATH_CONSTRAINT_H

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <z3++.h>
#include "MemoryModel.h"

namespace symexec {

// Constraint type
enum class ConstraintType {
    EQUALITY,       // ==
    INEQUALITY,     // !=
    LESS_THAN,      // < (unsigned)
    LESS_EQUAL,     // <= (unsigned)
    GREATER_THAN,   // > (unsigned)
    GREATER_EQUAL,  // >= (unsigned)
    SLESS_THAN,     // < (signed)
    SLESS_EQUAL,    // <= (signed)
    SGREATER_THAN,  // > (signed)
    SGREATER_EQUAL, // >= (signed)
    AND,            // &&
    OR,             // ||
    NOT,            // !
    CUSTOM          // Custom Z3 expression
};

// Single constraint representation
struct Constraint {
    ConstraintType type;
    SymbolicValue left;
    SymbolicValue right;  // For unary operations, this is unused
    z3::expr customExpr;  // For CUSTOM type
    std::string description;
    uint64_t pc;  // Program counter where constraint was added
    
    Constraint() : type(ConstraintType::EQUALITY), pc(0) {}
    
    // Create equality constraint
    static Constraint createEq(const SymbolicValue& l, const SymbolicValue& r, uint64_t pc = 0) {
        Constraint c;
        c.type = ConstraintType::EQUALITY;
        c.left = l;
        c.right = r;
        c.pc = pc;
        return c;
    }
    
    // Create inequality constraint
    static Constraint createNe(const SymbolicValue& l, const SymbolicValue& r, uint64_t pc = 0) {
        Constraint c;
        c.type = ConstraintType::INEQUALITY;
        c.left = l;
        c.right = r;
        c.pc = pc;
        return c;
    }
    
    // Create less-than constraint (unsigned)
    static Constraint createUlt(const SymbolicValue& l, const SymbolicValue& r, uint64_t pc = 0) {
        Constraint c;
        c.type = ConstraintType::LESS_THAN;
        c.left = l;
        c.right = r;
        c.pc = pc;
        return c;
    }
    
    // Create custom constraint
    static Constraint createCustom(const z3::expr& expr, const std::string& desc = "", uint64_t pc = 0) {
        Constraint c;
        c.type = ConstraintType::CUSTOM;
        c.customExpr = expr;
        c.description = desc;
        c.pc = pc;
        return c;
    }
    
    // Convert to Z3 expression
    z3::expr toZ3Expr(z3::context& ctx) const;
    
    // Get negated constraint (for path exploration)
    Constraint negate() const;
    
    // String representation
    std::string toString() const;
};

// Path constraint manager
class PathConstraintManager {
public:
    PathConstraintManager();
    explicit PathConstraintManager(z3::context& ctx);
    ~PathConstraintManager() = default;
    
    // Add constraint to current path
    void addConstraint(const Constraint& constraint);
    void addConstraint(const z3::expr& expr, const std::string& desc = "");
    
    // Get all constraints in current path
    std::vector<Constraint> getConstraints() const { return constraints; }
    
    // Get all constraints as Z3 expressions
    std::vector<z3::expr> getZ3Constraints() const;
    
    // Get combined constraint (conjunction of all)
    z3::expr getAllConstraints() const;
    
    // Push constraint context (for branching)
    void push();
    
    // Pop constraint context
    void pop();
    
    // Clear all constraints
    void clear();
    
    // Check satisfiability
    z3::check_result check(z3::solver& solver) const;
    
    // Get model (solution)
    z3::model getModel(z3::solver& solver) const;
    
    // Get constraint at specific index
    const Constraint& getConstraint(size_t index) const;
    
    // Get number of constraints
    size_t size() const { return constraints.size(); }
    
    // Get constraints added at specific PC
    std::vector<Constraint> getConstraintsAtPC(uint64_t pc) const;
    
    // Export constraints to SMT-LIB format
    std::string toSMTLIB() const;
    
    // Statistics
    size_t getEqualityCount() const;
    size_t getInequalityCount() const;
    size_t getComparisonCount() const;

private:
    std::vector<Constraint> constraints;
    std::vector<std::vector<Constraint>> constraintStack;  // For push/pop
    z3::context* ctx;
};

// Branch record - represents a decision point
struct BranchRecord {
    uint64_t pc;              // Program counter at branch
    uint64_t trueTarget;      // Target if condition is true
    uint64_t falseTarget;     // Target if condition is false
    Constraint condition;     // Branch condition
    bool taken;               // Whether branch was taken
    std::vector<Constraint> pathConstraints;  // Constraints at this point
    
    BranchRecord() : pc(0), trueTarget(0), falseTarget(0), taken(false) {}
};

// Path representation - complete execution path
class ExecutionPath {
public:
    ExecutionPath() : pathId(0), isFeasible(true) {}
    
    // Add branch to path
    void addBranch(const BranchRecord& branch);
    
    // Add constraint to path
    void addConstraint(const Constraint& constraint);
    
    // Get all branches
    std::vector<BranchRecord> getBranches() const { return branches; }
    
    // Get all constraints
    std::vector<Constraint> getConstraints() const { return pathConstraints; }
    
    // Get path predicate (formula representing this path)
    z3::expr getPathPredicate(z3::context& ctx) const;
    
    // Check if path is feasible
    bool checkFeasibility(z3::solver& solver) const;
    
    // Get path length (number of branches)
    size_t getLength() const { return branches.size(); }
    
    // Get path ID
    uint64_t getId() const { return pathId; }
    void setId(uint64_t id) { pathId = id; }
    
    // String representation
    std::string toString() const;
    
    // Export to DOT format
    std::string toDOT() const;

private:
    uint64_t pathId;
    std::vector<BranchRecord> branches;
    std::vector<Constraint> pathConstraints;
    bool isFeasible;
    static uint64_t nextId;
};

// Helper functions for constraint manipulation
namespace ConstraintUtils {

// Negate a Z3 expression
z3::expr negateExpr(const z3::expr& expr);

// Simplify constraints
std::vector<z3::expr> simplifyConstraints(const std::vector<z3::expr>& constraints, 
                                           z3::context& ctx);

// Extract symbolic variables from expression
std::vector<z3::app> extractVariables(const z3::expr& expr);

// Create range constraint (min <= x <= max)
z3::expr createRangeConstraint(const z3::expr& var, uint64_t min, uint64_t max);

// Create non-null constraint
z3::expr createNonNullConstraint(const z3::expr& var);

} // namespace ConstraintUtils

} // namespace symexec

#endif // PATH_CONSTRAINT_H
