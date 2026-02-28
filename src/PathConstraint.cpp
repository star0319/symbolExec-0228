#include "PathConstraint.h"
#include <sstream>
#include <iostream>

namespace symexec {

uint64_t ExecutionPath::nextId = 0;

// ============================================================================
// Constraint Implementation
// ============================================================================

z3::expr Constraint::toZ3Expr(z3::context& ctx) const {
    switch (type) {
        case ConstraintType::EQUALITY:
            return left.toZ3Expr() == right.toZ3Expr();
            
        case ConstraintType::INEQUALITY:
            return left.toZ3Expr() != right.toZ3Expr();
            
        case ConstraintType::LESS_THAN:
            return z3::ult(left.toZ3Expr(), right.toZ3Expr());
            
        case ConstraintType::LESS_EQUAL:
            return z3::ule(left.toZ3Expr(), right.toZ3Expr());
            
        case ConstraintType::GREATER_THAN:
            return z3::ugt(left.toZ3Expr(), right.toZ3Expr());
            
        case ConstraintType::GREATER_EQUAL:
            return z3::uge(left.toZ3Expr(), right.toZ3Expr());
            
        case ConstraintType::SLESS_THAN:
            return left.toZ3Expr() < right.toZ3Expr();
            
        case ConstraintType::SLESS_EQUAL:
            return left.toZ3Expr() <= right.toZ3Expr();
            
        case ConstraintType::SGREATER_THAN:
            return left.toZ3Expr() > right.toZ3Expr();
            
        case ConstraintType::SGREATER_EQUAL:
            return left.toZ3Expr() >= right.toZ3Expr();
            
        case ConstraintType::AND:
            return left.toZ3Expr() && right.toZ3Expr();
            
        case ConstraintType::OR:
            return left.toZ3Expr() || right.toZ3Expr();
            
        case ConstraintType::NOT:
            return !left.toZ3Expr();
            
        case ConstraintType::CUSTOM:
            return customExpr;
    }
    return z3::bool_val(true);
}

Constraint Constraint::negate() const {
    Constraint negated = *this;
    
    switch (type) {
        case ConstraintType::EQUALITY:
            negated.type = ConstraintType::INEQUALITY;
            break;
        case ConstraintType::INEQUALITY:
            negated.type = ConstraintType::EQUALITY;
            break;
        case ConstraintType::LESS_THAN:
            negated.type = ConstraintType::GREATER_EQUAL;
            break;
        case ConstraintType::LESS_EQUAL:
            negated.type = ConstraintType::GREATER_THAN;
            break;
        case ConstraintType::GREATER_THAN:
            negated.type = ConstraintType::LESS_EQUAL;
            break;
        case ConstraintType::GREATER_EQUAL:
            negated.type = ConstraintType::LESS_THAN;
            break;
        case ConstraintType::SLESS_THAN:
            negated.type = ConstraintType::SGREATER_EQUAL;
            break;
        case ConstraintType::SLESS_EQUAL:
            negated.type = ConstraintType::SGREATER_THAN;
            break;
        case ConstraintType::SGREATER_THAN:
            negated.type = ConstraintType::SLESS_EQUAL;
            break;
        case ConstraintType::SGREATER_EQUAL:
            negated.type = ConstraintType::SLESS_THAN;
            break;
        case ConstraintType::AND:
            negated.type = ConstraintType::OR;
            negated.left = left;  // Would need De Morgan's law for complete negation
            negated.right = right;
            break;
        case ConstraintType::OR:
            negated.type = ConstraintType::AND;
            break;
        case ConstraintType::NOT:
            negated.type = ConstraintType::CUSTOM;
            negated.customExpr = left.toZ3Expr();
            break;
        case ConstraintType::CUSTOM:
            negated.customExpr = !customExpr;
            break;
    }
    
    return negated;
}

std::string Constraint::toString() const {
    std::ostringstream oss;
    
    if (!description.empty()) {
        oss << description << ": ";
    }
    
    oss << "(" << left.toString();
    
    switch (type) {
        case ConstraintType::EQUALITY: oss << " == "; break;
        case ConstraintType::INEQUALITY: oss << " != "; break;
        case ConstraintType::LESS_THAN: oss << " <u "; break;
        case ConstraintType::LESS_EQUAL: oss << " <=u "; break;
        case ConstraintType::GREATER_THAN: oss << " >u "; break;
        case ConstraintType::GREATER_EQUAL: oss << " >=u "; break;
        case ConstraintType::SLESS_THAN: oss << " <s "; break;
        case ConstraintType::SLESS_EQUAL: oss << " <=s "; break;
        case ConstraintType::SGREATER_THAN: oss << " >s "; break;
        case ConstraintType::SGREATER_EQUAL: oss << " >=s "; break;
        case ConstraintType::AND: oss << " && "; break;
        case ConstraintType::OR: oss << " || "; break;
        case ConstraintType::NOT: oss << " !"; break;
        case ConstraintType::CUSTOM: oss << " custom "; break;
    }
    
    if (type != ConstraintType::NOT) {
        oss << right.toString();
    }
    
    oss << ")";
    
    if (pc != 0) {
        oss << " @ 0x" << std::hex << pc;
    }
    
    return oss.str();
}

// ============================================================================
// PathConstraintManager Implementation
// ============================================================================

PathConstraintManager::PathConstraintManager() : ctx(nullptr) {}

PathConstraintManager::PathConstraintManager(z3::context& c) : ctx(&c) {}

void PathConstraintManager::addConstraint(const Constraint& constraint) {
    constraints.push_back(constraint);
}

void PathConstraintManager::addConstraint(const z3::expr& expr, const std::string& desc) {
    Constraint c;
    c.type = ConstraintType::CUSTOM;
    c.customExpr = expr;
    c.description = desc;
    constraints.push_back(c);
}

std::vector<z3::expr> PathConstraintManager::getZ3Constraints() const {
    std::vector<z3::expr> exprs;
    for (const auto& c : constraints) {
        if (ctx) {
            exprs.push_back(c.toZ3Expr(*ctx));
        }
    }
    return exprs;
}

z3::expr PathConstraintManager::getAllConstraints() const {
    if (constraints.empty()) {
        return z3::bool_val(true);
    }
    
    z3::expr all = constraints[0].toZ3Expr(*ctx);
    for (size_t i = 1; i < constraints.size(); ++i) {
        all = all && constraints[i].toZ3Expr(*ctx);
    }
    return all;
}

void PathConstraintManager::push() {
    constraintStack.push_back(constraints);
}

void PathConstraintManager::pop() {
    if (!constraintStack.empty()) {
        constraints = constraintStack.back();
        constraintStack.pop_back();
    }
}

void PathConstraintManager::clear() {
    constraints.clear();
    constraintStack.clear();
}

z3::check_result PathConstraintManager::check(z3::solver& solver) const {
    solver.push();
    for (const auto& c : constraints) {
        solver.add(c.toZ3Expr(*ctx));
    }
    z3::check_result result = solver.check();
    solver.pop();
    return result;
}

z3::model PathConstraintManager::getModel(z3::solver& solver) const {
    solver.push();
    for (const auto& c : constraints) {
        solver.add(c.toZ3Expr(*ctx));
    }
    solver.check();
    z3::model model = solver.get_model();
    solver.pop();
    return model;
}

const Constraint& PathConstraintManager::getConstraint(size_t index) const {
    return constraints[index];
}

std::vector<Constraint> PathConstraintManager::getConstraintsAtPC(uint64_t pc) const {
    std::vector<Constraint> result;
    for (const auto& c : constraints) {
        if (c.pc == pc) {
            result.push_back(c);
        }
    }
    return result;
}

std::string PathConstraintManager::toSMTLIB() const {
    std::ostringstream oss;
    oss << "(set-logic QF_BV)\n";
    
    // Declare variables (simplified)
    oss << "; Constraints:\n";
    for (const auto& c : constraints) {
        oss << "; " << c.toString() << "\n";
    }
    
    // Assert constraints
    oss << "(assert\n";
    for (const auto& c : constraints) {
        oss << "  ; " << c.toString() << "\n";
    }
    oss << "  true\n";
    oss << ")\n";
    oss << "(check-sat)\n";
    oss << "(get-model)\n";
    
    return oss.str();
}

size_t PathConstraintManager::getEqualityCount() const {
    size_t count = 0;
    for (const auto& c : constraints) {
        if (c.type == ConstraintType::EQUALITY) count++;
    }
    return count;
}

size_t PathConstraintManager::getInequalityCount() const {
    size_t count = 0;
    for (const auto& c : constraints) {
        if (c.type == ConstraintType::INEQUALITY) count++;
    }
    return count;
}

size_t PathConstraintManager::getComparisonCount() const {
    size_t count = 0;
    for (const auto& c : constraints) {
        if (c.type >= ConstraintType::LESS_THAN && 
            c.type <= ConstraintType::SGREATER_EQUAL) {
            count++;
        }
    }
    return count;
}

// ============================================================================
// ExecutionPath Implementation
// ============================================================================

void ExecutionPath::addBranch(const BranchRecord& branch) {
    branches.push_back(branch);
    pathId = nextId++;
}

void ExecutionPath::addConstraint(const Constraint& constraint) {
    pathConstraints.push_back(constraint);
}

z3::expr ExecutionPath::getPathPredicate(z3::context& ctx) const {
    if (pathConstraints.empty()) {
        return z3::bool_val(true);
    }
    
    z3::expr predicate = pathConstraints[0].toZ3Expr(ctx);
    for (size_t i = 1; i < pathConstraints.size(); ++i) {
        predicate = predicate && pathConstraints[i].toZ3Expr(ctx);
    }
    return predicate;
}

bool ExecutionPath::checkFeasibility(z3::solver& solver) const {
    solver.push();
    for (const auto& c : pathConstraints) {
        solver.add(c.toZ3Expr(solver.ctx()));
    }
    z3::check_result result = solver.check();
    solver.pop();
    isFeasible = (result == z3::sat);
    return isFeasible;
}

std::string ExecutionPath::toString() const {
    std::ostringstream oss;
    oss << "Execution Path #" << pathId << "\n";
    oss << "Length: " << branches.size() << " branches\n";
    oss << "Feasible: " << (isFeasible ? "Yes" : "No") << "\n\n";
    
    oss << "Branches:\n";
    for (size_t i = 0; i < branches.size(); ++i) {
        const auto& b = branches[i];
        oss << "  " << i << ": 0x" << std::hex << b.pc << std::dec;
        oss << " -> 0x" << (b.taken ? b.trueTarget : b.falseTarget);
        oss << " (" << (b.taken ? "T" : "F") << ")\n";
    }
    
    oss << "\nConstraints:\n";
    for (const auto& c : pathConstraints) {
        oss << "  " << c.toString() << "\n";
    }
    
    return oss.str();
}

std::string ExecutionPath::toDOT() const {
    std::ostringstream oss;
    oss << "digraph Path {\n";
    oss << "  rankdir=LR;\n";
    oss << "  node [shape=circle];\n";
    oss << "  start [shape=point, label=\"\"];\n";
    
    uint64_t prevNode = 0;
    for (size_t i = 0; i < branches.size(); ++i) {
        const auto& b = branches[i];
        uint64_t currNode = i + 1;
        
        oss << "  n" << currNode << " [label=\"0x" << std::hex << b.pc << "\"];\n";
        
        if (i == 0) {
            oss << "  start -> n" << currNode << ";\n";
        } else {
            oss << "  n" << prevNode << " -> n" << currNode << ";\n";
        }
        
        prevNode = currNode;
    }
    
    oss << "}\n";
    return oss.str();
}

// ============================================================================
// ConstraintUtils Implementation
// ============================================================================

namespace ConstraintUtils {

z3::expr negateExpr(const z3::expr& expr) {
    if (expr.is_not()) {
        return expr.arg(0);
    }
    return !expr;
}

std::vector<z3::expr> simplifyConstraints(const std::vector<z3::expr>& constraints,
                                           z3::context& ctx) {
    std::vector<z3::expr> simplified;
    for (const auto& c : constraints) {
        simplified.push_back(c.simplify());
    }
    return simplified;
}

std::vector<z3::app> extractVariables(const z3::expr& expr) {
    std::vector<z3::app> vars;
    
    if (expr.is_app()) {
        if (expr.is_const() && expr.get_sort().is_bv()) {
            vars.push_back(expr);
        }
        for (unsigned i = 0; i < expr.num_args(); ++i) {
            auto childVars = extractVariables(expr.arg(i));
            vars.insert(vars.end(), childVars.begin(), childVars.end());
        }
    }
    
    return vars;
}

z3::expr createRangeConstraint(const z3::expr& var, uint64_t min, uint64_t max) {
    return z3::uge(var, z3::int_val(min)) && z3::ule(var, z3::int_val(max));
}

z3::expr createNonNullConstraint(const z3::expr& var) {
    return var != z3::int_val(0);
}

} // namespace ConstraintUtils

} // namespace symexec
