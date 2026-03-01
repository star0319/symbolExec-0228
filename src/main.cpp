#include <capstone/capstone.h>
#include <z3/z3++.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace symexec {

constexpr uint8_t EI_CLASS = 4;
constexpr uint8_t EI_DATA = 5;
constexpr uint8_t ELFCLASS32 = 1;
constexpr uint8_t ELFCLASS64 = 2;
constexpr uint8_t ELFDATA2LSB = 1;
constexpr uint32_t PT_LOAD = 1;
constexpr uint32_t PF_X = 0x1;
constexpr uint32_t PF_W = 0x2;
constexpr uint32_t PF_R = 0x4;
constexpr uint16_t EM_X86 = 3;
constexpr uint16_t EM_X86_64 = 62;

struct Elf64_Ehdr {
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct Elf64_Phdr {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};

struct Elf64_Shdr {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
};

struct Elf32_Ehdr {
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint32_t e_entry;
    uint32_t e_phoff;
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct Elf32_Phdr {
    uint32_t p_type;
    uint32_t p_offset;
    uint32_t p_vaddr;
    uint32_t p_paddr;
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t p_flags;
    uint32_t p_align;
};

struct Segment {
    uint64_t vaddr = 0;
    uint64_t memsz = 0;
    uint64_t filesz = 0;
    uint64_t offset = 0;
    bool r = false;
    bool w = false;
    bool x = false;
};

struct ElfBinary {
    std::string path;
    std::vector<uint8_t> raw;
    uint64_t entry = 0;
    bool is64 = true;
    uint16_t machine = 0;
    uint64_t text_addr = 0;
    std::vector<uint8_t> text_bytes;
    std::vector<Segment> segments;
    bool ok = false;
    std::string error;
};

class ElfLoader {
public:
    static ElfBinary load(const std::string& path) {
        ElfBinary bin;
        bin.path = path;

        std::ifstream ifs(path, std::ios::binary | std::ios::ate);
        if (!ifs) {
            bin.error = "open file failed";
            return bin;
        }
        const auto size = static_cast<size_t>(ifs.tellg());
        ifs.seekg(0);
        bin.raw.resize(size);
        if (!ifs.read(reinterpret_cast<char*>(bin.raw.data()), static_cast<std::streamsize>(size))) {
            bin.error = "read file failed";
            return bin;
        }
        if (size < 16) {
            bin.error = "not an elf";
            return bin;
        }

        if (!(bin.raw[0] == 0x7f && bin.raw[1] == 'E' && bin.raw[2] == 'L' && bin.raw[3] == 'F')) {
            bin.error = "invalid elf magic";
            return bin;
        }
        if (bin.raw[EI_DATA] != ELFDATA2LSB) {
            bin.error = "only little-endian supported";
            return bin;
        }

        if (bin.raw[EI_CLASS] == ELFCLASS64) {
            parse64(bin);
        } else if (bin.raw[EI_CLASS] == ELFCLASS32) {
            parse32(bin);
        } else {
            bin.error = "unknown elf class";
            return bin;
        }
        if (!bin.ok && bin.error.empty()) {
            bin.error = "elf parse failed";
        }
        return bin;
    }

private:
    static void parse64(ElfBinary& bin) {
        if (bin.raw.size() < sizeof(Elf64_Ehdr)) {
            bin.error = "elf64 header too short";
            return;
        }

        auto* eh = reinterpret_cast<const Elf64_Ehdr*>(bin.raw.data());
        bin.is64 = true;
        bin.entry = eh->e_entry;
        bin.machine = eh->e_machine;

        if (eh->e_phoff && eh->e_phnum) {
            for (uint16_t i = 0; i < eh->e_phnum; ++i) {
                const auto off = eh->e_phoff + static_cast<uint64_t>(i) * eh->e_phentsize;
                if (off + sizeof(Elf64_Phdr) > bin.raw.size()) {
                    continue;
                }
                auto* ph = reinterpret_cast<const Elf64_Phdr*>(bin.raw.data() + off);
                if (ph->p_type == PT_LOAD) {
                    Segment s;
                    s.vaddr = ph->p_vaddr;
                    s.memsz = ph->p_memsz;
                    s.filesz = ph->p_filesz;
                    s.offset = ph->p_offset;
                    s.r = (ph->p_flags & PF_R) != 0;
                    s.w = (ph->p_flags & PF_W) != 0;
                    s.x = (ph->p_flags & PF_X) != 0;
                    bin.segments.push_back(s);
                }
            }
        }

        if (eh->e_shoff && eh->e_shnum) {
            const auto shstr_off = eh->e_shoff + static_cast<uint64_t>(eh->e_shstrndx) * eh->e_shentsize;
            if (shstr_off + sizeof(Elf64_Shdr) <= bin.raw.size()) {
                auto* shstr = reinterpret_cast<const Elf64_Shdr*>(bin.raw.data() + shstr_off);
                if (shstr->sh_offset + shstr->sh_size <= bin.raw.size()) {
                    const char* names = reinterpret_cast<const char*>(bin.raw.data() + shstr->sh_offset);
                    for (uint16_t i = 0; i < eh->e_shnum; ++i) {
                        const auto off = eh->e_shoff + static_cast<uint64_t>(i) * eh->e_shentsize;
                        if (off + sizeof(Elf64_Shdr) > bin.raw.size()) {
                            continue;
                        }
                        auto* sh = reinterpret_cast<const Elf64_Shdr*>(bin.raw.data() + off);
                        const char* sec_name = (sh->sh_name < shstr->sh_size) ? names + sh->sh_name : "";
                        if (std::string(sec_name) == ".text") {
                            if (sh->sh_offset + sh->sh_size <= bin.raw.size()) {
                                bin.text_addr = sh->sh_addr;
                                bin.text_bytes.assign(bin.raw.begin() + static_cast<long>(sh->sh_offset),
                                                     bin.raw.begin() + static_cast<long>(sh->sh_offset + sh->sh_size));
                            }
                            break;
                        }
                    }
                }
            }
        }

        if (bin.text_bytes.empty()) {
            for (const auto& seg : bin.segments) {
                if (!seg.x || seg.filesz == 0) {
                    continue;
                }
                if (seg.offset + seg.filesz > bin.raw.size()) {
                    continue;
                }
                bin.text_addr = seg.vaddr;
                bin.text_bytes.assign(bin.raw.begin() + static_cast<long>(seg.offset),
                                      bin.raw.begin() + static_cast<long>(seg.offset + seg.filesz));
                break;
            }
        }

        if (bin.text_bytes.empty()) {
            bin.error = "cannot locate code section";
            return;
        }
        bin.ok = true;
    }

    static void parse32(ElfBinary& bin) {
        if (bin.raw.size() < sizeof(Elf32_Ehdr)) {
            bin.error = "elf32 header too short";
            return;
        }

        auto* eh = reinterpret_cast<const Elf32_Ehdr*>(bin.raw.data());
        bin.is64 = false;
        bin.entry = eh->e_entry;
        bin.machine = eh->e_machine;

        if (eh->e_phoff && eh->e_phnum) {
            for (uint16_t i = 0; i < eh->e_phnum; ++i) {
                const auto off = eh->e_phoff + static_cast<uint32_t>(i) * eh->e_phentsize;
                if (off + sizeof(Elf32_Phdr) > bin.raw.size()) {
                    continue;
                }
                auto* ph = reinterpret_cast<const Elf32_Phdr*>(bin.raw.data() + off);
                if (ph->p_type == PT_LOAD) {
                    Segment s;
                    s.vaddr = ph->p_vaddr;
                    s.memsz = ph->p_memsz;
                    s.filesz = ph->p_filesz;
                    s.offset = ph->p_offset;
                    s.r = (ph->p_flags & PF_R) != 0;
                    s.w = (ph->p_flags & PF_W) != 0;
                    s.x = (ph->p_flags & PF_X) != 0;
                    bin.segments.push_back(s);
                }
            }
        }

        for (const auto& seg : bin.segments) {
            if (!seg.x || seg.filesz == 0) {
                continue;
            }
            if (seg.offset + seg.filesz > bin.raw.size()) {
                continue;
            }
            bin.text_addr = seg.vaddr;
            bin.text_bytes.assign(bin.raw.begin() + static_cast<long>(seg.offset),
                                  bin.raw.begin() + static_cast<long>(seg.offset + seg.filesz));
            break;
        }

        if (bin.text_bytes.empty()) {
            bin.error = "cannot locate code segment";
            return;
        }
        bin.ok = true;
    }
};

struct Operand {
    enum class Kind { Reg, Imm, Mem, Invalid } kind = Kind::Invalid;
    int reg = 0;
    uint64_t imm = 0;
    int base = 0;
    int index = 0;
    int scale = 1;
    int64_t disp = 0;
    uint8_t size = 8;
};

struct Instruction {
    uint64_t address = 0;
    uint8_t size = 0;
    std::string mnemonic;
    std::string op_str;
    std::vector<Operand> ops;
    bool is_branch = false;
    bool is_conditional = false;
    bool is_call = false;
    bool is_ret = false;
    uint64_t direct_target = 0;
};

class Disassembler {
public:
    Disassembler() = default;

    bool init(uint16_t machine, bool is64) {
        cs_arch arch;
        cs_mode mode;

        if (machine == EM_X86 || machine == EM_X86_64) {
            arch = CS_ARCH_X86;
            mode = is64 ? CS_MODE_64 : CS_MODE_32;
        } else {
            return false;
        }

        if (cs_open(arch, mode, &h_) != CS_ERR_OK) {
            return false;
        }
        cs_option(h_, CS_OPT_DETAIL, CS_OPT_ON);
        initialized_ = true;
        return true;
    }

    ~Disassembler() {
        if (initialized_) {
            cs_close(&h_);
        }
    }

    std::vector<Instruction> disassemble(const std::vector<uint8_t>& code, uint64_t base) const {
        std::vector<Instruction> out;
        if (!initialized_) {
            return out;
        }

        cs_insn* insn = nullptr;
        size_t count = cs_disasm(h_, code.data(), code.size(), base, 0, &insn);
        out.reserve(count);

        for (size_t i = 0; i < count; ++i) {
            Instruction in;
            in.address = insn[i].address;
            in.size = static_cast<uint8_t>(insn[i].size);
            in.mnemonic = insn[i].mnemonic;
            in.op_str = insn[i].op_str;

            auto id = insn[i].id;
            in.is_call = (id == X86_INS_CALL);
            in.is_ret = (id == X86_INS_RET);
            in.is_branch = (id == X86_INS_JMP) || (id >= X86_INS_JAE && id <= X86_INS_JS) || in.is_call;
            in.is_conditional = (id >= X86_INS_JAE && id <= X86_INS_JS);

            if (insn[i].detail != nullptr) {
                auto& x86 = insn[i].detail->x86;
                for (uint8_t j = 0; j < x86.op_count; ++j) {
                    Operand op;
                    const auto& c = x86.operands[j];
                    op.size = c.size;
                    if (c.type == X86_OP_REG) {
                        op.kind = Operand::Kind::Reg;
                        op.reg = c.reg;
                    } else if (c.type == X86_OP_IMM) {
                        op.kind = Operand::Kind::Imm;
                        op.imm = static_cast<uint64_t>(c.imm);
                        if ((in.is_branch || in.is_call) && j == 0) {
                            in.direct_target = op.imm;
                        }
                    } else if (c.type == X86_OP_MEM) {
                        op.kind = Operand::Kind::Mem;
                        op.base = c.mem.base;
                        op.index = c.mem.index;
                        op.scale = c.mem.scale;
                        op.disp = c.mem.disp;
                    }
                    in.ops.push_back(op);
                }
            }

            out.push_back(std::move(in));
        }

        if (insn != nullptr) {
            cs_free(insn, count);
        }
        return out;
    }

    std::string regName(int reg) const { return cs_reg_name(h_, reg); }

private:
    csh h_ = 0;
    bool initialized_ = false;
};

struct BasicBlock {
    uint64_t start = 0;
    uint64_t end = 0;
    std::vector<uint64_t> inst_addrs;
    std::vector<uint64_t> succ;
};

struct CFG {
    std::map<uint64_t, BasicBlock> blocks;
    std::vector<std::pair<uint64_t, uint64_t>> edges;
};

class CFGBuilder {
public:
    static CFG build(const std::vector<Instruction>& insns, uint64_t entry) {
        CFG cfg;
        if (insns.empty()) {
            return cfg;
        }

        std::unordered_map<uint64_t, const Instruction*> m;
        for (const auto& in : insns) {
            m[in.address] = &in;
        }

        std::set<uint64_t> leaders;
        leaders.insert(entry);
        leaders.insert(insns.front().address);

        for (const auto& in : insns) {
            const uint64_t next = in.address + in.size;
            if (in.is_branch || in.is_call || in.is_ret) {
                if (in.direct_target) {
                    leaders.insert(in.direct_target);
                }
                if (!in.is_ret && in.mnemonic != "jmp") {
                    leaders.insert(next);
                }
            }
        }

        BasicBlock cur;
        bool started = false;
        for (size_t i = 0; i < insns.size(); ++i) {
            const auto& in = insns[i];
            if (leaders.count(in.address)) {
                if (started) {
                    cur.end = insns[i - 1].address + insns[i - 1].size;
                    cfg.blocks[cur.start] = cur;
                }
                cur = BasicBlock{};
                cur.start = in.address;
                started = true;
            }
            if (started) {
                cur.inst_addrs.push_back(in.address);
            }
        }
        if (started) {
            const auto& last = insns.back();
            cur.end = last.address + last.size;
            cfg.blocks[cur.start] = cur;
        }

        auto find_block_start = [&](uint64_t addr) -> uint64_t {
            auto it = cfg.blocks.upper_bound(addr);
            if (it == cfg.blocks.begin()) {
                return 0;
            }
            --it;
            const auto& b = it->second;
            if (addr >= b.start && addr < b.end) {
                return b.start;
            }
            return 0;
        };

        for (auto itb = cfg.blocks.begin(); itb != cfg.blocks.end(); ++itb) {
            uint64_t start = itb->first;
            auto& block = itb->second;
            if (block.inst_addrs.empty()) {
                continue;
            }
            auto it = m.find(block.inst_addrs.back());
            if (it == m.end()) {
                continue;
            }
            const auto& last = *it->second;
            const uint64_t fallthrough = last.address + last.size;

            auto add_edge = [&](uint64_t src, uint64_t dst, BasicBlock& b) {
                const auto bs = find_block_start(dst);
                if (bs == 0) {
                    return;
                }
                b.succ.push_back(bs);
                cfg.edges.emplace_back(src, bs);
            };

            if (last.is_ret) {
                continue;
            }
            if (last.mnemonic == "jmp") {
                if (last.direct_target) {
                    add_edge(start, last.direct_target, block);
                }
                continue;
            }
            if (last.is_conditional) {
                if (last.direct_target) {
                    add_edge(start, last.direct_target, block);
                }
                add_edge(start, fallthrough, block);
                continue;
            }
            if (last.is_call) {
                add_edge(start, fallthrough, block);
                continue;
            }
            add_edge(start, fallthrough, block);
        }

        return cfg;
    }

    static std::string toDot(const CFG& cfg) {
        std::ostringstream oss;
        oss << "digraph CFG {\n";
        oss << "  node [shape=box];\n";
        for (const auto& [start, block] : cfg.blocks) {
            oss << "  n" << std::hex << start << " [label=\"0x" << start << "\\n";
            oss << "[" << std::dec << block.inst_addrs.size() << " insn]\"];\n";
        }
        for (const auto& e : cfg.edges) {
            oss << "  n" << std::hex << e.first << " -> n" << e.second << ";\n";
        }
        oss << "}\n";
        return oss.str();
    }
};

class AbstractValue {
public:
    AbstractValue() = default;

    static AbstractValue concrete(z3::context& ctx, uint64_t v, unsigned bits = 64) {
        AbstractValue a;
        a.bits_ = bits;
        a.expr_ = ctx.bv_val(v, bits);
        a.is_concrete_ = true;
        a.concrete_ = v;
        return a;
    }

    static AbstractValue symbolic(z3::context& ctx, const std::string& name, unsigned bits = 64) {
        AbstractValue a;
        a.bits_ = bits;
        a.expr_ = ctx.bv_const(name.c_str(), bits);
        a.is_concrete_ = false;
        return a;
    }

    static AbstractValue fromExpr(const z3::expr& e) {
        AbstractValue a;
        a.bits_ = e.get_sort().bv_size();
        a.expr_ = e;
        uint64_t num = 0;
        if (e.is_numeral_u64(num)) {
            a.is_concrete_ = true;
            a.concrete_ = num;
        } else {
            a.is_concrete_ = false;
        }
        return a;
    }

    const z3::expr& expr() const { return *expr_; }
    unsigned bits() const { return bits_; }
    bool isConcrete() const { return is_concrete_; }
    uint64_t concrete() const { return concrete_; }

    std::string str() const {
        if (!expr_.has_value()) {
            return "<undef>";
        }
        std::ostringstream oss;
        if (is_concrete_) {
            oss << "0x" << std::hex << concrete_;
        } else {
            oss << expr().to_string();
        }
        return oss.str();
    }

private:
    unsigned bits_ = 64;
    std::optional<z3::expr> expr_;
    bool is_concrete_ = false;
    uint64_t concrete_ = 0;
};

class MemoryModel {
public:
    explicit MemoryModel(z3::context& ctx) : ctx_(&ctx) {}

    void mapSegment(const Segment& s, const std::vector<uint8_t>& file) {
        regions_.push_back(s);
        if (s.filesz == 0) {
            return;
        }
        if (s.offset + s.filesz > file.size()) {
            return;
        }
        for (uint64_t i = 0; i < s.filesz; ++i) {
            mem_[s.vaddr + i] = AbstractValue::concrete(*ctx_, file[s.offset + i], 8);
        }
    }

    void mapStack(uint64_t base, uint64_t size) {
        Segment s;
        s.vaddr = base - size;
        s.memsz = size;
        s.filesz = 0;
        s.offset = 0;
        s.r = s.w = true;
        s.x = false;
        regions_.push_back(s);
    }

    bool valid(uint64_t addr) const {
        for (const auto& r : regions_) {
            if (addr >= r.vaddr && addr < r.vaddr + r.memsz) {
                return true;
            }
        }
        return false;
    }

    AbstractValue read(uint64_t addr, unsigned size) {
        if (size == 0) {
            return AbstractValue::concrete(*ctx_, 0, 64);
        }
        z3::expr out = ctx_->bv_val(0, size * 8);
        for (unsigned i = 0; i < size; ++i) {
            auto it = mem_.find(addr + i);
            z3::expr b = it == mem_.end() ? ctx_->bv_val(0, 8) : byteExpr(it->second);
            out = z3::concat(b, out.extract(size * 8 - 1, 8));
        }
        return wrapExpr(out);
    }

    void write(uint64_t addr, const AbstractValue& v, unsigned size) {
        z3::expr e = castToBits(v.expr(), size * 8);
        for (unsigned i = 0; i < size; ++i) {
            const unsigned low = i * 8;
            const unsigned high = low + 7;
            z3::expr b = e.extract(high, low);
            mem_[addr + i] = wrapExpr(b);
        }
    }

private:
    z3::context* ctx_;
    std::unordered_map<uint64_t, AbstractValue> mem_;
    std::vector<Segment> regions_;

    z3::expr castToBits(const z3::expr& e, unsigned bits) {
        if (e.get_sort().bv_size() == bits) {
            return e;
        }
        if (e.get_sort().bv_size() < bits) {
            return z3::zext(e, bits - e.get_sort().bv_size());
        }
        return e.extract(bits - 1, 0);
    }

    z3::expr byteExpr(const AbstractValue& v) {
        if (v.bits() == 8) {
            return v.expr();
        }
        return v.expr().extract(7, 0);
    }

    AbstractValue wrapExpr(const z3::expr& e) {
        return AbstractValue::fromExpr(e);
    }

public:
    std::vector<z3::expr> drainEqualities() {
        return {};
    }

};

struct PathConstraintManager {
    std::vector<z3::expr> constraints;

    void add(const z3::expr& e) { constraints.push_back(e); }

    z3::expr conjunction(z3::context& ctx) const {
        z3::expr all = ctx.bool_val(true);
        for (const auto& c : constraints) {
            all = all && c;
        }
        return all;
    }
};

struct ExecutionState {
    uint64_t id = 0;
    uint64_t pc = 0;
    std::unordered_map<std::string, AbstractValue> regs;
    MemoryModel mem;
    PathConstraintManager pcm;
    std::vector<uint64_t> trace;
    std::vector<uint64_t> callstack;
    size_t depth = 0;
    bool terminated = false;

    std::optional<AbstractValue> last_cmp_l;
    std::optional<AbstractValue> last_cmp_r;

    explicit ExecutionState(z3::context& ctx) : mem(ctx) {}
};

struct Stats {
    uint64_t states_created = 0;
    uint64_t paths_terminated = 0;
    uint64_t instructions = 0;
    uint64_t branches = 0;
    uint64_t solver_queries = 0;
    uint64_t solver_sat = 0;
    uint64_t solver_unsat = 0;
    double seconds = 0.0;
};

struct SymbolicInput {
    std::string name;
    std::string kind;
    std::string target;
    z3::expr expr;
};

struct TestCase {
    uint64_t state_id = 0;
    std::vector<uint64_t> path;
    std::vector<std::pair<std::string, uint64_t>> assignments;
};

class SymbolicExecutor {
public:
    struct Config {
        size_t max_depth = 64;
        size_t max_steps = 20000;
        size_t max_states = 1024;
    };

    SymbolicExecutor(const ElfBinary& bin,
                     const std::unordered_map<uint64_t, Instruction>& map,
                     const Config& cfg)
        : bin_(bin), insn_map_(map), cfg_(cfg), solver_(ctx_) {}

    void addSymbolicRegister(const std::string& reg) {
        auto n = "sym_reg_" + reg;
        z3::expr v = ctx_.bv_const(n.c_str(), 64);
        symbolic_inputs_.push_back(SymbolicInput{n, "reg", reg, v});
        pending_reg_symbolic_.push_back({reg, v});
    }

    void addSymbolicMemory(uint64_t addr, unsigned size) {
        for (unsigned i = 0; i < size; ++i) {
            std::ostringstream oss;
            oss << "sym_mem_" << std::hex << addr + i;
            z3::expr v = ctx_.bv_const(oss.str().c_str(), 8);
            symbolic_inputs_.push_back(SymbolicInput{oss.str(), "mem", toHex(addr + i), v});
            pending_mem_symbolic_.push_back({addr + i, v});
        }
    }

    std::vector<TestCase> run() {
        auto t0 = std::chrono::high_resolution_clock::now();
        std::vector<TestCase> tests;

        auto init = makeInitialState();
        worklist_.push_back(std::move(init));

        size_t steps = 0;
        while (!worklist_.empty() && steps < cfg_.max_steps && stats_.states_created < cfg_.max_states) {
            ExecutionState st = std::move(worklist_.back());
            worklist_.pop_back();

            if (st.terminated) {
                tests.push_back(buildTestCase(st));
                continue;
            }

            if (st.depth > cfg_.max_depth) {
                st.terminated = true;
                stats_.paths_terminated++;
                tests.push_back(buildTestCase(st));
                continue;
            }

            stepState(st);
            steps++;

            if (st.terminated) {
                stats_.paths_terminated++;
                tests.push_back(buildTestCase(st));
            } else {
                worklist_.push_back(std::move(st));
            }
        }

        auto t1 = std::chrono::high_resolution_clock::now();
        stats_.seconds = std::chrono::duration<double>(t1 - t0).count();
        return tests;
    }

    const Stats& stats() const { return stats_; }

private:
    const ElfBinary& bin_;
    const std::unordered_map<uint64_t, Instruction>& insn_map_;
    Config cfg_;

    z3::context ctx_;
    z3::solver solver_;
    Stats stats_;
    std::vector<ExecutionState> worklist_;

    uint64_t next_state_id_ = 1;
    std::vector<SymbolicInput> symbolic_inputs_;
    std::vector<std::pair<std::string, z3::expr>> pending_reg_symbolic_;
    std::vector<std::pair<uint64_t, z3::expr>> pending_mem_symbolic_;

    static std::string toHex(uint64_t v) {
        std::ostringstream oss;
        oss << "0x" << std::hex << v;
        return oss.str();
    }

    ExecutionState makeInitialState() {
        ExecutionState st(ctx_);
        st.id = next_state_id_++;
        stats_.states_created++;
        st.pc = bin_.entry;

        const std::vector<std::string> gprs = {
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
        for (const auto& r : gprs) {
            st.regs[r] = AbstractValue::concrete(ctx_, 0, 64);
        }

        constexpr uint64_t kStackTop = 0x7fff'ffff'0000ULL;
        st.regs["rsp"] = AbstractValue::concrete(ctx_, kStackTop, 64);
        st.regs["rbp"] = AbstractValue::concrete(ctx_, kStackTop, 64);

        for (const auto& seg : bin_.segments) {
            st.mem.mapSegment(seg, bin_.raw);
        }
        st.mem.mapStack(kStackTop, 0x200000);

        for (const auto& [r, v] : pending_reg_symbolic_) {
            st.regs[r] = AbstractValue::symbolic(ctx_, v.decl().name().str(), 64);
        }
        for (const auto& [addr, v] : pending_mem_symbolic_) {
            st.mem.write(addr, AbstractValue::symbolic(ctx_, v.decl().name().str(), 8), 1);
        }

        st.regs["rip"] = AbstractValue::concrete(ctx_, st.pc, 64);
        return st;
    }

    bool feasible(const ExecutionState& st, const z3::expr& extra) {
        stats_.solver_queries++;
        solver_.push();
        solver_.add(st.pcm.conjunction(ctx_));
        solver_.add(extra);
        const auto r = solver_.check();
        solver_.pop();
        if (r == z3::sat) {
            stats_.solver_sat++;
            return true;
        }
        stats_.solver_unsat++;
        return false;
    }

    void stepState(ExecutionState& st) {
        auto it = insn_map_.find(st.pc);
        if (it == insn_map_.end()) {
            st.terminated = true;
            return;
        }

        const Instruction& ins = it->second;
        stats_.instructions++;
        st.trace.push_back(ins.address);

        if (ins.is_ret) {
            if (st.callstack.empty()) {
                st.terminated = true;
                return;
            }
            st.pc = st.callstack.back();
            st.callstack.pop_back();
            st.regs["rip"] = AbstractValue::concrete(ctx_, st.pc);
            return;
        }

        if (ins.mnemonic == "jmp") {
            if (ins.direct_target == 0) {
                st.terminated = true;
                return;
            }
            st.pc = ins.direct_target;
            st.regs["rip"] = AbstractValue::concrete(ctx_, st.pc);
            return;
        }

        if (ins.is_call) {
            if (ins.direct_target != 0 && insn_map_.count(ins.direct_target)) {
                st.callstack.push_back(ins.address + ins.size);
                st.pc = ins.direct_target;
            } else {
                st.pc = ins.address + ins.size;
            }
            st.regs["rip"] = AbstractValue::concrete(ctx_, st.pc);
            return;
        }

        if (ins.is_conditional) {
            stats_.branches++;
            if (ins.direct_target == 0) {
                st.terminated = true;
                return;
            }
            const uint64_t fallthrough = ins.address + ins.size;
            const z3::expr cond = branchCondition(st, ins);

            const bool can_true = feasible(st, cond);
            const bool can_false = feasible(st, !cond);

            if (can_true && can_false && stats_.states_created < cfg_.max_states) {
                ExecutionState other(ctx_);
                cloneState(st, other);
                other.id = next_state_id_++;
                stats_.states_created++;
                other.pcm.add(!cond);
                other.pc = fallthrough;
                other.depth++;
                other.regs["rip"] = AbstractValue::concrete(ctx_, other.pc);
                worklist_.push_back(std::move(other));

                st.pcm.add(cond);
                st.pc = ins.direct_target;
                st.depth++;
                st.regs["rip"] = AbstractValue::concrete(ctx_, st.pc);
                return;
            }
            if (can_true) {
                st.pcm.add(cond);
                st.pc = ins.direct_target;
                st.depth++;
                st.regs["rip"] = AbstractValue::concrete(ctx_, st.pc);
                return;
            }
            if (can_false) {
                st.pcm.add(!cond);
                st.pc = fallthrough;
                st.depth++;
                st.regs["rip"] = AbstractValue::concrete(ctx_, st.pc);
                return;
            }

            st.terminated = true;
            return;
        }

        executeNonBranch(st, ins);
        st.pc = ins.address + ins.size;
        st.regs["rip"] = AbstractValue::concrete(ctx_, st.pc);

        for (auto& eq : st.mem.drainEqualities()) {
            st.pcm.add(eq);
        }
    }

    void cloneState(const ExecutionState& src, ExecutionState& dst) {
        dst.pc = src.pc;
        dst.regs = src.regs;
        dst.mem = src.mem;
        dst.pcm = src.pcm;
        dst.trace = src.trace;
        dst.callstack = src.callstack;
        dst.depth = src.depth;
        dst.terminated = src.terminated;
        dst.last_cmp_l = src.last_cmp_l;
        dst.last_cmp_r = src.last_cmp_r;
    }

    static std::string capRegName(int cs_reg) {
        switch (cs_reg) {
            case X86_REG_RAX:
            case X86_REG_EAX:
            case X86_REG_AX:
            case X86_REG_AL: return "rax";
            case X86_REG_RBX:
            case X86_REG_EBX:
            case X86_REG_BX:
            case X86_REG_BL: return "rbx";
            case X86_REG_RCX:
            case X86_REG_ECX:
            case X86_REG_CX:
            case X86_REG_CL: return "rcx";
            case X86_REG_RDX:
            case X86_REG_EDX:
            case X86_REG_DX:
            case X86_REG_DL: return "rdx";
            case X86_REG_RSI:
            case X86_REG_ESI: return "rsi";
            case X86_REG_RDI:
            case X86_REG_EDI: return "rdi";
            case X86_REG_RBP:
            case X86_REG_EBP: return "rbp";
            case X86_REG_RSP:
            case X86_REG_ESP: return "rsp";
            case X86_REG_R8:
            case X86_REG_R8D: return "r8";
            case X86_REG_R9:
            case X86_REG_R9D: return "r9";
            case X86_REG_R10:
            case X86_REG_R10D: return "r10";
            case X86_REG_R11:
            case X86_REG_R11D: return "r11";
            case X86_REG_R12:
            case X86_REG_R12D: return "r12";
            case X86_REG_R13:
            case X86_REG_R13D: return "r13";
            case X86_REG_R14:
            case X86_REG_R14D: return "r14";
            case X86_REG_R15:
            case X86_REG_R15D: return "r15";
            default: return "";
        }
    }

    static std::string normalizeReg(const std::string& raw) {
        static const std::unordered_map<std::string, std::string> m = {
            {"eax", "rax"}, {"ax", "rax"}, {"al", "rax"},
            {"ebx", "rbx"}, {"bx", "rbx"}, {"bl", "rbx"},
            {"ecx", "rcx"}, {"cx", "rcx"}, {"cl", "rcx"},
            {"edx", "rdx"}, {"dx", "rdx"}, {"dl", "rdx"},
            {"esi", "rsi"}, {"edi", "rdi"}, {"esp", "rsp"}, {"ebp", "rbp"}};
        auto it = m.find(raw);
        if (it != m.end()) {
            return it->second;
        }
        return raw;
    }

    AbstractValue getReg(ExecutionState& st, const std::string& r) {
        auto n = normalizeReg(r);
        auto it = st.regs.find(n);
        if (it == st.regs.end()) {
            st.regs[n] = AbstractValue::concrete(ctx_, 0);
        }
        return st.regs[n];
    }

    void setReg(ExecutionState& st, const std::string& r, const AbstractValue& v) {
        st.regs[normalizeReg(r)] = v;
    }

    z3::expr asBv64(const AbstractValue& v) {
        auto e = v.expr();
        const unsigned b = e.get_sort().bv_size();
        if (b == 64) {
            return e;
        }
        if (b < 64) {
            return z3::zext(e, 64 - b);
        }
        return e.extract(63, 0);
    }

    uint64_t memAddr(ExecutionState& st, const Operand& o) {
        uint64_t base = 0;
        if (o.base != X86_REG_INVALID) {
            std::string r = capRegName(o.base);
            auto rv = getReg(st, r);
            if (rv.isConcrete()) {
                base = rv.concrete();
            }
        }
        uint64_t idx = 0;
        if (o.index != X86_REG_INVALID) {
            std::string r = capRegName(o.index);
            auto rv = getReg(st, r);
            if (rv.isConcrete()) {
                idx = rv.concrete() * static_cast<uint64_t>(std::max(o.scale, 1));
            }
        }
        return base + idx + static_cast<uint64_t>(o.disp);
    }

    AbstractValue readOperand(ExecutionState& st, const Operand& o) {
        if (o.kind == Operand::Kind::Imm) {
            return AbstractValue::concrete(ctx_, o.imm, 64);
        }
        if (o.kind == Operand::Kind::Reg) {
            std::string r = capRegName(o.reg);
            return getReg(st, r);
        }
        if (o.kind == Operand::Kind::Mem) {
            const uint64_t a = memAddr(st, o);
            const unsigned sz = std::max<unsigned>(1, o.size == 0 ? 8 : o.size);
            return st.mem.read(a, sz);
        }
        return AbstractValue::concrete(ctx_, 0, 64);
    }

    void writeOperand(ExecutionState& st, const Operand& o, const AbstractValue& v) {
        if (o.kind == Operand::Kind::Reg) {
            std::string r = capRegName(o.reg);
            setReg(st, r, v);
            return;
        }
        if (o.kind == Operand::Kind::Mem) {
            const uint64_t a = memAddr(st, o);
            const unsigned sz = std::max<unsigned>(1, o.size == 0 ? 8 : o.size);
            st.mem.write(a, v, sz);
        }
    }

    AbstractValue fromExpr(const z3::expr& e) {
        return AbstractValue::fromExpr(e);
    }

    void executeNonBranch(ExecutionState& st, const Instruction& ins) {
        const std::string& m = ins.mnemonic;
        if ((m == "mov" || m == "movzx" || m == "movsxd") && ins.ops.size() >= 2) {
            auto s = readOperand(st, ins.ops[1]);
            writeOperand(st, ins.ops[0], s);
            return;
        }
        if (m == "lea" && ins.ops.size() >= 2 && ins.ops[1].kind == Operand::Kind::Mem) {
            uint64_t addr = memAddr(st, ins.ops[1]);
            writeOperand(st, ins.ops[0], AbstractValue::concrete(ctx_, addr, 64));
            return;
        }
        if ((m == "add" || m == "sub" || m == "xor" || m == "and" || m == "or") && ins.ops.size() >= 2) {
            auto a = readOperand(st, ins.ops[0]);
            auto b = readOperand(st, ins.ops[1]);
            z3::expr ae = asBv64(a);
            z3::expr be = asBv64(b);
            z3::expr r = ae;
            if (m == "add") {
                r = ae + be;
            } else if (m == "sub") {
                r = ae - be;
            } else if (m == "xor") {
                r = ae ^ be;
            } else if (m == "and") {
                r = ae & be;
            } else if (m == "or") {
                r = ae | be;
            }
            writeOperand(st, ins.ops[0], fromExpr(r));
            return;
        }
        if ((m == "cmp" || m == "test") && ins.ops.size() >= 2) {
            auto a = readOperand(st, ins.ops[0]);
            auto b = readOperand(st, ins.ops[1]);
            st.last_cmp_l = a;
            if (m == "test") {
                z3::expr t = asBv64(a) & asBv64(b);
                st.last_cmp_r = fromExpr(t);
            } else {
                st.last_cmp_r = b;
            }
            return;
        }
        if (m == "push" && !ins.ops.empty()) {
            auto v = readOperand(st, ins.ops[0]);
            auto rsp = getReg(st, "rsp");
            z3::expr nrsp = asBv64(rsp) - ctx_.bv_val(8, 64);
            auto new_rsp = fromExpr(nrsp);
            setReg(st, "rsp", new_rsp);
            if (new_rsp.isConcrete()) {
                st.mem.write(new_rsp.concrete(), v, 8);
            }
            return;
        }
        if (m == "pop" && !ins.ops.empty()) {
            auto rsp = getReg(st, "rsp");
            if (rsp.isConcrete()) {
                auto v = st.mem.read(rsp.concrete(), 8);
                writeOperand(st, ins.ops[0], v);
            }
            z3::expr nrsp = asBv64(rsp) + ctx_.bv_val(8, 64);
            setReg(st, "rsp", fromExpr(nrsp));
            return;
        }
    }

    z3::expr branchCondition(ExecutionState& st, const Instruction& ins) {
        z3::expr a = ctx_.bv_val(0, 64);
        z3::expr b = ctx_.bv_val(0, 64);
        if (st.last_cmp_l.has_value()) {
            a = asBv64(*st.last_cmp_l);
        }
        if (st.last_cmp_r.has_value()) {
            b = asBv64(*st.last_cmp_r);
        }

        const std::string& m = ins.mnemonic;
        if (m == "je" || m == "jz") return a == b;
        if (m == "jne" || m == "jnz") return a != b;
        if (m == "jb" || m == "jc" || m == "jnae") return z3::ult(a, b);
        if (m == "ja" || m == "jnbe") return z3::ugt(a, b);
        if (m == "jbe" || m == "jna") return z3::ule(a, b);
        if (m == "jae" || m == "jnb" || m == "jnc") return z3::uge(a, b);
        if (m == "jl" || m == "jnge") return z3::slt(a, b);
        if (m == "jle" || m == "jng") return z3::sle(a, b);
        if (m == "jg" || m == "jnle") return z3::sgt(a, b);
        if (m == "jge" || m == "jnl") return z3::sge(a, b);
        return ctx_.bool_val(true);
    }

    TestCase buildTestCase(const ExecutionState& st) {
        TestCase tc;
        tc.state_id = st.id;
        tc.path = st.trace;

        solver_.push();
        solver_.add(st.pcm.conjunction(ctx_));
        if (solver_.check() == z3::sat) {
            auto model = solver_.get_model();
            for (const auto& s : symbolic_inputs_) {
                z3::expr v = model.eval(s.expr, true);
                uint64_t cv = 0;
                v.is_numeral_u64(cv);
                tc.assignments.emplace_back(s.name + "(" + s.kind + ":" + s.target + ")", cv);
            }
        }
        solver_.pop();
        return tc;
    }

};

struct Cli {
    std::string binary;
    std::string out_dir = ".";
    size_t max_depth = 64;
    size_t max_steps = 20000;
    size_t max_states = 1024;
    bool dump_cfg = true;
    std::vector<std::string> sym_regs;
    std::vector<std::pair<uint64_t, unsigned>> sym_mems;
};

static void usage(const char* p) {
    std::cout << "Usage: " << p << " <elf-binary> [options]\n"
              << "Options:\n"
              << "  --sym-reg <reg>         mark register symbolic, can repeat\n"
              << "  --sym-mem <addr:size>   mark memory bytes symbolic, e.g. 0x404000:8\n"
              << "  --max-depth <n>\n"
              << "  --max-steps <n>\n"
              << "  --max-states <n>\n"
              << "  --out <dir>\n"
              << "  --no-cfg\n";
}

static bool parseCli(int argc, char** argv, Cli& c) {
    if (argc < 2) {
        return false;
    }
    c.binary = argv[1];
    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        auto need = [&](const std::string& name) -> std::string {
            if (i + 1 >= argc) {
                throw std::runtime_error("missing value for " + name);
            }
            return argv[++i];
        };

        if (a == "--sym-reg") {
            c.sym_regs.push_back(need(a));
        } else if (a == "--sym-mem") {
            auto v = need(a);
            auto pos = v.find(':');
            if (pos == std::string::npos) {
                throw std::runtime_error("--sym-mem format addr:size");
            }
            uint64_t addr = std::stoull(v.substr(0, pos), nullptr, 0);
            unsigned sz = static_cast<unsigned>(std::stoul(v.substr(pos + 1)));
            c.sym_mems.push_back({addr, sz});
        } else if (a == "--max-depth") {
            c.max_depth = std::stoul(need(a));
        } else if (a == "--max-steps") {
            c.max_steps = std::stoul(need(a));
        } else if (a == "--max-states") {
            c.max_states = std::stoul(need(a));
        } else if (a == "--out") {
            c.out_dir = need(a);
        } else if (a == "--no-cfg") {
            c.dump_cfg = false;
        } else if (a == "-h" || a == "--help") {
            return false;
        } else {
            throw std::runtime_error("unknown option: " + a);
        }
    }
    return true;
}

static void writeFile(const std::string& path, const std::string& s) {
    std::ofstream ofs(path);
    ofs << s;
}

static std::string hexList(const std::vector<uint64_t>& xs) {
    std::ostringstream oss;
    for (size_t i = 0; i < xs.size(); ++i) {
        if (i) oss << " -> ";
        oss << "0x" << std::hex << xs[i] << std::dec;
    }
    return oss.str();
}

}  // namespace symexec

int main(int argc, char** argv) {
    using namespace symexec;

    Cli cli;
    try {
        if (!parseCli(argc, argv, cli)) {
            usage(argv[0]);
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "arg parse error: " << e.what() << "\n";
        usage(argv[0]);
        return 1;
    }

    auto bin = ElfLoader::load(cli.binary);
    if (!bin.ok) {
        std::cerr << "ELF load failed: " << bin.error << "\n";
        return 2;
    }

    Disassembler dis;
    if (!dis.init(bin.machine, bin.is64)) {
        std::cerr << "disassembler init failed: only x86/x86_64 currently supported\n";
        return 3;
    }

    auto insns = dis.disassemble(bin.text_bytes, bin.text_addr);
    if (insns.empty()) {
        std::cerr << "no instructions decoded\n";
        return 4;
    }

    std::unordered_map<uint64_t, Instruction> insn_map;
    for (const auto& i : insns) {
        insn_map[i.address] = i;
    }

    auto cfg = CFGBuilder::build(insns, bin.entry);
    if (cli.dump_cfg) {
        writeFile(cli.out_dir + "/cfg.dot", CFGBuilder::toDot(cfg));
    }

    SymbolicExecutor::Config ecfg;
    ecfg.max_depth = cli.max_depth;
    ecfg.max_steps = cli.max_steps;
    ecfg.max_states = cli.max_states;

    SymbolicExecutor exec(bin, insn_map, ecfg);
    for (const auto& r : cli.sym_regs) {
        exec.addSymbolicRegister(r);
    }
    for (const auto& [addr, sz] : cli.sym_mems) {
        exec.addSymbolicMemory(addr, sz);
    }

    auto tests = exec.run();
    const auto& st = exec.stats();

    std::ostringstream tc;
    tc << "# Symbolic Execution Testcases\n\n";
    for (const auto& t : tests) {
        tc << "[Path state=" << t.state_id << "]\n";
        tc << "Trace: " << hexList(t.path) << "\n";
        tc << "Assignments:\n";
        for (const auto& [k, v] : t.assignments) {
            tc << "  " << k << " = 0x" << std::hex << v << std::dec << "\n";
        }
        tc << "\n";
    }
    writeFile(cli.out_dir + "/testcases.txt", tc.str());

    std::ostringstream js;
    js << "{\n";
    js << "  \"binary\": \"" << cli.binary << "\",\n";
    js << "  \"entry\": \"0x" << std::hex << bin.entry << std::dec << "\",\n";
    js << "  \"stats\": {\n";
    js << "    \"states_created\": " << st.states_created << ",\n";
    js << "    \"paths_terminated\": " << st.paths_terminated << ",\n";
    js << "    \"instructions\": " << st.instructions << ",\n";
    js << "    \"branches\": " << st.branches << ",\n";
    js << "    \"solver_queries\": " << st.solver_queries << ",\n";
    js << "    \"solver_sat\": " << st.solver_sat << ",\n";
    js << "    \"solver_unsat\": " << st.solver_unsat << ",\n";
    js << "    \"seconds\": " << std::fixed << std::setprecision(4) << st.seconds << "\n";
    js << "  },\n";
    js << "  \"cfg\": {\n";
    js << "    \"basic_blocks\": " << cfg.blocks.size() << ",\n";
    js << "    \"edges\": " << cfg.edges.size() << "\n";
    js << "  },\n";
    js << "  \"paths\": " << tests.size() << "\n";
    js << "}\n";
    writeFile(cli.out_dir + "/stats.json", js.str());

    std::cout << "Loaded ELF: " << cli.binary << "\n";
    std::cout << "Entry: 0x" << std::hex << bin.entry << std::dec << "\n";
    std::cout << "Decoded instructions: " << insns.size() << "\n";
    std::cout << "CFG blocks/edges: " << cfg.blocks.size() << "/" << cfg.edges.size() << "\n";
    std::cout << "States: " << st.states_created << ", Paths: " << tests.size() << "\n";
    std::cout << "Solver queries(sat/unsat): " << st.solver_queries << " ("
              << st.solver_sat << "/" << st.solver_unsat << ")\n";
    std::cout << "Artifacts:\n";
    if (cli.dump_cfg) {
        std::cout << "  " << cli.out_dir << "/cfg.dot\n";
    }
    std::cout << "  " << cli.out_dir << "/testcases.txt\n";
    std::cout << "  " << cli.out_dir << "/stats.json\n";

    return 0;
}
