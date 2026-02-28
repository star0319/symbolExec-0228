#ifndef ELF_PARSER_H
#define ELF_PARSER_H

#include <string>
#include <vector>
#include <cstdint>
#include <map>
#include <memory>

namespace symexec {

// ELF file types
enum class ELFType {
    NONE,
    REL,
    EXEC,
    DYN,
    CORE
};

// ELF class (32/64 bit)
enum class ELFClass {
    NONE,
    ELF32,
    ELF64
};

// ELF machine architecture
enum class ELFMachine {
    NONE,
    X86,
    X86_64,
    ARM,
    AARCH64,
    MIPS,
    UNKNOWN
};

// Program header entry
struct ProgramHeader {
    uint32_t type;
    uint32_t flags;
    uint64_t offset;
    uint64_t vaddr;
    uint64_t paddr;
    uint64_t filesz;
    uint64_t memsz;
    uint64_t align;
};

// Section header entry
struct SectionHeader {
    uint32_t name;
    uint32_t type;
    uint64_t flags;
    uint64_t addr;
    uint64_t offset;
    uint64_t size;
    uint32_t link;
    uint32_t info;
    uint64_t addralign;
    uint64_t entsize;
    std::string nameStr;
};

// Symbol entry
struct Symbol {
    std::string name;
    uint64_t value;
    uint64_t size;
    uint8_t info;
    uint8_t other;
    uint16_t shndx;
    bool isFunc;
};

// Loaded segment for memory mapping
struct LoadedSegment {
    uint64_t vaddr;
    uint64_t size;
    std::vector<uint8_t> data;
    bool readable;
    bool writable;
    bool executable;
};

// ELF parsing result
struct ELFInfo {
    ELFClass elfClass;
    ELFType elfType;
    ELFMachine machine;
    uint64_t entryPoint;
    uint64_t baseAddr;
    std::vector<ProgramHeader> programHeaders;
    std::vector<SectionHeader> sectionHeaders;
    std::vector<Symbol> symbols;
    std::vector<LoadedSegment> segments;
    bool isPIE;
    bool isValid;
    std::string errorMessage;
};

class ELFParser {
public:
    ELFParser() = default;
    ~ELFParser() = default;

    // Parse ELF file from path
    ELFInfo parseFile(const std::string& filepath);
    
    // Parse ELF from memory buffer
    ELFInfo parseBuffer(const std::vector<uint8_t>& buffer);

    // Get architecture string
    static std::string getArchitectureString(ELFMachine machine);
    
    // Get ELF type string
    static std::string getELFTypeString(ELFType type);

private:
    // ELF header parsing
    bool parseELFHeader(const std::vector<uint8_t>& buffer, size_t& offset, ELFInfo& info);
    
    // Program header parsing
    bool parseProgramHeaders(const std::vector<uint8_t>& buffer, size_t offset, ELFInfo& info);
    
    // Section header parsing
    bool parseSectionHeaders(const std::vector<uint8_t>& buffer, size_t offset, ELFInfo& info);
    
    // Symbol table parsing
    bool parseSymbols(const std::vector<uint8_t>& buffer, const ELFInfo& info);
    
    // Load segments into memory
    void loadSegments(const std::vector<uint8_t>& buffer, ELFInfo& info);
    
    // Read utilities
    template<typename T>
    T readValue(const std::vector<uint8_t>& buffer, size_t offset) const;
    
    uint16_t readU16(const std::vector<uint8_t>& buffer, size_t offset) const;
    uint32_t readU32(const std::vector<uint8_t>& buffer, size_t offset) const;
    uint64_t readU64(const std::vector<uint8_t>& buffer, size_t offset) const;
    
    // ELF magic number
    static constexpr uint8_t ELF_MAGIC[4] = {0x7f, 'E', 'L', 'F'};
    
    // ELF constants
    static constexpr uint8_t EI_CLASS = 4;
    static constexpr uint8_t EI_DATA = 5;
    static constexpr uint16_t ET_NONE = 0;
    static constexpr uint16_t ET_REL = 1;
    static constexpr uint16_t ET_EXEC = 2;
    static constexpr uint16_t ET_DYN = 3;
    static constexpr uint16_t ET_CORE = 4;
    
    // Machine types
    static constexpr uint16_t EM_386 = 3;
    static constexpr uint16_t EM_X86_64 = 62;
    static constexpr uint16_t EM_ARM = 40;
    static constexpr uint16_t EM_AARCH64 = 183;
    static constexpr uint16_t EM_MIPS = 8;
    
    // Program header types
    static constexpr uint32_t PT_NULL = 0;
    static constexpr uint32_t PT_LOAD = 1;
    static constexpr uint32_t PT_DYNAMIC = 2;
    static constexpr uint32_t PT_INTERP = 3;
    static constexpr uint32_t PT_NOTE = 4;
    static constexpr uint32_t PT_GNU_EH_FRAME = 0x6474e550;
    static constexpr uint32_t PT_GNU_STACK = 0x6474e551;
    static constexpr uint32_t PT_GNU_RELRO = 0x6474e552;
    
    // Section header types
    static constexpr uint32_t SHT_NULL = 0;
    static constexpr uint32_t SHT_PROGBITS = 1;
    static constexpr uint32_t SHT_SYMTAB = 2;
    static constexpr uint32_t SHT_STRTAB = 3;
    static constexpr uint32_t SHT_DYNSYM = 11;
    
    bool isLittleEndian = true;
};

} // namespace symexec

#endif // ELF_PARSER_H
