#include "ELFParser.h"
#include <fstream>
#include <cstring>
#include <iostream>

namespace symexec {

ELFInfo ELFParser::parseFile(const std::string& filepath) {
    ELFInfo info;
    info.isValid = false;
    
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        info.errorMessage = "Failed to open file: " + filepath;
        return info;
    }
    
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<uint8_t> buffer(fileSize);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), fileSize)) {
        info.errorMessage = "Failed to read file";
        return info;
    }
    
    return parseBuffer(buffer);
}

ELFInfo ELFParser::parseBuffer(const std::vector<uint8_t>& buffer) {
    ELFInfo info;
    info.isValid = false;
    info.baseAddr = 0;
    info.isPIE = false;
    
    if (buffer.size() < 16) {
        info.errorMessage = "File too small to be ELF";
        return info;
    }
    
    // Check ELF magic number
    if (std::memcmp(buffer.data(), ELF_MAGIC, 4) != 0) {
        info.errorMessage = "Not an ELF file (invalid magic number)";
        return info;
    }
    
    size_t offset = 0;
    if (!parseELFHeader(buffer, offset, info)) {
        return info;
    }
    
    // Parse program headers
    if (!parseProgramHeaders(buffer, offset, info)) {
        info.errorMessage = "Failed to parse program headers";
        return info;
    }
    
    // Parse section headers
    parseSectionHeaders(buffer, offset, info);
    
    // Parse symbols
    parseSymbols(buffer, info);
    
    // Load segments
    loadSegments(buffer, info);
    
    // Determine if PIE
    info.isPIE = (info.elfType == ELFType::DYN);
    
    info.isValid = true;
    return info;
}

bool ELFParser::parseELFHeader(const std::vector<uint8_t>& buffer, size_t& offset, ELFInfo& info) {
    // ELF class
    uint8_t elfClass = buffer[EI_CLASS];
    if (elfClass == 1) {
        info.elfClass = ELFClass::ELF32;
    } else if (elfClass == 2) {
        info.elfClass = ELFClass::ELF64;
    } else {
        info.errorMessage = "Invalid ELF class";
        return false;
    }
    
    // Endianness
    isLittleEndian = (buffer[EI_DATA] == 1);
    
    // ELF type
    uint16_t e_type = readU16(buffer, 16);
    switch (e_type) {
        case ET_NONE: info.elfType = ELFType::NONE; break;
        case ET_REL: info.elfType = ELFType::REL; break;
        case ET_EXEC: info.elfType = ELFType::EXEC; break;
        case ET_DYN: info.elfType = ELFType::DYN; break;
        case ET_CORE: info.elfType = ELFType::CORE; break;
        default:
            info.errorMessage = "Unknown ELF type: " + std::to_string(e_type);
            return false;
    }
    
    // Machine architecture
    uint16_t e_machine = readU16(buffer, 18);
    switch (e_machine) {
        case EM_386: info.machine = ELFMachine::X86; break;
        case EM_X86_64: info.machine = ELFMachine::X86_64; break;
        case EM_ARM: info.machine = ELFMachine::ARM; break;
        case EM_AARCH64: info.machine = ELFMachine::AARCH64; break;
        case EM_MIPS: info.machine = ELFMachine::MIPS; break;
        default:
            info.machine = ELFMachine::UNKNOWN;
            std::cerr << "Warning: Unknown machine type: " << e_machine << std::endl;
    }
    
    // Entry point and headers
    if (info.elfClass == ELFClass::ELF64) {
        info.entryPoint = readU64(buffer, 24);
        offset = readU64(buffer, 32);  // e_phoff
        uint64_t shoff = readU64(buffer, 40);  // e_shoff
        info.programHeaders.resize(readU32(buffer, 56));  // e_phnum
        info.sectionHeaders.resize(readU32(buffer, 60));  // e_shnum
        uint16_t shstrndx = readU16(buffer, 62);
        
        // Store section header string table index for later
        if (shstrndx < info.sectionHeaders.size()) {
            // Will be used in parseSectionHeaders
        }
    } else {
        info.entryPoint = readU32(buffer, 24);
        offset = readU32(buffer, 28);  // e_phoff
        uint32_t shoff = readU32(buffer, 32);  // e_shoff
        info.programHeaders.resize(readU16(buffer, 44));  // e_phnum
        info.sectionHeaders.resize(readU16(buffer, 48));  // e_shnum
    }
    
    return true;
}

bool ELFParser::parseProgramHeaders(const std::vector<uint8_t>& buffer, size_t offset, ELFInfo& info) {
    if (offset == 0 || info.programHeaders.empty()) {
        return true;  // No program headers
    }
    
    size_t phEntSize = info.elfClass == ELFClass::ELF64 ? 56 : 32;
    
    for (size_t i = 0; i < info.programHeaders.size(); ++i) {
        size_t phOffset = offset + i * phEntSize;
        ProgramHeader ph;
        
        if (info.elfClass == ELFClass::ELF64) {
            ph.type = readU32(buffer, phOffset);
            ph.flags = readU32(buffer, phOffset + 4);
            ph.offset = readU64(buffer, phOffset + 8);
            ph.vaddr = readU64(buffer, phOffset + 16);
            ph.paddr = readU64(buffer, phOffset + 24);
            ph.filesz = readU64(buffer, phOffset + 32);
            ph.memsz = readU64(buffer, phOffset + 40);
            ph.align = readU64(buffer, phOffset + 48);
        } else {
            ph.type = readU32(buffer, phOffset);
            ph.offset = readU32(buffer, phOffset + 4);
            ph.vaddr = readU32(buffer, phOffset + 8);
            ph.paddr = readU32(buffer, phOffset + 12);
            ph.filesz = readU32(buffer, phOffset + 16);
            ph.memsz = readU32(buffer, phOffset + 20);
            ph.flags = readU32(buffer, phOffset + 24);
            ph.align = readU32(buffer, phOffset + 28);
        }
        
        info.programHeaders[i] = ph;
        
        // Track base address
        if (ph.type == PT_LOAD && ph.vaddr < info.baseAddr) {
            info.baseAddr = ph.vaddr;
        }
    }
    
    return true;
}

bool ELFParser::parseSectionHeaders(const std::vector<uint8_t>& buffer, size_t offset, ELFInfo& info) {
    // Find section header string table first
    if (info.sectionHeaders.empty()) {
        return true;
    }
    
    size_t shEntSize = info.elfClass == ELFClass::ELF64 ? 64 : 40;
    size_t shOffset;
    
    if (info.elfClass == ELFClass::ELF64) {
        shOffset = readU64(buffer, 40);  // e_shoff
    } else {
        shOffset = readU32(buffer, 32);  // e_shoff
    }
    
    if (shOffset == 0) {
        return true;  // No section headers
    }
    
    // Parse all section headers
    for (size_t i = 0; i < info.sectionHeaders.size(); ++i) {
        size_t shdrOffset = shOffset + i * shEntSize;
        SectionHeader& sh = info.sectionHeaders[i];
        
        if (info.elfClass == ELFClass::ELF64) {
            sh.name = readU32(buffer, shdrOffset);
            sh.type = readU32(buffer, shdrOffset + 4);
            sh.flags = readU64(buffer, shdrOffset + 8);
            sh.addr = readU64(buffer, shdrOffset + 16);
            sh.offset = readU64(buffer, shdrOffset + 24);
            sh.size = readU64(buffer, shdrOffset + 32);
            sh.link = readU32(buffer, shdrOffset + 40);
            sh.info = readU32(buffer, shdrOffset + 44);
            sh.addralign = readU64(buffer, shdrOffset + 48);
            sh.entsize = readU64(buffer, shdrOffset + 56);
        } else {
            sh.name = readU32(buffer, shdrOffset);
            sh.type = readU32(buffer, shdrOffset + 4);
            sh.flags = readU32(buffer, shdrOffset + 8);
            sh.addr = readU32(buffer, shdrOffset + 12);
            sh.offset = readU32(buffer, shdrOffset + 16);
            sh.size = readU32(buffer, shdrOffset + 20);
            sh.link = readU32(buffer, shdrOffset + 24);
            sh.info = readU32(buffer, shdrOffset + 28);
            sh.addralign = readU32(buffer, shdrOffset + 32);
            sh.entsize = readU32(buffer, shdrOffset + 36);
        }
    }
    
    // Get section names from string table
    // Find .shstrtab section
    for (const auto& sh : info.sectionHeaders) {
        if (sh.type == SHT_STRTAB && sh.name == 0) {
            // This might be .shstrtab, resolve names
            for (auto& section : info.sectionHeaders) {
                if (section.name < sh.size) {
                    size_t nameOffset = sh.offset + section.name;
                    if (nameOffset + 1 <= buffer.size()) {
                        section.nameStr = reinterpret_cast<const char*>(&buffer[nameOffset]);
                    }
                }
            }
            break;
        }
    }
    
    return true;
}

bool ELFParser::parseSymbols(const std::vector<uint8_t>& buffer, const ELFInfo& info) {
    // Find symbol table and string table
    const SectionHeader* symtab = nullptr;
    const SectionHeader* strtab = nullptr;
    const SectionHeader* dynsym = nullptr;
    const SectionHeader* dynstr = nullptr;
    
    for (const auto& sh : info.sectionHeaders) {
        if (sh.type == SHT_SYMTAB) {
            symtab = &sh;
            if (sh.link < info.sectionHeaders.size()) {
                strtab = &info.sectionHeaders[sh.link];
            }
        } else if (sh.type == SHT_DYNSYM) {
            dynsym = &sh;
            if (sh.link < info.sectionHeaders.size()) {
                dynstr = &info.sectionHeaders[sh.link];
            }
        }
    }
    
    auto parseSymTab = [&](const SectionHeader* sym, const SectionHeader* str) {
        if (!sym || !str) return;
        
        size_t symSize = info.elfClass == ELFClass::ELF64 ? 24 : 16;
        size_t numSymbols = sym->size / symSize;
        
        for (size_t i = 0; i < numSymbols; ++i) {
            size_t symOffset = sym->offset + i * symSize;
            Symbol symbol;
            symbol.isFunc = false;
            
            if (info.elfClass == ELFClass::ELF64) {
                symbol.name = readU32(buffer, symOffset);
                symbol.info = buffer[symOffset + 4];
                symbol.other = buffer[symOffset + 5];
                symbol.shndx = readU16(buffer, symOffset + 6);
                symbol.value = readU64(buffer, symOffset + 8);
                symbol.size = readU64(buffer, symOffset + 16);
            } else {
                symbol.name = readU32(buffer, symOffset);
                symbol.value = readU32(buffer, symOffset + 4);
                symbol.size = readU32(buffer, symOffset + 8);
                symbol.info = buffer[symOffset + 12];
                symbol.other = buffer[symOffset + 13];
                symbol.shndx = readU16(buffer, symOffset + 14);
            }
            
            // Get symbol name
            if (symbol.name < str->size) {
                size_t nameOffset = str->offset + symbol.name;
                if (nameOffset < buffer.size()) {
                    symbol.name = reinterpret_cast<const char*>(&buffer[nameOffset]);
                }
            }
            
            // Check if function
            uint8_t type = symbol.info & 0xf;
            symbol.isFunc = (type == 2);  // STT_FUNC
            
            info.symbols.push_back(symbol);
        }
    };
    
    parseSymTab(symtab, strtab);
    parseSymTab(dynsym, dynstr);
    
    return true;
}

void ELFParser::loadSegments(const std::vector<uint8_t>& buffer, ELFInfo& info) {
    for (const auto& ph : info.programHeaders) {
        if (ph.type != PT_LOAD) continue;
        
        LoadedSegment seg;
        seg.vaddr = ph.vaddr;
        seg.size = ph.memsz;
        seg.readable = (ph.flags & 4) != 0;
        seg.writable = (ph.flags & 2) != 0;
        seg.executable = (ph.flags & 1) != 0;
        
        if (ph.filesz > 0 && ph.offset + ph.filesz <= buffer.size()) {
            seg.data.resize(ph.filesz);
            std::memcpy(seg.data.data(), &buffer[ph.offset], ph.filesz);
        }
        
        info.segments.push_back(seg);
    }
}

std::string ELFParser::getArchitectureString(ELFMachine machine) {
    switch (machine) {
        case ELFMachine::X86: return "x86";
        case ELFMachine::X86_64: return "x86_64";
        case ELFMachine::ARM: return "ARM";
        case ELFMachine::AARCH64: return "AArch64";
        case ELFMachine::MIPS: return "MIPS";
        default: return "Unknown";
    }
}

std::string ELFParser::getELFTypeString(ELFType type) {
    switch (type) {
        case ELFType::NONE: return "NONE";
        case ELFType::REL: return "REL (Relocatable)";
        case ELFType::EXEC: return "EXEC (Executable)";
        case ELFType::DYN: return "DYN (Shared Object/PIE)";
        case ELFType::CORE: return "CORE (Core Dump)";
        default: return "Unknown";
    }
}

uint16_t ELFParser::readU16(const std::vector<uint8_t>& buffer, size_t offset) const {
    if (offset + 2 > buffer.size()) return 0;
    uint16_t val;
    std::memcpy(&val, &buffer[offset], 2);
    return isLittleEndian ? val : __builtin_bswap16(val);
}

uint32_t ELFParser::readU32(const std::vector<uint8_t>& buffer, size_t offset) const {
    if (offset + 4 > buffer.size()) return 0;
    uint32_t val;
    std::memcpy(&val, &buffer[offset], 4);
    return isLittleEndian ? val : __builtin_bswap32(val);
}

uint64_t ELFParser::readU64(const std::vector<uint8_t>& buffer, size_t offset) const {
    if (offset + 8 > buffer.size()) return 0;
    uint64_t val;
    std::memcpy(&val, &buffer[offset], 8);
    return isLittleEndian ? val : __builtin_bswap64(val);
}

} // namespace symexec
