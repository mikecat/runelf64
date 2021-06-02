#ifndef PARSE_ELF_H_GUARD_DB72AE1B_B85E_4C0C_B5FA_D61A7C0FB9C3
#define PARSE_ELF_H_GUARD_DB72AE1B_B85E_4C0C_B5FA_D61A7C0FB9C3

#include <stdint.h>

#define ELF_CLASS_32BIT 1
#define ELF_CLASS_64BIT 2

#define ELF_DATA_LITTLE_ENDIAN 1
#define ELF_DATA_BIG_ENDIAN 2

struct elf_ident {
	uint8_t magic[4];
	uint8_t elf_class;
	uint8_t data_encoding;
	uint8_t version;
	uint8_t padding[9];
};

struct elf_header {
	struct elf_ident ident;
	uint16_t type;
	uint16_t machine;
	uint32_t version;
	uint64_t entry_address;
	uint64_t program_table_offset;
	uint64_t section_table_offset;
	uint32_t flags;
	uint16_t header_size;
	uint16_t program_table_entry_size;
	uint16_t program_table_entry_num;
	uint16_t section_table_entry_size;
	uint16_t section_table_entry_num;
	uint16_t string_section_index;
};

struct elf_program_header {
	uint32_t type;
	uint64_t offset;
	uint64_t virtual_addr;
	uint64_t physical_addr;
	uint64_t file_size;
	uint64_t memory_size;
	uint32_t flags;
	uint64_t align;
};

struct elf_section_header {
	uint32_t name_idx;
	uint32_t type;
	uint64_t flags;
	uint64_t addr;
	uint64_t offset;
	uint64_t size;
	uint32_t link;
	uint32_t info;
	uint64_t addr_align;
	uint64_t entry_size;
};

struct elf_info {
	struct elf_header header;
	struct elf_program_header* program_headers;
	struct elf_section_header* section_headers;
};

/*
Read header information from ELF data on the memory.
Returns NULL on failure.
Result may contain pointers to original data.
*/
struct elf_info* parse_elf(const void* data, size_t size);

void free_elf_info(struct elf_info* data);

void dump_elf_info(const struct elf_info* info, const void* data);

#endif
