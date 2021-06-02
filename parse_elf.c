#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include "parse_elf.h"

uint16_t read16_little(const uint8_t* data) {
	return data[0] | ((uint16_t)data[1] << 8);
}

uint32_t read32_little(const uint8_t* data) {
	return data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

uint64_t read64_little(const uint8_t* data) {
	return data[0] | ((uint64_t)data[1] << 8) | ((uint64_t)data[2] << 16) | ((uint64_t)data[3] << 24) |
		((uint64_t)data[4] << 32) | ((uint64_t)data[5] << 40) | ((uint64_t)data[6] << 48) | ((uint64_t)data[7] << 56);
}

uint16_t read16_big(const uint8_t* data) {
	return ((uint16_t)data[0] << 8) | data[1];
}

uint32_t read32_big(const uint8_t* data) {
	return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | data[3];
}

uint64_t read64_big(const uint8_t* data) {
	return ((uint64_t)data[0] << 56) | ((uint64_t)data[1] << 48) | ((uint64_t)data[2] << 40) | ((uint64_t)data[3] << 32) |
		((uint64_t)data[4] << 24) | ((uint64_t)data[5] << 16) | ((uint64_t)data[6] << 8) | data[7];
}

struct elf_info* parse_elf(const void* data, size_t size) {
	const uint8_t* udata = data;
	if (udata == NULL) return NULL;
	struct elf_info* result = calloc(1, sizeof(*result));
	if (result == NULL) {
		perror("calloc");
		return NULL;
	}
	if (size < 16) {
		fputs("data too small\n", stderr);
		free_elf_info(result);
		return NULL;
	}
	for (int i = 0; i < 4; i++) {
		result->header.ident.magic[i] = udata[i];
	}
	result->header.ident.elf_class = udata[4];
	result->header.ident.data_encoding = udata[5];
	result->header.ident.version = udata[6];
	for (int i = 0; i < 9; i++) {
		result->header.ident.padding[i] = udata[7 + i];
	}
	if (result->header.ident.magic[0] != 0x7f || result->header.ident.magic[1] != 0x45 ||
	result->header.ident.magic[2] != 0x4c || result->header.ident.magic[3] != 0x46) {
		fputs("not ELF file\n", stderr);
		free_elf_info(result);
		return NULL;
	}
	if (result->header.ident.elf_class != ELF_CLASS_32BIT && result->header.ident.elf_class != ELF_CLASS_64BIT) {
		fprintf(stderr, "unsupported ELF class 0x%02X\n", result->header.ident.elf_class);
		free_elf_info(result);
		return NULL;
	}
	if (result->header.ident.data_encoding != ELF_DATA_LITTLE_ENDIAN && result->header.ident.data_encoding != ELF_DATA_BIG_ENDIAN) {
		fprintf(stderr, "unsupported data encoding 0x%02X\n", result->header.ident.data_encoding);
		free_elf_info(result);
		return NULL;
	}
	if (result->header.ident.version != 1) {
		fprintf(stderr, "unsupported ELF version 0x%02X\n", result->header.ident.version);
		free_elf_info(result);
		return NULL;
	}
	uint16_t (*read16)(const uint8_t*);
	uint32_t (*read32)(const uint8_t*);
	uint64_t (*read64)(const uint8_t*);
	if (result->header.ident.data_encoding == ELF_DATA_BIG_ENDIAN) {
		read16 = read16_big;
		read32 = read32_big;
		read64 = read64_big;
	} else {
		read16 = read16_little;
		read32 = read32_little;
		read64 = read64_little;
	}
	uint16_t header_size_expected = result->header.ident.elf_class== ELF_CLASS_32BIT ? 0x34 : 0x40;
	if (size < header_size_expected) {
		fputs("data too small for header\n", stderr);
		free_elf_info(result);
		return NULL;
	}

	if (result->header.ident.elf_class== ELF_CLASS_32BIT) {
		result->header.type = read16(udata + 0x10);
		result->header.machine = read16(udata + 0x12);
		result->header.version = read32(udata + 0x14);
		result->header.entry_address = read32(udata + 0x18);
		result->header.program_table_offset = read32(udata + 0x1c);
		result->header.section_table_offset = read32(udata + 0x20);
		result->header.flags = read32(udata + 0x24);
		result->header.header_size = read16(udata + 0x28);
		result->header.program_table_entry_size = read16(udata + 0x2a);
		result->header.program_table_entry_num = read16(udata + 0x2c);
		result->header.section_table_entry_size = read16(udata + 0x2e);
		result->header.section_table_entry_num = read16(udata + 0x30);
		result->header.string_section_index = read16(udata + 0x32);
	} else {
		result->header.type = read16(udata + 0x10);
		result->header.machine = read16(udata + 0x12);
		result->header.version = read32(udata + 0x14);
		result->header.entry_address = read64(udata + 0x18);
		result->header.program_table_offset = read64(udata + 0x20);
		result->header.section_table_offset = read64(udata + 0x28);
		result->header.flags = read32(udata + 0x30);
		result->header.header_size = read16(udata + 0x34);
		result->header.program_table_entry_size = read16(udata + 0x36);
		result->header.program_table_entry_num = read16(udata + 0x38);
		result->header.section_table_entry_size = read16(udata + 0x3a);
		result->header.section_table_entry_num = read16(udata + 0x3c);
		result->header.string_section_index = read16(udata + 0x3e);
	}

	if (result->header.version != 1) {
		fprintf(stderr, "unsupported ELF version 0x%08" PRIx32 "\n", result->header.version);
		free_elf_info(result);
		return NULL;
	}
	if (result->header.header_size < header_size_expected) {
		fprintf(stderr, "ELF header too small (expected %" PRIu16 ", actual %" PRIu16 ")\n",
			header_size_expected, result->header.header_size);
		free_elf_info(result);
		return NULL;
	}

	if (result->header.program_table_entry_num > 0) {
		uint16_t ph_expected_size = result->header.ident.elf_class== ELF_CLASS_32BIT ? 0x20 : 0x38;
		if (result->header.program_table_entry_size < ph_expected_size) {
			fprintf(stderr, "program header table entry too small (expected" PRIu16 ", actual " PRIu16 ")\n",
				ph_expected_size, result->header.program_table_entry_size);
			free_elf_info(result);
			return NULL;
		}
		uint32_t program_table_size = (uint32_t)result->header.program_table_entry_size * result->header.program_table_entry_num;
		if(program_table_size > size || result->header.program_table_offset > size - program_table_size) {
			fprintf(stderr, "program header table (offset 0x" PRIx64 ", size 0x" PRIx32 ") out-of-data\n",
				result->header.program_table_offset, program_table_size);
			free_elf_info(result);
			return NULL;
		}
		result->program_headers = malloc(sizeof(*result->program_headers) * result->header.program_table_entry_num);
		if (result->program_headers == NULL) {
			perror("malloc");
			free_elf_info(result);
			return NULL;
		}
		for (uint32_t i = 0; i < result->header.program_table_entry_num; i++) {
			const uint8_t* entry = udata + result->header.program_table_offset + (uint32_t)result->header.program_table_entry_size * i;
			if (result->header.ident.elf_class== ELF_CLASS_32BIT) {
				result->program_headers[i].type = read32(entry + 0x00);
				result->program_headers[i].offset = read32(entry + 0x04);
				result->program_headers[i].virtual_addr = read32(entry + 0x08);
				result->program_headers[i].physical_addr = read32(entry + 0x0c);
				result->program_headers[i].file_size = read32(entry + 0x10);
				result->program_headers[i].memory_size = read32(entry + 0x14);
				result->program_headers[i].flags = read32(entry + 0x18);
				result->program_headers[i].align = read32(entry + 0x1c);
			} else {
				result->program_headers[i].type = read32(entry + 0x00);
				result->program_headers[i].offset = read64(entry + 0x08);
				result->program_headers[i].virtual_addr = read64(entry + 0x10);
				result->program_headers[i].physical_addr = read64(entry + 0x18);
				result->program_headers[i].file_size = read64(entry + 0x20);
				result->program_headers[i].memory_size = read64(entry + 0x28);
				result->program_headers[i].flags = read32(entry + 0x04);
				result->program_headers[i].align = read64(entry + 0x30);
			}
			uint64_t offset_in_file = result->program_headers[i].offset;
			uint64_t size_in_file = result->program_headers[i].file_size;
			if (size_in_file > 0 && (size_in_file > size || offset_in_file > size - size_in_file)) {
				fprintf(stderr, "program_headers[%" PRIu32 "] out-of-file (offset 0x%" PRIx64 ", size 0x%" PRIx64 ")\n",
					i, offset_in_file, size_in_file);
				free_elf_info(result);
				return NULL;
			}
		}
	}

	if (result->header.section_table_entry_num > 0) {
		uint16_t sh_expected_size = result->header.ident.elf_class== ELF_CLASS_32BIT ? 0x28 : 0x40;
		if (result->header.section_table_entry_size < sh_expected_size) {
			fprintf(stderr, "section header table entry too small (expected" PRIu16 ", actual " PRIu16 ")\n",
				sh_expected_size, result->header.section_table_entry_size);
			free_elf_info(result);
			return NULL;
		}
		uint32_t section_table_size = (uint32_t)result->header.section_table_entry_size * result->header.section_table_entry_num;
		if(section_table_size > size || result->header.section_table_offset > size - section_table_size) {
			fprintf(stderr, "section header table (offset 0x" PRIx64 ", size 0x" PRIx32 ") out-of-data\n",
				result->header.section_table_offset, section_table_size);
			free_elf_info(result);
			return NULL;
		}
		if (result->header.string_section_index != 0 && result->header.string_section_index >= result->header.section_table_entry_num) {
			fprintf(stderr, "invalid string section index (index %" PRIu16 " among %" PRIu16 " entries)\n",
				result->header.string_section_index, result->header.section_table_entry_num);
			free_elf_info(result);
			return NULL;
		}
		result->section_headers = malloc(sizeof(*result->section_headers) * result->header.section_table_entry_num);
		if (result->section_headers == NULL) {
			perror("malloc");
			free_elf_info(result);
			return NULL;
		}
		for (uint32_t i = 0; i < result->header.section_table_entry_num; i++) {
			const uint8_t* entry = udata + result->header.section_table_offset + (uint32_t)result->header.section_table_entry_size * i;
			if (result->header.ident.elf_class== ELF_CLASS_32BIT) {
				result->section_headers[i].name_idx = read32(entry + 0x00);
				result->section_headers[i].type = read32(entry + 0x04);
				result->section_headers[i].flags = read32(entry + 0x08);
				result->section_headers[i].addr = read32(entry + 0x0c);
				result->section_headers[i].offset = read32(entry + 0x10);
				result->section_headers[i].size = read32(entry + 0x14);
				result->section_headers[i].link = read32(entry + 0x18);
				result->section_headers[i].info = read32(entry + 0x1c);
				result->section_headers[i].addr_align = read32(entry + 0x20);
				result->section_headers[i].entry_size = read32(entry + 0x24);
			} else {
				result->section_headers[i].name_idx = read32(entry + 0x00);
				result->section_headers[i].type = read32(entry + 0x04);
				result->section_headers[i].flags = read64(entry + 0x08);
				result->section_headers[i].addr = read64(entry + 0x10);
				result->section_headers[i].offset = read64(entry + 0x18);
				result->section_headers[i].size = read64(entry + 0x20);
				result->section_headers[i].link = read32(entry + 0x28);
				result->section_headers[i].info = read32(entry + 0x2c);
				result->section_headers[i].addr_align = read64(entry + 0x30);
				result->section_headers[i].entry_size = read64(entry + 0x38);
			}
			uint64_t offset_in_file = result->section_headers[i].offset;
			uint64_t size_in_file = result->section_headers[i].size;
			if (result->section_headers[i].type != 8 && /* SHT_NOBITS */
			size_in_file > 0 && (size_in_file > size || offset_in_file > size - size_in_file)) {
				fprintf(stderr, "section_headers[%" PRIu32 "] out-of-file (offset 0x%" PRIx64 ", size 0x%" PRIx64 ")\n",
					i, offset_in_file, size_in_file);
				free_elf_info(result);
				return NULL;
			}
		}
		if (result->header.string_section_index != 0) {
			if (result->section_headers[result->header.string_section_index].type == 8) {
				fprintf(stderr, "string table (%" PRIu16 ") has type SHT_NOBITS\n", result->header.string_section_index);
				free_elf_info(result);
				return NULL;
			}
			struct elf_section_header* str_table = &result->section_headers[result->header.string_section_index];
			uint64_t last_nul = str_table->size;
			if (str_table->size > 0) {
				if (udata[str_table->offset] == 0) last_nul = 0;
				for (uint64_t i = str_table->size - 1; i > 0; i--) {
					if (udata[str_table->offset + i] == 0) {
						last_nul = i;
						break;
					}
				}
			}
			if (last_nul >= str_table->size) {
				fprintf(stderr, "no NUL in string table (%" PRIu16 ")\n", result->header.string_section_index);
				free_elf_info(result);
				return NULL;
			}
			for (uint32_t i = 0; i < result->header.section_table_entry_num; i++) {
				if (result->section_headers[i].name_idx > last_nul) {
					fprintf(stderr, "name index of section_headers[%" PRIu32 "] (" PRIu32 ") is beyond last NUL (%" PRIu64 ")\n",
						i, result->section_headers[i].name_idx, last_nul);
					free_elf_info(result);
					return NULL;
				}
			}
		}
	}

	return result;
}

void free_elf_info(struct elf_info* data) {
	if (data != NULL) {
		free(data->program_headers);
		free(data);
	}
}

void dump_elf_info(const struct elf_info* info, const void* data) {
	if (info == NULL || data == NULL) return;
	{
		const char* class_str = "", *encoding_str = "";
		switch (info->header.ident.elf_class) {
			case 1: class_str = " (32bit)"; break;
			case 2: class_str = " (64bit)"; break;
		}
		switch (info->header.ident.data_encoding) {
			case 1: encoding_str = " (little endian)"; break;
			case 2: encoding_str = " (big endian)"; break;
		}
		printf("class: 0x%02" PRIx8 "%s encoding: 0x%02" PRIx8 "%s ident_version: %" PRIu8 "\n",
			info->header.ident.elf_class, class_str, info->header.ident.data_encoding, encoding_str,
			info->header.ident.version);
	}
	{
		const char* type_str = "", *machine_str = "";
		switch (info->header.type) {
			case 0: type_str = " (ET_NONE)"; break;
			case 1: type_str = " (ET_REL)"; break;
			case 2: type_str = " (ET_EXEC)"; break;
			case 3: type_str = " (ET_DYN)"; break;
			case 4: type_str = " (ET_CORE)"; break;
		}
		switch (info->header.machine) {
			case 0: machine_str = " (none)"; break;
			case 1: machine_str = " (AT&T WE 32100)"; break;
			case 2: machine_str = " (SPARC)"; break;
			case 3: machine_str = " (Intel)"; break;
			case 4: machine_str = " (Motorola 68000)"; break;
			case 5: machine_str = " (Motorola 88000)"; break;
			case 7: machine_str = " (Intel 80860)"; break;
			case 8: machine_str = " (MIPS RS3000)"; break;
			case 10: machine_str = " (MIPS RS4000)"; break;
			case 11: case 12: case 13: case 14: case 15: case 16: machine_str = " (reserved)"; break;
		}
		char type_buf[32];
		snprintf(type_buf, sizeof(type_buf),
			info->header.type >= UINT16_C(0xff00) ? "0x%" PRIx16 : "%" PRIu16, info->header.type);
		printf("type: %s%s machine: %" PRIu16 "%s version: %" PRIu32 "\n",
			type_buf, type_str, info->header.machine, machine_str, info->header.version);
	}
	printf("entry_address: 0x%016" PRIx64 " flags: 0x%08" PRIx32 " string_section: %" PRIu16 "\n",
		info->header.entry_address, info->header.flags, info->header.string_section_index);

	if (info->header.program_table_entry_num > 0) {
		printf("\nprogram headers\n");
		int width = 1;
		for (uint16_t num = info->header.program_table_entry_num; num > 9; num /= 10) width++;
		for (uint16_t i = 0; i < info->header.program_table_entry_num; i++) {
			const char* type_str = "";
			switch (info->program_headers[i].type) {
				case 0: type_str = " (PT_NULL)"; break;
				case 1: type_str = " (PT_LOAD)"; break;
				case 2: type_str = " (PT_DYNAMIC)"; break;
				case 3: type_str = " (PT_INTERP)"; break;
				case 4: type_str = " (PT_NOTE)"; break;
				case 5: type_str = " (PT_SHLIB)"; break;
				case 6: type_str = " (PT_PHDR)"; break;
			}
			char type_buf[32];
			snprintf(type_buf, sizeof(type_buf),
				info->program_headers[i].type >= UINT32_C(0x10000000) ? "0x%" PRIx32 : "%" PRIu32, info->program_headers[i].type);
			char flags_str[] = "---";
			if (info->program_headers[i].flags & 0x4) flags_str[0] = 'R';
			if (info->program_headers[i].flags & 0x2) flags_str[1] = 'W';
			if (info->program_headers[i].flags & 0x1) flags_str[2] = 'X';
			printf("\n[%*" PRIu16 "] type: %s%s flags: 0x%08" PRIx32 " (%s)\n",
				width, i, type_buf, type_str, info->program_headers[i].flags, flags_str);
			printf(" %*c  offset: 0x%016" PRIx64 " file_size: 0x%016" PRIx64 "\n",
				width, ' ', info->program_headers[i].offset, info->program_headers[i].file_size);
			printf(" %*c  virtual_addr: 0x%016" PRIx64 " physical_addr: 0x%016" PRIx64 "\n",
				width, ' ', info->program_headers[i].virtual_addr, info->program_headers[i].physical_addr);
			printf(" %*c  memory_size: 0x%016" PRIx64 " align: 0x%016" PRIx64 "\n",
				width, ' ', info->program_headers[i].memory_size, info->program_headers[i].align);
		}
	}

	if (info->header.section_table_entry_num > 0) {
		printf("\nsection headers\n");
		int width = 1;
		for (uint16_t num = info->header.section_table_entry_num; num > 9; num /= 10) width++;
		const uint8_t* str_table = info->header.string_section_index > 0 ?
			(const uint8_t*)data + info->section_headers[info->header.string_section_index].offset : NULL;
		for (uint16_t i = 0; i < info->header.section_table_entry_num; i++) {
			printf("\n[%*" PRIu16 "] name: ", width,i);
			if (str_table == NULL) {
				printf("0x%08" PRIx32 "\n", info->section_headers[i].name_idx);
			} else {
				printf("%s (0x%08" PRIx32 ")\n",
					(const char*)(str_table + info->section_headers[i].name_idx),
					info->section_headers[i].name_idx);
			}
			const char* type_str = "";
			switch (info->section_headers[i].type) {
				case 0: type_str = " (SHT_NULL)"; break;
				case 1: type_str = " (SHT_PROGBITS)"; break;
				case 2: type_str = " (SHT_SYMTAB)"; break;
				case 3: type_str = " (SHT_STRTAB)"; break;
				case 4: type_str = " (SHT_RELA)"; break;
				case 5: type_str = " (SHT_HASH)"; break;
				case 6: type_str = " (SHT_DYNAMIC)"; break;
				case 7: type_str = " (SHT_NOTE)"; break;
				case 8: type_str = " (SHT_NOBITS)"; break;
				case 9: type_str = " (SHT_REL)"; break;
				case 10: type_str = " (SHT_SHLIB)"; break;
				case 11: type_str = " (SHT_DYNSYM)"; break;
			}
			char type_buf[32];
			snprintf(type_buf, sizeof(type_buf),
				info->section_headers[i].type >= UINT32_C(0x10000000) ? "0x%" PRIx32 : "%" PRIu32, info->section_headers[i].type);
			char flags_str[] = "---";
			if (info->section_headers[i].flags & 0x4) flags_str[0] = 'E';
			if (info->section_headers[i].flags & 0x2) flags_str[1] = 'A';
			if (info->section_headers[i].flags & 0x1) flags_str[2] = 'W';
			printf(" %*c  type: %s%s flags: 0x%016" PRIx64 " (%s)\n",
				width, ' ', type_buf, type_str, info->section_headers[i].flags, flags_str);
			printf(" %*c  address: 0x%016" PRIx64 " addr_align: 0x%016" PRIx64 "\n",
				width, ' ', info->section_headers[i].addr, info->section_headers[i].addr_align);
			printf(" %*c  offset: 0x%016" PRIx64 " size: 0x%016" PRIx64 "\n",
				width, ' ', info->section_headers[i].offset, info->section_headers[i].size);
			printf(" %*c  link: 0x%08" PRIx32 " info: 0x%08" PRIx32 " entry_size: 0x%016" PRIx64 "\n",
				width, ' ', info->section_headers[i].link, info->section_headers[i].info,
				info->section_headers[i].entry_size);
		}
	}
}
