#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include "read_file.h"
#include "parse_elf.h"

#define OPTION_NAME_MAX 2

enum option_kind {
	OPTION_EXISTANCE,
	OPTION_STRING,
	OPTION_INT32,
	OPTION_UINT32,
	OPTION_INT64,
	OPTION_UINT64
};

struct option_info {
	const char* name[OPTION_NAME_MAX];
	const char* description;
	enum option_kind kind;
	void* saveTo;
};

/* return non-zero on success, zero on failure */
int str_to_uint64(uint64_t* out, const char* str) {
	uint64_t res = 0;
	int radix = 10;
	if (out == NULL || str == NULL) return 0;
	if (str[0] == '\0') {
		/* emptry string! */
		return 0;
	} else if (str[0] == '0') {
		if (str[1] == '\0') {
			/* "0" */
			*out = 0;
			return 1;
		} else if (str[1] == 'x' || str[1] == 'X') {
			radix = 16;
			str++;
		} else if (str[1] == 'b' || str[1] == 'B') {
			radix = 2;
			str++;
		} else {
			radix = 8;
		}
		str++;
	}
	while (*str != '\0') {
		int digit = -1;
		if ('0' <= *str && *str <= '9') digit = *str - '0';
		else if (*str == 'a' || *str == 'A') digit = 10;
		else if (*str == 'b' || *str == 'B') digit = 11;
		else if (*str == 'c' || *str == 'C') digit = 12;
		else if (*str == 'd' || *str == 'D') digit = 13;
		else if (*str == 'e' || *str == 'E') digit = 14;
		else if (*str == 'f' || *str == 'F') digit = 15;
		if (digit < 0 || radix <= digit) {
			/* invalid character! */
			return 0;
		} else {
			if (res > UINT64_MAX / radix || res * radix > UINT64_MAX - digit) {
				/* overflow! */
				return 0;
			}
			res = res * radix + digit;
		}
		str++;
	}
	*out = res;
	return 1;
}

/* return non-zero on success, zero on failure */
int str_to_int64(int64_t* out, const char* str) {
	if (out == NULL || str == NULL) return 0;
	if (str[0] == '+' && (str[1] != '+' && str[1] != '-')) {
		return str_to_int64(out, str + 1);
	} else if (str[0] == '-') {
		uint64_t minus_int64_min = -(uint64_t)INT64_MIN;
		uint64_t ures;
		int check = str_to_uint64(&ures, str + 1);
		if (!check || ures > minus_int64_min) return 0;
		*out = ures == minus_int64_min ? INT64_MIN : -(int64_t)ures;
		return 1;
	} else {
		uint64_t ures;
		int check = str_to_uint64(&ures, str);
		if (!check || ures > INT64_MAX) return 0;
		*out = ures;
		return 1;
	}
}

int main(int argc, char* argv[]) {
	int help = 0;
	char* elf_name = NULL;

	int option_error = 0;
	const struct option_info options[] = {
		{{"-h", "--help"}, "show this help", OPTION_EXISTANCE, &help}
	};
	const size_t option_num = sizeof(options) / sizeof(*options);

	for (int i = 1; !option_error && i < argc; i++) {
		int hit = 0;
		for (size_t j = 0; j < option_num; j++) {
			int match = 0;
			for (int k = 0; k < OPTION_NAME_MAX && options[j].name[k] != NULL; k++) {
				if (strcmp(argv[i], options[j].name[k]) == 0) {
					match = 1;
					break;
				}
			}
			if (match) {
				switch (options[j].kind) {
					case OPTION_EXISTANCE:
						*(int*)options[j].saveTo = 1;
						break;
					case OPTION_STRING:
						if (i + 1 < argc) {
							*(char**)options[j].saveTo = argv[++i];
						} else {
							fprintf(stderr, "parameter for %s is missing\n", argv[i]);
							option_error = 1;
						}
						break;
					case OPTION_INT32:
					case OPTION_UINT32:
					case OPTION_INT64:
					case OPTION_UINT64:
						if (i + 1 < argc) {
							i++;
							enum option_kind opk = options[j].kind;
							int invalid = 0;
							if (opk == OPTION_INT32 || opk == OPTION_INT64) {
								int64_t res;
								if (str_to_int64(&res, argv[i])) {
									if (opk == OPTION_INT32) {
										if (res < INT32_MIN || INT32_MAX < res) {
											invalid = 1;
										} else {
											*(int32_t*)options[j].saveTo = res;
										}
									} else {
										*(int64_t*)options[j].saveTo = res;
									}
								} else {
									invalid = 1;
								}
							} else {
								uint64_t res;
								if (str_to_uint64(&res, argv[i])) {
									if (opk == OPTION_UINT32) {
										if (UINT32_MAX < res) {
											invalid = 1;
										} else {
											*(uint32_t*)options[j].saveTo = res;
										}
									} else {
										*(uint64_t*)options[j].saveTo = res;
									}
								} else {
									invalid = 1;
								}
							}
							if (invalid) {
								fprintf(stderr, "parameter for %s is invalid\n", argv[i]);
								option_error = 1;
							}
						} else {
							fprintf(stderr, "parameter for %s is missing\n", argv[i]);
							option_error = 1;
						}
						break;
					default:
						assert(!"unknown option kind");
						option_error = 1;
						break;
				}
				hit = 1;
				break;
			}
		}
		if (!hit) {
			if (argv[i][0] != '-' && i == argc - 1) {
				elf_name = argv[i];
			} else {
				fprintf(stderr, "unknown option %s\n", argv[i]);
				option_error = 1;
			}
		}
	}
	if (!help && elf_name == NULL) {
		fprintf(stderr, "no ELF file name given\n");
		option_error = 1;
	}
	if (help || option_error) {
		if (option_error) fprintf(stderr, "\n");
		fprintf(stderr, "Usage: %s [options...] elf_name\n", argc > 0 ? argv[0] : "runelf64");
		fprintf(stderr, "\n");
		fprintf(stderr, "options:\n");
		for (size_t i = 0; i < option_num; i++) {
			fprintf(stderr, "  ");
			for (int j = 0; j < OPTION_NAME_MAX && options[i].name[j] != NULL; j++) {
				if (j > 0) {
					fprintf(stderr, " / ");
				}
				fprintf(stderr, "%s", options[i].name[j]);
				if (options[i].kind != OPTION_EXISTANCE) {
					fprintf(stderr," value");
				}
			}
			fprintf(stderr, " : %s\n", options[i].description);
		}
		return option_error ? 1 : 0;
	}

	size_t elf_size = 0;
	void* elf_data = read_file(&elf_size, elf_name);
	if (elf_data == NULL) {
		fputs("failed to read ELF file\n", stderr);
		return 1;
	}
	struct elf_info* elf_info = parse_elf(elf_data, elf_size);
	if (elf_info == NULL) {
		free(elf_data);
		return 1;
	}

	free_elf_info(elf_info);
	free(elf_data);
	return 0;
}
