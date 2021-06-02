#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "read_file.h"

#define CHUNK_SIZE 4096

void* read_file(size_t* size, const char* file_name) {
	if (size == NULL || file_name == NULL) return NULL;
	char* buffer = NULL;
	size_t cur_size = 0;
	FILE* fp = fopen(file_name, "rb");
	if (fp == NULL) {
		perror("read_file: fopen");
		return NULL;
	}
	for (;;) {
		char chunk[CHUNK_SIZE];
		size_t size_read = fread(chunk, 1, CHUNK_SIZE, fp);
		if (ferror(fp)) {
			fputs("read_file: read error\n", stderr);
			fclose(fp);
			free(buffer);
			return NULL;
		}
		if (size_read > 0) {
			if (cur_size > SIZE_MAX - size_read) {
				fputs("read_file: file too large\n", stderr);
				fclose(fp);
				free(buffer);
				return NULL;
			}
			char* new_buffer = realloc(buffer, cur_size + size_read);
			if (new_buffer == NULL) {
				perror("read_file: realloc");
				fclose(fp);
				free(buffer);
				return NULL;
			}
			buffer = new_buffer;
			memcpy(buffer + cur_size, chunk, size_read);
			cur_size += size_read;
		}
		if (feof(fp)) {
			fclose(fp);
			*size = cur_size;
			return buffer;
		}
	}
}
