#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "read_file.h"

#define CHUNK_SIZE 4096

void* readFile(size_t* size, const char* fileName) {
	if (size == NULL || fileName == NULL) return NULL;
	char* buffer = NULL;
	size_t curSize = 0;
	FILE* fp = fopen(fileName, "rb");
	if (fp == NULL) {
		perror("readFile: fopen");
		return NULL;
	}
	for (;;) {
		char chunk[CHUNK_SIZE];
		size_t sizeRead = fread(chunk, 1, CHUNK_SIZE, fp);
		if (ferror(fp)) {
			fputs("readFile: read error\n", stderr);
			fclose(fp);
			free(buffer);
			return NULL;
		}
		if (sizeRead > 0) {
			if (curSize > SIZE_MAX - sizeRead) {
				fputs("readFile: file too large\n", stderr);
				fclose(fp);
				free(buffer);
				return NULL;
			}
			char* newBuffer = realloc(buffer, curSize + sizeRead);
			if (newBuffer == NULL) {
				perror("readFile: realloc");
				fclose(fp);
				free(buffer);
				return NULL;
			}
			buffer = newBuffer;
			memcpy(buffer + curSize, chunk, sizeRead);
		}
		if (feof(fp)) {
			fclose(fp);
			*size = curSize;
			return buffer;
		}
	}
}
