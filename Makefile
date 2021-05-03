CC=gcc
CFLAGS=-Wall -Wextra -std=c99 -pedantic -O2
LD=gcc
LDFLAGS=-static

TARGET=runelf64

OBJS=runelf64_main.o

$(TARGET): $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^

.PHONY: clean
clean:
	rm -f $(OBJS) $(TARGET)
