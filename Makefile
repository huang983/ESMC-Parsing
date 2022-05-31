CC := $(CROSS_COMPILE)gcc

SRCS = $(wildcard *.c)

LDLIBS  =
override CFLAGS += -Wall

all: synce

synce:
	$(CC) $(CFLAGS) main.c -o $@ $(LDLIBS)

.PHONY: clean
clean:
	@rm -rvf *.o synce