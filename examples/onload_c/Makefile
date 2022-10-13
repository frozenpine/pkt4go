NAME=onload_c
ARCH=$(shell uname -m)

LIB=-L../../onload/libs
LD_FLAGS=-lciul1

INCLUDE=-I../../ -I../../onload/include

CC=gcc
CFLAGS=-ggdb3
CFLAGS+=$(CFLAG)

default:
	$(CC) $(CFLAGS) -o $(NAME) *.c \
		$(INCLUDE) $(LIB) $(LD_FLAGS)

.PHONY: clean
clean:
	-rm -f $(BINARY)
