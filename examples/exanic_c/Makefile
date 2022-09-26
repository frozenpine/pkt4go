NAME=exanic_c
ARCH=$(shell uname -m)

LIB=-L../../exanic/libs
LD_FLAGS=-lexanic

INCLUDE=-I../../ -I../../exanic/include

CC=gcc
CFLAGS=-ggdb3
CFLAGS+=$(CFLAG)

default:
	$(CC) $(CFLAGS) -o $(NAME) *.c \
		$(INCLUDE) $(LIB) $(LD_FLAGS)

.PHONY: clean
clean:
	-rm -f $(BINARY)
