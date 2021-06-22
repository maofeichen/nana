CC = gcc
CCFLAG = -g -Wall

all: nm.c
	${CC} ${CCFLAG} -o nm nm.c -lpcap 

.PHONY: clean
clean:
	rm -rf *.o nm