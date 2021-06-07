CC = gcc
CCFLAG = -g -Wall

all: hello_pcap.c
	# gcc -g -Wall -o hello_pcap hello_pcap.c -L/usr/local/lib -lpcap
	${CC} ${CCFLAG} -o hello_pcap hello_pcap.c -lpcap 

.PHONY: clean
clean:
	rm -rf *.o hello_pcap