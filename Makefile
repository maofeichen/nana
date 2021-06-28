CC = gcc
CCFLAG = -g -Wall

nm:	main.o nm_pcap.o
	${CC} ${CCFLAG} -o nm main.o nm_pcap.o -lpcap 

main.o:	main.c
	${CC} ${CCFLAG} -c main.c 

nm_pcap.o:	nm_pcap.c
	${CC} ${CCFLAG} -c nm_pcap.c nm_pcap.h 

.PHONY: clean
clean:
	rm -rf *.o nm
