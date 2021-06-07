all: hello_pcap.c
	# gcc -g -Wall -o hello_pcap hello_pcap.c -L/usr/local/lib -lpcap
	gcc -g -Wall -o hello_pcap hello_pcap.c -lpcap 


clean:
	rm -rf *.o hello_pcap