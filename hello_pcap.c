#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t *ift = NULL;

    if(pcap_findalldevs(&ift, errbuf) == 0) {
        pcap_if_t *it = ift; // local copy of *ift, otherwise *ift can't be free correctly
        while (it) {
            printf("%s - %s\n", it->name, it->description);
            it = it->next;
        }
        pcap_freealldevs(ift);
    }
    else {
        printf("error: %s\n", errbuf);
        exit(-1);
    }

    return 0;
}