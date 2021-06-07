#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *it;

    if(pcap_findalldevs(&it, errbuf) != 0) {
        while (it) {
            printf("%s - %s\n", it->name, it->description);
            // printf("%s\n", iptos(it->addresses->addr));
            it = it->next;
        }
        pcap_freealldevs(it);
    }
    else {
        printf("error: find all devs - %s\n", errbuf);
        exit(-1);
    }

    return 0;
}