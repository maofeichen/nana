#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

void if_print(pcap_if_t *ift);
void sa_print(struct sockaddr *sa);

void sa_print(struct sockaddr *sa)
{
    if(sa != NULL) {
        char str[INET6_ADDRSTRLEN] = {0};
        switch (sa->sa_family)
        {
        case AF_INET :
        case AF_INET6:
            if(inet_ntop(sa->sa_family,&(((struct sockaddr_in*)sa)->sin_addr),str,INET6_ADDRSTRLEN) != NULL) {
                printf("\t%s\n", str);
            }
            else {
                perror("inet_ntop");
                exit(EXIT_FAILURE);
            }
            break;
        default:
            printf("\terror: unknown af_family:%u\n", sa->sa_family);
            break;
        }
    }
}

void if_print(pcap_if_t *ift)
{
    pcap_addr_t *a = NULL;

    if(ift != NULL) {
        printf("%s:\n", ift->name);
        if(ift->description)
            printf("\t%s\n", ift->description);
        if(ift->flags & PCAP_IF_LOOPBACK)
            printf("\tloopback\n");

        for(a = ift->addresses; a; a = a->next) {
            sa_print(a->addr);
            sa_print(a->netmask);
            sa_print(a->broadaddr);
            sa_print(a->dstaddr);
        }
    }
}

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t *ift = NULL;

    if(pcap_findalldevs(&ift, errbuf) == 0) {
        pcap_if_t *it = ift; // local copy of *ift, otherwise *ift can't be free correctly
        while (it) {
            if_print(it);
            it = it->next;
        }
        pcap_freealldevs(ift);
    }
    else {
        printf("error: %s\n", errbuf);
        exit(1);
    }

    return 0;
}