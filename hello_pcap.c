#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

void print_ift(pcap_if_t *ift);
void print_sa(struct sockaddr *sa);

void print_sa(struct sockaddr *sa)
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

void print_ift(pcap_if_t *ift)
{
    pcap_addr_t *a = NULL;

    if(ift != NULL) {
        printf("%s:\n", ift->name);
        if(ift->description)
            printf("\t%s\n", ift->description);

        if(ift->flags & PCAP_IF_LOOPBACK)
            printf("\tloopback\n");

        for(a = ift->addresses; a; a = a->next) {
            print_sa(a->addr);
            print_sa(a->netmask);
            print_sa(a->broadaddr);
            print_sa(a->dstaddr);
        }
    }
}

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t *ift, *it;

    if(pcap_findalldevs(&ift, errbuf) == 0) {
        // local copy of *ift, otherwise *ift can't be free correctly
        for(it = ift; it; it=it->next) {
            print_ift(it);
        }
        pcap_freealldevs(ift);
    }
    else {
        fprintf(stderr, "%s\n", errbuf);
        exit(1);
    }

    return 0;
}