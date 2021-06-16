#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#define FLAG_STRLEN 128

bool get_flags(bpf_u_int32 flags, char* sflag);
bool get_sa_addr(struct sockaddr *sa, char* saddr);
void print_ift(pcap_if_t *ift);
void print_alldev();
void usage(char *n);

bool get_flags(bpf_u_int32 flags, char* sflag)
{
    if(flags & PCAP_IF_LOOPBACK)
        strcat(sflag, "loopback ");

    if(flags & PCAP_IF_UP)
        strcat(sflag, "up ");

    if(flags & PCAP_IF_WIRELESS)
        strcat(sflag, "wireless ");

    if (*sflag != 0)
        return true;
    else
        return false;
}

bool get_sa_addr(struct sockaddr *sa, char* saddr)
{
    if(sa != NULL) {
        switch (sa->sa_family)
        {
        case AF_INET :
        case AF_INET6:
            if(inet_ntop(sa->sa_family,&(((struct sockaddr_in*)sa)->sin_addr),saddr,INET6_ADDRSTRLEN) == NULL) {
                perror("inet_ntop");
                // exit(EXIT_FAILURE);
            }
            break;
        default:
            printf("\terror: unknown af_family:%u", sa->sa_family);
            return false;
            // break;
        }
        return true;
    }
    return false;
}

void print_ift(pcap_if_t *ift)
{
    pcap_addr_t *a = NULL;
    char saddr[INET6_ADDRSTRLEN] = {0};
    char sflag[FLAG_STRLEN] = {0};

    if(ift != NULL) {
        printf("%s:\n", ift->name);
        if(ift->description)
            printf("\t%s\n", ift->description);

        if(get_flags(ift->flags, sflag) )
            printf("\t%s\n", sflag);

        for(a = ift->addresses; a; a = a->next) {
            if(get_sa_addr(a->addr,saddr) ) 
                printf("\taddr: %s ", saddr);
            
            if(get_sa_addr(a->netmask, saddr) )
                printf("netmask: %s ", saddr);

            if(get_sa_addr(a->broadaddr, saddr) )
                printf("broadaddr: %s ", saddr);
            
            if(get_sa_addr(a->dstaddr, saddr) )
                printf("dstaddr: %s ", saddr);
            printf("\n");
        }
    }
}

void print_alldev()
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
}

void usage(char *n)
{
    printf("usage: %s -p\n", n);
}

int main(int argc, char *argv[])
{
    // opterr = 0;
    for (;;) {
        int opt = getopt(argc, argv, "ph?");
        if (opt == -1)
            break;
        switch (opt)
        {
        case 'p':
            print_alldev();
            break;
        case '?':
            fprintf(stderr, "%s: unexpected option: %c\n", argv[0], optopt);
            usage(argv[0]);
            return -1;
        case 'h':
        default:
            usage(argv[0]);
            break;
        }
    }

    for(int i = optind; i < argc; i++) {
        fprintf(stderr, "non option: %s\n", argv[i]);
    }

    // if (optind != argc)
    // {
    //     fprintf(stderr, "A non option was supplied\n");
    //     usage(argv[0]);
    //     return -1;
    // }

    return 0;
}