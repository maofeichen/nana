#include <pcap.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#define FLAG_STRLEN 128 /* Maximum str length to hold dev flags */

bool get_strflags(bpf_u_int32 flags, char* sflag);
bool get_sa_addr(struct sockaddr *sa, char* saddr);
bool print_dev(pcap_if_t *ift);
bool print_alldevs();
void usage(char *n);

bool get_strflags(bpf_u_int32 flags, char* sflag)
{
    bool isflag = false;
    if(flags & PCAP_IF_UP) {
        strcat(sflag, "UP");
        isflag = true;
    }

    if(flags & PCAP_IF_LOOPBACK) {
        if(isflag)
            strcat(sflag, "|");
        strcat(sflag, "LOOPBACK");
        isflag = true;
    }

    if(flags & PCAP_IF_RUNNING) {
        if(isflag)
            strcat(sflag, "|");
        strcat(sflag, "RUNNING");
        isflag = true;
    }

    if(flags & PCAP_IF_WIRELESS) {
        if(isflag)
            strcat(sflag, "|");
        strcat(sflag, "WIRELESS");
        isflag = true;
    }

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

bool print_dev(pcap_if_t *ift)
{
    pcap_addr_t *a = NULL;
    char saddr[INET6_ADDRSTRLEN] = {0};
    char sflag[FLAG_STRLEN] = {0};

    if(ift != NULL && ift->name) {
        printf("%s:\n", ift->name);
        
        if(ift->description)
            printf("\t%s\n", ift->description);

        if(get_strflags(ift->flags, sflag) )
            printf("\tflags=%d<%s>\n", ift->flags, sflag);

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
        return true;
    }
    return false;
}

bool print_alldevs()
{
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t *ift;

    if(pcap_findalldevs(&ift, errbuf) == 0) {
        // local copy of *ift, otherwise *ift can't be free correctly
        for(pcap_if_t *it = ift; it; it=it->next) {
            print_dev(it);
        }
        pcap_freealldevs(ift);
    }
    else {
        fprintf(stderr, "%s\n", errbuf);
        return false;
    }
    return true;
}

void usage(char *n)
{
    printf("usage: %s -p\n", n);
}

int main(int argc, char *argv[])
{
    static const struct option longopts[] = {
        {.name = "print", .has_arg = no_argument, .val = 'p'},
        {.name = "help", .has_arg = no_argument, .val = 'h'},
        {},
    };

    // opterr = 0;
    for (;;) {
        int opt = getopt_long(argc, argv, "ph", longopts, NULL);
        if (opt == -1)
            break;
        switch (opt)
        {
        case 'p':
            print_alldevs();
            break;
        case 'h':
        default:
            usage(argv[0]);
            break;
        }
    }

    for(int i = optind; i < argc; i++) {
        fprintf(stderr, "%s: invalid positional argument: %s\n", argv[0], argv[i]);
    }

    return 0;
}