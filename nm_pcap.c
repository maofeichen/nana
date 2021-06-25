#include <string.h> // for strcat, etc
#include "nm_pcap.h"

#define FLAG_STRLEN 128 /* Maximum str length to hold dev flags */



bool get_straddr(struct sockaddr *sa, char* saddr)
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
            printf("\tunknown af_family:%u", sa->sa_family);
            return false;
        }
        return true;
    }
    return false;
}

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

    if(flags & PCAP_IF_CONNECTION_STATUS) {
        if(isflag)
            strcat(sflag, "|");

        if(flags & PCAP_IF_CONNECTION_STATUS_CONNECTED)
            strcat(sflag, "CONNECTED");
        else if(flags & PCAP_IF_CONNECTION_STATUS_DISCONNECTED)
            strcat(sflag, "DISCONNECTED");
        else if(flags & PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE)
            strcat(sflag, "CONN_NOT_APPLICABLE");
        else if(flags & PCAP_IF_CONNECTION_STATUS_UNKNOWN)
            strcat(sflag, "CONN_UNKNOWN");

        isflag = true;
    }

    if(flags & PCAP_IF_WIRELESS) {
        if(isflag)
            strcat(sflag, "|");
        strcat(sflag, "WIRELESS");
        isflag = true;
    }

    if (isflag)
        return true;
    else
        return false;
}

bool print_dev(pcap_if_t *ift)
{
    pcap_addr_t *paddr = NULL;
    char straddr[INET6_ADDRSTRLEN] = {0};
    char strflag[FLAG_STRLEN] = {0};

    if(ift != NULL && ift->name) {
        printf("%s:\n", ift->name); // dev: name
        
        if(ift->description)    // dev: description 
            printf("\t%s\n", ift->description);

        if(get_strflags(ift->flags, strflag) )  // dev: flags 
            printf("\tflags=%d<%s>\n", ift->flags, strflag);

        // dev: addrs 
        for(paddr = ift->addresses; paddr; paddr = paddr->next) {   
            if(get_straddr(paddr->addr,straddr) ) {
                switch (paddr->addr->sa_family)
                {
                case AF_INET:
                    printf("\tinet ");
                    break;
                case AF_INET6:
                    printf("\tinet6 ");
                    break;
                default:
                    printf("\taddr ");
                    break;
                }
                printf("%s ", straddr);
            }
            
            if(get_straddr(paddr->netmask, straddr) )
                printf("netmask %s ", straddr);

            if(get_straddr(paddr->broadaddr, straddr) )
                printf("broadaddr %s ", straddr);
            
            if(get_straddr(paddr->dstaddr, straddr) )
                printf("dstaddr %s ", straddr);
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

