#include "nm_pcap.h"
#include <stdlib.h> // exit, etc.
#include <string.h> /* strcat */

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

void print_dev(pcap_if_t *ift)
{
    pcap_addr_t *paddr;
    char saddr[INET6_ADDRSTRLEN] = {0};
    char sflag[FLAG_STRLEN];

    if(ift != NULL) {
        /* Print dev name, desc and flags if any */
        if(ift->name)
            printf("%s:\n", ift->name); 
        if(ift->description)
            printf("\t%s\n", ift->description);
        if(get_strflags(ift->flags, sflag)) 
            printf("\tflags=%d<%s>\n", ift->flags, sflag);

        /* Print dev addr, netmask, broad, dst addrs if any */
        for(paddr = ift->addresses; paddr; paddr = paddr->next) {   
            if(get_straddr(paddr->addr,saddr) )         // addr 
                printf("\taddr %s ", saddr);
            if(get_straddr(paddr->netmask, saddr) )     // netmask
                printf("netmask %s ", saddr);
            if(get_straddr(paddr->broadaddr, saddr) )   // broadaddr
                printf("broadaddr %s ", saddr);
            if(get_straddr(paddr->dstaddr, saddr) )     // dstaddr
                printf("dstaddr %s ", saddr);
            printf("\n");
        }
    } else {
        fprintf(stderr, "Error: pcap_if_t:%p is NULL\n", ift);
    }
}

void print_alldevs()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *ift, *it;

    if(pcap_findalldevs(&ift, errbuf) == 0) {
        for(it = ift; it; it=it->next) {
            print_dev(it);
        }
        pcap_freealldevs(ift);
    } else {
        fprintf(stderr, "Error: %s\n", errbuf);
        exit(1);
    }
}