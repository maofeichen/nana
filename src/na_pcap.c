#include "na_pcap.h"
#include <signal.h>
#include <stdlib.h> // exit, etc 
#include <string.h> // strcat 
#include <stdbool.h>
#include <stdint.h>

pcap_t *pkt_handler;    // packet handler: accessible in a signal handler function
u_int64_t cap_cnt = 0;  // number of captured packets
bool is_termin_cap = false; // flag to terminate capture

bool get_straddr(struct sockaddr *sa, char* saddr);
bool get_strflag(bpf_u_int32 flags, char* sflag);
void p_dev(pcap_if_t *ift);

void sigint_hndlr(int sig);
void proc_pkt(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

bool get_straddr(struct sockaddr *sa, char* saddr)
{
    if(sa != NULL) {
        switch (sa->sa_family)
        {
        case AF_INET :
            if(inet_ntop(sa->sa_family,&(((struct sockaddr_in*)sa)->sin_addr),saddr,INET_ADDRSTRLEN) == NULL) {
                perror("inet_ntop");
                // exit(EXIT_FAILURE);
            }
            break;
        case AF_INET6:
            if(inet_ntop(sa->sa_family,&(((struct sockaddr_in6*)sa)->sin6_addr),saddr,INET6_ADDRSTRLEN) == NULL) {
                perror("inet_ntop");
                // exit(EXIT_FAILURE);
            }
            break;
        case AF_PACKET:
            // printf("\tAF_PACKET");
            strcpy(saddr, "AF_PACKET");
            // saddr = "AF_PACKET";
            break;
        default:
            printf("\tunknown AF_Family:%u", sa->sa_family);
            return false;
        }
        return true;
    }
    return false;
}

// TODO: Remove last '|' of flag string
bool get_strflag(bpf_u_int32 flags, char* sflag)
{
    if (flags != 0) {
        if(flags & PCAP_IF_UP) 
            strcat(sflag, "UP|");
        
        if(flags & PCAP_IF_LOOPBACK) 
            strcat(sflag, "LOOPBACK|");

        if(flags & PCAP_IF_RUNNING) 
            strcat(sflag, "RUNNING|");

        if(flags & PCAP_IF_CONNECTION_STATUS) {
            if(flags & PCAP_IF_CONNECTION_STATUS_CONNECTED)
                strcat(sflag, "CONNECTED|");
            else if(flags & PCAP_IF_CONNECTION_STATUS_DISCONNECTED)
                strcat(sflag, "DISCONNECTED|");
            else if(flags & PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE)
                strcat(sflag, "CONN_NOT_APPLICABLE|");
            else if(flags & PCAP_IF_CONNECTION_STATUS_UNKNOWN)
                strcat(sflag, "CONN_UNKNOWN|");
        }

        if(flags & PCAP_IF_WIRELESS) 
            strcat(sflag, "WIRELESS|");

        return true;
    } else
        return false;
}

void p_dev(pcap_if_t *ift)
{
    pcap_addr_t *paddr;
    char saddr[STRLEN_ADDR] = "";
    char sflag[STRLEN_FLAG] = "";

    if(ift != NULL) {
        // Print dev name, desc and flags if any 
        if(ift->name)
            printf("%s: ", ift->name); 
        if(ift->description)
            printf("%s\n", ift->description);
        if(get_strflag(ift->flags, sflag)) 
            printf("\tflags=%d<%s>\n", ift->flags, sflag);

        // Print dev addr, netmask, broad, dst addrs if any 
        for(paddr = ift->addresses; paddr; paddr = paddr->next) {
            if(get_straddr(paddr->addr,saddr) )
                printf("\taddr %s ", saddr);
            if(get_straddr(paddr->netmask, saddr) )
                printf("netmask %s ", saddr);
            if(get_straddr(paddr->broadaddr, saddr) )
                printf("broadaddr %s ", saddr);
            if(get_straddr(paddr->dstaddr, saddr) )
                printf("dstaddr %s ", saddr);
            printf("\n");
        }
    } else {
        fprintf(stderr, "Error: pcap_if_t:%p is NULL\n", ift);
    }
}

void p_alldevs()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *ift, *it;

    if(pcap_findalldevs(&ift, errbuf) == 0) {
        for(it = ift; it; it=it->next) {
            p_dev(it);
        }
        pcap_freealldevs(ift);
    } else {
        fprintf(stderr, "Error: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
}

void sigint_hndlr(int sig)
{
    // pcap_breakloop(pkt_handler);
    is_termin_cap = true;
    // printf("total captured packets: %d\n", cap_cnt);
}

void proc_pkt(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    // printf("current packet len: %d\n", h->len);
    cap_cnt++;
}

void cap_live(const char *iface)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    int ract, rloop, rstat, rnpkt;
    struct pcap_stat pstat;
    struct pcap_pkthdr *pkt_hdr;
    const u_char *pkt_data;

    if(signal(SIGINT, sigint_hndlr) == SIG_ERR) {
        fprintf(stderr, "error register signal sigint\n");
        exit(EXIT_FAILURE);
    }

    if((pkt_handler = pcap_create(iface, errbuf)) == NULL) {
        fprintf(stderr, "error pcap_create %s: %s\n", iface, errbuf);
        exit(EXIT_FAILURE);
    }

    // create handler success, need to close it at the end
    if(ract = pcap_activate(pkt_handler) != 0) {
        pcap_perror(pkt_handler, "error pcap_activate");
        goto close_handler;
    }

    if((pcap_setnonblock(pkt_handler, 1, errbuf)) != 0) {
        fprintf(stderr, "error pcap_setnonblock %s: %s\n", iface, errbuf);
        goto close_handler;
    }

    printf("start listening on interface: %s\n", iface);
    while (true) {
        if (is_termin_cap) 
            break;
        
        if ((rnpkt = pcap_next_ex(pkt_handler, &pkt_hdr, &pkt_data)) == PCAP_ERROR) {
            pcap_perror(pkt_handler, "error pcap_next_ex");
            break;
        } else if(rnpkt == 1){
            cap_cnt++;
        }
    }

    if((rstat = pcap_stats(pkt_handler, &pstat)) == 0) {
        // printf("total %u packets received - %u packets dropped - %u packets dropped by kernel\n", 
        //         pstat.ps_recv, pstat.ps_drop, pstat.ps_ifdrop);
        printf("total %u packets received - %u packets dropped - %u packets dropped by kernel\n", 
                cap_cnt, pstat.ps_drop, pstat.ps_ifdrop);
    }
    else if(rstat == PCAP_ERROR)
        pcap_perror(pkt_handler, "error pcap_stats");

close_handler:
    pcap_close(pkt_handler);
}