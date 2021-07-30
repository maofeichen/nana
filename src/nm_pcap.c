#include "nm_pcap.h"
#include <signal.h>
#include <stdlib.h> // exit, etc 
#include <string.h> // strcat 

// external variables
pcap_t *pkt_hdr;    // packet handler: accessible in a signal handler function
int cap_cnt;        // number of captured packets 

// prototypes
bool get_straddr(struct sockaddr *sa, char* saddr);
bool get_strflag(bpf_u_int32 flags, char* sflag);
void print_dev(pcap_if_t *ift);

void sigint_handler(int sig);
void parse_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

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

void print_dev(pcap_if_t *ift)
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
        exit(EXIT_FAILURE);
    }
}

void sigint_handler(int sig)
{
    printf("Caught SIGINT\n");
    pcap_breakloop(pkt_hdr);
    printf("total %d packet had been captured\n", cap_cnt);
    // exit(EXIT_SUCCESS);
}

void parse_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    printf("current packet len: %d\n", h->len);
    cap_cnt++;
}

void capture_live(const char *iface)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    int ra, rl;

    if((pkt_hdr = pcap_create(iface, errbuf)) != NULL) {
        if((ra = pcap_activate(pkt_hdr)) == 0) {
            if(signal(SIGINT, sigint_handler) != SIG_ERR) {
                rl = pcap_loop(pkt_hdr, -1, parse_packet, NULL);
                if (rl == PCAP_ERROR)
                    fprintf(stderr, "%s", pcap_geterr(pkt_hdr));
                else if (rl == PCAP_ERROR_BREAK)
                    printf("live capture terminateed by break\n");
            }
        } else {
            pcap_perror(pkt_hdr, "error pcap_activate");
        }
        pcap_close(pkt_hdr);
    } else {
        fprintf(stderr, "error pcap_create %s: %s\n", iface, errbuf);
        exit(EXIT_FAILURE);
    }
}