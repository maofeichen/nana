#ifndef _NM_PCAP_H
#define _NM_PCAP_H

#include <pcap.h>   // libpcap
#include <stdbool.h>

#define STRLEN_FLAG 128 // Maximum str length to hold dev flags 
#define STRLEN_ADDR 128 // Maximum str length to hold dev addr 

void p_alldevs();
void cap_live(const char *iface);

#endif  // _NM_PCAP_H