#ifndef _NA_PCAP_H
#define _NA_PCAP_H

#include <pcap.h>   // libpcap
#include <stdbool.h>

#define STRLEN_FLAG 128 // Maximum str length to hold dev flags 
#define STRLEN_ADDR 128 // Maximum str length to hold dev addr 

void p_alldevs();
void cap_live(const char *iface);

#endif