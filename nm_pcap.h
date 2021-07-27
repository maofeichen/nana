#include <pcap.h>
#include <stdbool.h>

#define STRLEN_FLAG 128 // Maximum str length to hold dev flags 
#define STRLEN_ADDR 128 // Maximum str length to hold dev addr 


bool get_straddr(struct sockaddr *sa, char* saddr);
bool get_strflag(bpf_u_int32 flags, char* sflag);
void print_dev(pcap_if_t *ift);
void print_alldevs();

