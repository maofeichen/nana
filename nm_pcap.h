#include <pcap.h>
#include <stdbool.h>

bool get_straddr(struct sockaddr *sa, char* saddr);
bool get_strflags(bpf_u_int32 flags, char* sflag);
bool print_dev(pcap_if_t *ift);
bool print_alldevs();

