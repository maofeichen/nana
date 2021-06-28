#include <pcap.h>
#include <stdbool.h>

#define FLAG_STRLEN 128 /* Maximum str length to hold dev flags */

bool get_straddr(struct sockaddr *sa, char* saddr);
bool get_strflags(bpf_u_int32 flags, char* sflag);
void print_dev(pcap_if_t *ift);
void print_alldevs();

