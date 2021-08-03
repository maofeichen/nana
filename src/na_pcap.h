#include <pcap.h>
#include <stdbool.h>

#define STRLEN_FLAG 128 // Maximum str length to hold dev flags 
#define STRLEN_ADDR 128 // Maximum str length to hold dev addr 

void print_alldevs();
void capture_live(const char *iface);