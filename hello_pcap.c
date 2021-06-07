#include <pcap.h>
#include <stdio.h>

int main()
{
    char errBuf[PCAP_ERRBUF_SIZE], *dev;
    pcap_if_t *it;
    int ret;

    // dev = pcap_lookupdev(errBuf);
    ret = pcap_findalldevs(&it, errBuf);
    if(ret == -1) {
        printf("error:%s\n", errBuf);
        exit(-1);
    }
    while (it) {
        printf(":%s - %s\n", it->name, it->description);
        printf("%s\n", iptos(it->addresses->addr));
        it = it->next;
    }
    
    // if(dev){
    //     printf("success: device: %s\n", dev);
    // }
    // else {
    //     printf("error: %s\n", errBuf);
    // }

    return 0;
}