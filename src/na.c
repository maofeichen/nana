#include "na_pcap.h"
#include <getopt.h>
#include <stdlib.h> // exit, etc. 

void usage(char *n)
{
    printf("usage: %s [options]\n"
           "Options:\n"
           "-i,--iface      Capture live network traffice from iface\n"
           "-p,--print      Display network interface information\n"
           "-h,--help       Display help information\n"
           "-v,--version    Display version informaion\n", n);
}

void version()
{
    printf("na version 0.01\n");
}

int main(int argc, char *argv[])
{
    int opt, opt_index;
    static const struct option longopts[] = {
        {"iface",   required_argument, 0, 'i'},
        {"print",   no_argument, 0, 'p'},
        {"help",    no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {NULL,      0,           0, 0},
    };

    if(argc <= 1) {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    while ((opt = getopt_long(argc, argv, "phvi:", longopts, &opt_index)) != -1) {
        switch (opt)
        {
        case 'i':
            cap_live(optarg);
            break;
        case 'p':
            p_alldevs();
            break;
        case 'v':
            version();
            break;
        case 'h':
        case '?':
        default:
            usage(argv[0]);
            break;
        }
    }

    for(int i = optind; i < argc; i++) {
        fprintf(stderr, "non-option argument: %s\n", argv[i]);
    }

    exit(EXIT_SUCCESS);
}