#include <getopt.h>
#include <stdlib.h> // exit, etc. 

#include "nm_pcap.h"
#include "nmon.h"

void usage(char *n)
{
    printf("usage: %s [options]\n"
           "Options:\n"
           "-i,--iface      Capture live network traffice from iface\n"
           "-s,--show       Display network interface information\n"
           "-h,--help       Display help information\n"
           "-v,--version    Display version informaion\n", n);
}

void version(char *n)
{
    printf("%s version 0.01\n", n);
}

int main(int argc, char *argv[])
{
    int opt, opt_index;
    static const struct option longopts[] = {
        {"iface",   required_argument, 0, 'i'},
        {"shwo",    no_argument, 0, 's'},
        {"help",    no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {NULL,      0,           0, 0},
    };

    if(argc <= 1) {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    while ((opt = getopt_long(argc, argv, "shvi:", longopts, &opt_index)) != -1) {
        switch (opt)
        {
        case 'i':
            cap_live(optarg);
            break;
        case 's':
            p_alldevs();
            break;
        case 'v':
            version(PROG_NAME);
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