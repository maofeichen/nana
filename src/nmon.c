#include <getopt.h>
#include <stdlib.h> // exit, etc. 

#include "nm_pcap.h"
#include "nmon.h"

void usage(char *nm)
{
    printf("usage: %s [options]\n"
           "Options:\n"
           "-i,--iface      Capture live network traffic from iface\n"
           "-d,--display    Display network interface information\n"
           "-h,--help       Display help information\n"
           "-v,--version    Display version informaion\n", nm);
}

void version(char *nm)
{
    printf("%s version 0.01\n", nm);
}

int main(int argc, char *argv[])
{
    int opt, opt_index;
    static const struct option longopts[] = {
        {"iface",   required_argument, 0, 'i'},
        {"display", no_argument, 0, 'd'},
        {"help",    no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {NULL,      0,           0, 0},
    };

    if(argc <= 1) {
        usage(PROG_NAME);
        exit(EXIT_FAILURE);
    }

    while ((opt = getopt_long(argc, argv, "dhvi:", longopts, &opt_index)) != -1) {
        switch (opt)
        {
        case 'i':
            cap_live(optarg);
            break;
        case 'd':
            p_alldevs();
            break;
        case 'v':
            version(PROG_NAME);
            break;
        case 'h':
        case '?':
        default:
            usage(PROG_NAME);
            break;
        }
    }

    for(int i = optind; i < argc; i++) {
        fprintf(stderr, "non-option argument: %s\n", argv[i]);
    }

    exit(EXIT_SUCCESS);
}