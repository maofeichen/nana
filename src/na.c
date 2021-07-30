#include "nm_pcap.h"
#include <getopt.h>
#include <stdlib.h> // exit, etc. 

void usage(char *n)
{
    printf("usage: %s [options]\n"
           "Options:\n"
           "--iface|-i          Capture live network traffice from iface\n"
           "--print|-p          Display network interface information\n"
           "--help|-h           Display help information\n"
           "--version|-v        Display version informaion\n", n);
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
    }

    while ((opt = getopt_long_only(argc, argv, "phvi:", longopts, &opt_index)) != -1) {
        // printf("opt_index: %d - option: %s\n", opt_index, longopts[opt_index].name);
        switch (opt)
        {
        case 'i':
            capture_live(optarg);
            break;
        case 'p':
            print_alldevs();
            break;
        case 'v':
            version();
            break;
        case 'h':
        default:
            usage(argv[0]);
            break;
        }
    }

    for(int i = optind; i < argc; i++) {
        fprintf(stderr, "%s: invalid positional argument: %s\n", argv[0], argv[i]);
    }
    exit(0);
}