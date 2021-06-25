#include "nm.h"

void 
usage(char *n)
{
    printf("Usage: %s [options]\n"
           "Options:\n"
           "--print|-p          Display network interface information\n"
           "--help|-h           Display help information\n"
           "--version|-v        Display version informaion\n", n);
}

int 
main(int argc, char *argv[])
{
    int opt, opt_index;
    static const struct option longopts[] = {
        {"print",   no_argument, 0, 'p'},
        {"help",    no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {NULL,      0,           0, 0},
    };

    while ((opt = getopt_long_only(argc, argv, "phv", longopts, &opt_index)) != -1) {
        printf("opt_index: %d - option: %s\n", opt_index, longopts[opt_index].name);
        switch (opt)
        {
        case 'p':
            print_alldevs();
            break;
        case 'v':
            printf("nm version 0.01\n");
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

    return 0;
}