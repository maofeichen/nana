#include <getopt.h>

void usage(char *n)
{
    printf("usage: %s -p\n", n);
}

int main(int argc, char *argv[])
{
    static const struct option longopts[] = {
        {.name = "print", .has_arg = no_argument, .val = 'p'},
        {.name = "help", .has_arg = no_argument, .val = 'h'},
        {},
    };

    // opterr = 0;
    for (;;) {
        int opt = getopt_long(argc, argv, "ph", longopts, NULL);
        if (opt == -1)
            break;
        switch (opt)
        {
        case 'p':
            print_alldevs();
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