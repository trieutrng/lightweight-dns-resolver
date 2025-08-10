#include <stdio.h>
#include <stdlib.h>

#include "dns_resolver.h"

int main(int argc, char *args[]) {
    if (argc < 3) {
        printhelp();
        exit(-1);
    }

    struct Query query;
    int rs = getqueryinfo(argc, args, &query);

    if (rs != 0) {
        printhelp();
        exit(-1);
    }
    
    return 0;
}