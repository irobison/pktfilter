#include <stdio.h>
#include "capture.h"

int main(int argc, char *argv[]) {
    const char *interface = (argc > 1) ? argv[1] : "en0";
    printf("pktfilter: Hello world\n");
    capture_packet(interface);
    return 0;
}