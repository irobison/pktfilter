#include <stdio.h>
#include <string.h>
#include <signal.h>
#include "capture.h"

int main() {
    signal(SIGINT, sig_handler);
    printf("pktfilter: Hello world\n");
    list_interfaces();
    char interface[256];
    printf("Enter interface name: ");
    fgets(interface, sizeof(interface), stdin);
    interface[strcspn(interface, "\n")] = 0;
    char filter[256] = "";
    printf("Enter BPF filter (or press enter for none): ");
    fgets(filter, sizeof(filter), stdin);
    filter[strcspn(filter, "\n")] = 0;
    capture_packet(interface, filter);
    return 0;
}