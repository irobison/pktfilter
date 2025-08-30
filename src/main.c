#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <maxminddb.h>
#include "capture.h"

extern MMDB_s mmdb;

int main() {
    signal(SIGINT, sig_handler);
    printf("pktfilter: Hello world\n");
    if (MMDB_open("GeoLite2-Country.mmdb", MMDB_MODE_MMAP, &mmdb) != MMDB_SUCCESS) {
        fprintf(stderr, "GeoIP database not found. Download from MaxMind and place as GeoLite2-Country.mmdb\n");
    }
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