#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include "capture.h"

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    printf("Packet length: %d\n", header->len);
}

void list_interfaces() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return;
    }
    printf("Available interfaces:\n");
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        printf("%s: %s\n", d->name, d->description ? d->description : "No description");
    }
    pcap_freealldevs(alldevs);
}

void capture_packet() {
    const char *dev = "en0";  // Specific interface
    char errbuf[PCAP_ERRBUF_SIZE];
    list_interfaces();
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return;
    }
    printf("Capturing packets on %s. Press Ctrl+C to stop.\n", dev);
    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);
}