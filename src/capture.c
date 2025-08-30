#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include "capture.h"

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth = (struct ether_header *)packet;
    printf("Ethernet: src=%02x:%02x:%02x:%02x:%02x:%02x, dst=%02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5],
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
        struct ip *ip = (struct ip *)(packet + sizeof(struct ether_header));
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip->ip_dst), dst_ip, INET_ADDRSTRLEN);
        printf("IPv4: src=%s, dst=%s, proto=%d\n", src_ip, dst_ip, ip->ip_p);
    }
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