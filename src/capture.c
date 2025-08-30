#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
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
        if (ip->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ether_header) + (ip->ip_hl << 2));
            printf("TCP: src_port=%d, dst_port=%d, seq=%u, flags=",
                   ntohs(tcp->th_sport), ntohs(tcp->th_dport), ntohl(tcp->th_seq));
            if (tcp->th_flags & TH_SYN) printf("SYN ");
            if (tcp->th_flags & TH_ACK) printf("ACK ");
            if (tcp->th_flags & TH_FIN) printf("FIN ");
            if (tcp->th_flags & TH_RST) printf("RST ");
            if (tcp->th_flags & TH_PUSH) printf("PSH ");
            if (tcp->th_flags & TH_URG) printf("URG ");
            printf("\n");
        } else if (ip->ip_p == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct ether_header) + (ip->ip_hl << 2));
            printf("UDP: src_port=%d, dst_port=%d\n", ntohs(udp->uh_sport), ntohs(udp->uh_dport));
        } else if (ip->ip_p == IPPROTO_ICMP) {
            struct icmp *icmp = (struct icmp *)(packet + sizeof(struct ether_header) + (ip->ip_hl << 2));
            printf("ICMP: type=%d, code=%d\n", icmp->icmp_type, icmp->icmp_code);
        }
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

void capture_packet(const char *dev, const char *filter) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return;
    }
    if (strlen(filter) > 0) {
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
            pcap_close(handle);
            return;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
            pcap_close(handle);
            return;
        }
        pcap_freecode(&fp);
    }
    printf("Capturing packets on %s with filter '%s'. Press Ctrl+C to stop.\n", dev, strlen(filter) > 0 ? filter : "none");
    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);
}