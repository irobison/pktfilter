#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <maxminddb.h>
#include <microhttpd.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include "capture.h"

#define RESET "\033[0m"
#define GREEN "\033[32m"
#define BLUE "\033[34m"
#define RED "\033[31m"
#define YELLOW "\033[33m"

MMDB_s mmdb;
extern struct MHD_Daemon *http_daemon;

struct source {
    char ip[INET_ADDRSTRLEN];
    int count;
};

struct stats {
    int total;
    int tcp;
    int udp;
    int icmp;
    struct source top_sources[10];
    int num_sources;
};

struct stats pkt_stats = {0};

void add_source(const char *ip) {
    for (int i = 0; i < pkt_stats.num_sources; i++) {
        if (strcmp(pkt_stats.top_sources[i].ip, ip) == 0) {
            pkt_stats.top_sources[i].count++;
            return;
        }
    }
    if (pkt_stats.num_sources < 10) {
        strcpy(pkt_stats.top_sources[pkt_stats.num_sources].ip, ip);
        pkt_stats.top_sources[pkt_stats.num_sources].count = 1;
        pkt_stats.num_sources++;
    }
}

void print_stats() {
    printf("\n--- Packet Statistics ---\n");
    printf("Total packets: %d\n", pkt_stats.total);
    printf("TCP: %d\n", pkt_stats.tcp);
    printf("UDP: %d\n", pkt_stats.udp);
    printf("ICMP: %d\n", pkt_stats.icmp);
    printf("Top source IPs:\n");
    for (int i = 0; i < pkt_stats.num_sources; i++) {
        printf("  %s: %d\n", pkt_stats.top_sources[i].ip, pkt_stats.top_sources[i].count);
    }
}

volatile sig_atomic_t stop = 0;

void sig_handler(int sig) {
    stop = 1;
    print_stats();
    MMDB_close(&mmdb);
    if (http_daemon) MHD_stop_daemon(http_daemon);
    exit(0);
}

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    pkt_stats.total++;
    time_t now = time(NULL);
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%H:%M:%S", localtime(&now));
    struct ether_header *eth = (struct ether_header *)packet;
    char eth_src[18], eth_dst[18];
    sprintf(eth_src, "%02x:%02x:%02x:%02x:%02x:%02x",
            eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
            eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    sprintf(eth_dst, "%02x:%02x:%02x:%02x:%02x:%02x",
            eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
            eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    printf("%-12s | %s%-10s%s | %-23s | %-23s | %-32s\n", timestamp, GREEN, "Ethernet", RESET, eth_src, eth_dst, "");
    if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
        struct ip *ip = (struct ip *)(packet + sizeof(struct ether_header));
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip->ip_dst), dst_ip, INET_ADDRSTRLEN);
        char proto_details[33];
        sprintf(proto_details, "proto=%d", ip->ip_p);
        printf("%-12s | %s%-10s%s | %-23s | %-23s | %-32s\n", timestamp, BLUE, "IPv4", RESET, src_ip, dst_ip, proto_details);
        // GeoIP lookup
        int gai_error, mmdb_error;
        MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, src_ip, &gai_error, &mmdb_error);
        if (MMDB_SUCCESS == mmdb_error && result.found_entry) {
            MMDB_entry_data_s entry_data;
            int status = MMDB_get_value(&result.entry, &entry_data, "country", "iso_code", NULL);
            if (MMDB_SUCCESS == status && entry_data.has_data) {
                char country_code[3];
                snprintf(country_code, sizeof(country_code), "%.*s", entry_data.data_size, entry_data.utf8_string);
                char country_details[33];
                sprintf(country_details, "Country: %s", country_code);
                printf("%-12s | %s%-10s%s | %-23s | %-23s | %-32s\n", timestamp, YELLOW, "Country", RESET, "", "", country_details);
            }
        }
        add_source(src_ip);
        if (ip->ip_p == IPPROTO_TCP) {
            pkt_stats.tcp++;
            struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ether_header) + (ip->ip_hl << 2));
            char flags[20] = "";
            if (tcp->th_flags & TH_SYN) strcat(flags, "SYN ");
            if (tcp->th_flags & TH_ACK) strcat(flags, "ACK ");
            if (tcp->th_flags & TH_FIN) strcat(flags, "FIN ");
            if (tcp->th_flags & TH_RST) strcat(flags, "RST ");
            if (tcp->th_flags & TH_PUSH) strcat(flags, "PSH ");
            if (tcp->th_flags & TH_URG) strcat(flags, "URG ");
            char src_str[26], dst_str[26];
            sprintf(src_str, "%s:%d", src_ip, ntohs(tcp->th_sport));
            sprintf(dst_str, "%s:%d", dst_ip, ntohs(tcp->th_dport));
            char tcp_details[33];
            sprintf(tcp_details, "seq=%u, flags=%s", ntohl(tcp->th_seq), flags);
            printf("%-12s | %s%-10s%s | %-23s | %-23s | %-32s\n", timestamp, BLUE, "TCP", RESET, src_str, dst_str, tcp_details);
        } else if (ip->ip_p == IPPROTO_UDP) {
            pkt_stats.udp++;
            struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct ether_header) + (ip->ip_hl << 2));
            char src_str[26], dst_str[26];
            sprintf(src_str, "%s:%d", src_ip, ntohs(udp->uh_sport));
            sprintf(dst_str, "%s:%d", dst_ip, ntohs(udp->uh_dport));
            printf("%-12s | %s%-10s%s | %-23s | %-23s | %-32s\n", timestamp, BLUE, "UDP", RESET, src_str, dst_str, "");
        } else if (ip->ip_p == IPPROTO_ICMP) {
            pkt_stats.icmp++;
            struct icmp *icmp = (struct icmp *)(packet + sizeof(struct ether_header) + (ip->ip_hl << 2));
            char icmp_details[33];
            sprintf(icmp_details, "type=%d, code=%d", icmp->icmp_type, icmp->icmp_code);
            printf("%-12s | %s%-10s%s | %-23s | %-23s | %-32s\n", timestamp, RED, "ICMP", RESET, src_ip, dst_ip, icmp_details);
        }
    }
    char length_details[33];
    sprintf(length_details, "Length: %d bytes", header->len);
    printf("%-12s | %-10s | %-23s | %-23s | %-32s\n", timestamp, "Packet", "", "", length_details);
    printf("------------|------------|-------------------------|-------------------------|----------------------------------\n");
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
    printf("%-12s | %-10s | %-23s | %-23s | %-32s\n", "Timestamp", "Protocol", "Source", "Destination", "Details");
    printf("------------|------------|-------------------------|-------------------------|----------------------------------\n");
    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);
}