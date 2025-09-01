#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <netinet/in.h>
#include <microhttpd.h>
#include <maxminddb.h>
#include "capture.h"

extern MMDB_s mmdb;
struct MHD_Daemon *http_daemon;

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

enum MHD_Result request_handler(void *cls, struct MHD_Connection *connection,
                                const char *url, const char *method,
                                const char *version, const char *upload_data,
                                size_t *upload_data_size, void **con_cls) {
    if (strcmp(method, "GET") != 0) return MHD_NO;
    if (strcmp(url, "/") != 0) return MHD_NO;

    char response[2048];
    extern struct stats pkt_stats;
    sprintf(response,
            "<html><head><title>pktfilter Dashboard</title></head><body>"
            "<h1>pktfilter Live Stats</h1>"
            "<p>Total packets: %d</p>"
            "<p>TCP: %d</p>"
            "<p>UDP: %d</p>"
            "<p>ICMP: %d</p>"
            "<h2>Top Source IPs</h2><ul>",
            pkt_stats.total, pkt_stats.tcp, pkt_stats.udp, pkt_stats.icmp);
    for (int i = 0; i < pkt_stats.num_sources; i++) {
        char temp[256];
        sprintf(temp, "<li>%s: %d</li>", pkt_stats.top_sources[i].ip, pkt_stats.top_sources[i].count);
        strcat(response, temp);
    }
    strcat(response, "</ul></body></html>");

    struct MHD_Response *mhd_response = MHD_create_response_from_buffer(strlen(response), response, MHD_RESPMEM_MUST_COPY);
    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, mhd_response);
    MHD_destroy_response(mhd_response);
    return ret;
}

int main() {
    signal(SIGINT, sig_handler);
    printf("pktfilter: Hello world\n");
    if (MMDB_open("GeoLite2-Country.mmdb", MMDB_MODE_MMAP, &mmdb) != MMDB_SUCCESS) {
        fprintf(stderr, "GeoIP database not found. Download from MaxMind and place as GeoLite2-Country.mmdb\n");
    }
    http_daemon = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION | MHD_USE_SELECT_INTERNALLY, 8080, NULL, NULL,
                              &request_handler, NULL, MHD_OPTION_END);
    if (http_daemon == NULL) {
        fprintf(stderr, "Failed to start HTTP server\n");
        return 1;
    }
    printf("Web dashboard available at http://localhost:8080\n");
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
    MHD_stop_daemon(http_daemon);
    return 0;
}