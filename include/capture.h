#ifndef CAPTURE_H
#define CAPTURE_H

void sig_handler(int sig);
void list_interfaces();
void capture_packet(const char *interface, const char *filter);

#endif