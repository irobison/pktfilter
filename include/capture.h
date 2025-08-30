#ifndef CAPTURE_H
#define CAPTURE_H

void list_interfaces();
void capture_packet(const char *interface, const char *filter);

#endif