#include "header.h"
#include <stdint.h>

void print_tcp_header(tcp_header *tcph);

void print_ip_header(ip_header *iph);

void print_hex(uint8_t *buf, int count);
