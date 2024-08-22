#include "utils.h"
#include "header.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>

void print_tcp_header(tcp_header *tcph) {
    printf("\nsrc: %hu, dest: %hu, seq: %u, ack: %u, wnd: %hu, doff: "
           "%X, res: %X, urg: %u, "
           "ack: %u, psh: %u, rst: %u, syn: %u, fin: %u\n",
           tcph->src_port, tcph->dest_port, tcph->seq, tcph->seq_ack, tcph->wnd,
           tcph->doff, tcph->res, !!(tcph->flags & TCP_URG),
           !!(tcph->flags & TCP_ACK), !!(tcph->flags & TCP_PSH),
           !!(tcph->flags & TCP_RST), !!(tcph->flags & TCP_SYN),
           !!(tcph->flags & TCP_FIN));
}

void print_ip_header(ip_header *iph) {
    printf("\nv: %02X, ihl: %02X, tos: %02X, len:  %02X, id:  "
           "%02X, frag:  %02X, ttl: %02X, proto: %02X, dest: %02X, "
           "src: %02X\n",
           iph->ver, iph->ihl, iph->tos, iph->len, iph->id, iph->frag, iph->ttl,
           iph->proto, iph->dest_addr, iph->src_addr);

    printf("\n");

    char str[INET6_ADDRSTRLEN];
    uint32_t converted = htonl(iph->src_addr);

    printf("src_addr: %s\n",
           inet_ntop(AF_INET, &converted, str, INET_ADDRSTRLEN));
    converted = htonl(iph->dest_addr);
    printf("dest_addr: %s\n",
           inet_ntop(AF_INET, &converted, str, INET_ADDRSTRLEN));
}

void print_hex(uint8_t *buffer, int count) {
    printf("\n");
    for (int i = 0; i < count; i++) {
        printf("%02X ", buffer[i]);
    }
    printf("\n");
}
