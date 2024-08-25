#include "utils.h"
#include "header.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>

void print_tcp_header(tcp_header *tcph) {
    printf(
        "\nsrc: %hu, dest: %hu, seq: %u, ack: %u, wnd: %hu, check: %04x, doff: "
        "%X, res: %X, urg: %u, "
        "ack: %u, psh: %u, rst: %u, syn: %u, fin: %u\n",
        ntohs(tcph->src_port), ntohs(tcph->dest_port), ntohl(tcph->seq),
        ntohl(tcph->seq_ack), ntohs(tcph->wnd), tcph->check, tcph->doff,
        tcph->res, !!(tcph->flags & TCP_FLAG_URG),
        !!(tcph->flags & TCP_FLAG_ACK), !!(tcph->flags & TCP_FLAG_PSH),
        !!(tcph->flags & TCP_FLAG_RST), !!(tcph->flags & TCP_FLAG_SYN),
        !!(tcph->flags & TCP_FLAG_FIN));
}

void print_ip_header(ip_header *iph) {
    printf(
        "\nv: %02X, ihl: %02X, tos: %02X, len:  %04X, id:  "
        "%04X, frag:  %04X, ttl: %02X, proto: %02X, check: %04X, dest: %08X, "
        "src: %08X\n",
        iph->ver, iph->ihl, iph->tos, iph->len, iph->id, iph->frag, iph->ttl,
        iph->proto, iph->check, iph->dest_addr, iph->src_addr);

    printf("\n");

    char str[INET6_ADDRSTRLEN];
    printf("src_addr: %s\n",
           inet_ntop(AF_INET, &iph->src_addr, str, INET_ADDRSTRLEN));
    printf("dest_addr: %s\n",
           inet_ntop(AF_INET, &iph->dest_addr, str, INET_ADDRSTRLEN));
}

void print_tcp_ip_header(tcp_ip_header *piph) {
    printf("\n");
    print_hex((uint8_t *)piph, 12);
    printf("\n");
}

void print_tcp_tcb(tcp_tcb_snd *snd, tcp_tcb_rcv *rcv) {
    printf("\n snd: iss: %u, una: %u, nxt: %u, wnd: %u, up: %u, wl1: %u, wl2: "
           "%u \n rcv: irs: %u, nxt: %u, wnd: %u, up: %u \n",
           snd->iss, snd->una, snd->nxt, snd->wnd, snd->up, snd->wl1, snd->wl2,
           rcv->irs, rcv->nxt, rcv->wnd, rcv->up);
}

void print_hex(uint8_t *buffer, int count) {
    printf("\n");
    for (int i = 0; i < count; i++) {
        printf("%02X ", buffer[i]);
    }
    printf("\n");
}
