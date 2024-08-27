#include "utils.h"
#include "header.h"
#include "tcp.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>

void print_tcp_header(tcp_header *tcph) {
    printf(
        "\nsrc: %hu, dest: %hu, seq: %u, ack: %u, wnd: %hu, check: %04x, doff: "
        "%X, res: %X, urg: %u, "
        "ack: %u, psh: %u, rst: %u, syn: %u, fin: %u\n",
        tcph->src_port, tcph->dest_port, tcph->seq, tcph->seq_ack, tcph->wnd,
        tcph->check, tcph->doff, tcph->res, !!(tcph->flags & TCP_FLAG_URG),
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
    uint32_t src_addr = htonl(iph->src_addr);
    uint32_t dest_addr = htonl(iph->dest_addr);
    printf("src_addr: %s\n",
           inet_ntop(AF_INET, &src_addr, str, INET_ADDRSTRLEN));
    printf("dest_addr: %s\n",
           inet_ntop(AF_INET, &dest_addr, str, INET_ADDRSTRLEN));
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

void print_tcp_event_type(enum tcp_event_type type) {
    switch (type) {
    case TCP_EVENT_OPEN:
        printf("event type: %s", "TCP_EVENT_OPEN\n");
        break;
    case TCP_EVENT_SEND:
        printf("event type: %s", "TCP_EVENT_SEND\n");
        break;
    case TCP_EVENT_RECEIVE:
        printf("event type: %s", "TCP_EVENT_RECEIVE\n");
        break;
    case TCP_EVENT_CLOSE:
        printf("event type: %s", "TCP_EVENT_CLOSE\n");
        break;
    case TCP_EVENT_ABORT:
        printf("event type: %s", "TCP_EVENT_ABORT\n");
        break;
    case TCP_EVENT_STATUS:
        printf("event type: %s", "TCP_EVENT_STATUS\n");
        break;
    case TCP_EVENT_SEGMENT_ARRIVES:
        printf("event type: %s", "TCP_EVENT_SEGMENT_ARRIVES\n");
        break;
    case TCP_EVENT_USER_TIMEOUT:
        printf("event type: %s", "TCP_EVENT_USER_TIMEOUT\n");
        break;
    case TCP_EVENT_RETRANSMISSION_TIMEOUT:
        printf("event type: %s", "TCP_EVENT_RETRANSMISSION_TIMEOUT\n");
        break;
    case TCP_EVENT_TIME_WAIT_TIMEOUT:
        printf("event type: %s", "TCP_EVENT_TIME_WAIT_TIMEOUT\n");
        break;
    }
}

void print_hex(uint8_t *buffer, int count) {
    printf("\n");
    for (int i = 0; i < count; i++) {
        printf("%02X ", buffer[i]);
    }
    printf("\n");
}
