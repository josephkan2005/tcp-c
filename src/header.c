#include "header.h"
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int tcp_read_options(tcp_header *header, uint8_t *buffer) {
    int opt_len = (header->doff << 2) - TCP_HEADER_SIZE;

    int nbytes = 0;
    int written = 0;
    while (nbytes < opt_len) {
        uint8_t opt_kind = buffer[nbytes];
        nbytes++;
        switch (opt_kind) {
        case TCP_MSS:
            memcpy(header->opts + written, buffer + nbytes - 1, 4);
            written += 4;

            nbytes += buffer[nbytes];
            break;
        case TCP_EOL:
        case TCP_NOOP:
            break;
        default:
            printf("Option not supported");
            nbytes += buffer[nbytes] - 1;
            break;
        }
    }

    return opt_len;
}

int tcp_write_options(tcp_header *header, uint8_t *buffer) {
    int opt_len = (header->doff << 2) - TCP_HEADER_SIZE;

    memcpy(header->opts, buffer, opt_len);

    return 0;
}

tcp_header create_tcp_header(uint16_t src_port, uint16_t dest_port) {
    tcp_header tcph;
    tcph.src_port = src_port;
    tcph.dest_port = dest_port;

    tcph.seq = 0;

    tcph.seq_ack = 0;

    tcph.doff = 5;
    tcph.res = 0;
    tcph.flags = 0;
    tcph.wnd = htons(10);

    tcph.check = 0;
    tcph.urg_ptr = 0;

    return tcph;
}

int to_tcp_header(tcp_header *header, uint8_t *buffer) {
    memcpy(header, buffer, sizeof(tcp_header));
    tcp_read_options(header, buffer + TCP_HEADER_SIZE);

    return 0;
}

int from_tcp_header(tcp_header *header, uint8_t *buffer) {
    memcpy(buffer, header, header->doff << 2);

    return sizeof(tcp_header);
}

ip_header create_ip_header(uint32_t src_addr, uint32_t dest_addr,
                           uint16_t data_len) {
    ip_header iph;

    iph.ver = 4;
    iph.ihl = 5;
    iph.tos = 0;
    iph.len = htons(data_len);
    iph.id = 0;
    iph.frag = 0;
    iph.ttl = 10;
    iph.proto = 6;
    iph.check = 0;
    iph.src_addr = src_addr;
    iph.dest_addr = dest_addr;

    return iph;
}

int to_ip_header(ip_header *header, uint8_t *buffer) {
    // *header = *(ip_header *)buffer;
    memcpy(header, buffer, IP_HEADER_SIZE);
    return 0;
}

int from_ip_header(ip_header *header, uint8_t *buffer) {
    header->check = ip_checksum(header);
    header->check = htons(header->check);

    memcpy(buffer, header, sizeof(ip_header));

    return sizeof(ip_header);
}

uint16_t checksum(uint16_t *payload, uint32_t count, uint32_t start) {
    uint32_t sum = start;
    while (count > 1) {
        sum += *payload++;
        count -= 2;
    }

    if (count > 0) {
        sum += (*payload) & htons(0xFF00);
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

// 45 00 00 3C 0F C7 40 00 40 06 A9 A0 C0 A8 00 01 C0 A8 00 03 BF E4 1F 40 B6 93
// F1 F2 00 00 00 00 A0 02 FA F0 3E 8F 00 00 02 04 05 B4 04 02 08 0A 03 87 01 F9
// 00 00 00 00 01 03 03 07 45 00 00 3C 0F C8 40 00 40 06 A9 9F C0 A8 00 01 C0 A8
// 00 03 BF E4 1F 40 B6 93 F1 F2 00 00 00 00 A0 02 FA F0 3A 80 00 00 02 04 05 B4
// 04 02 08 0A 03 87 06 08 00 00 00 00 01 03 03 07

int tcp_checksum(tcp_ip_header *iph, tcp_header *tcph, uint8_t *payload) {
    tcph->check = 0;

    uint8_t tcp_len = iph->tcp_len;

    uint32_t sum = 0;

    sum += iph->src_addr;
    sum += iph->dest_addr;
    sum += htonl(IPPROTO_TCP);
    sum += tcp_len;

    int opt_len = tcph->doff - (TCP_HEADER_SIZE >> 2);
    for (int i = 0; i < opt_len; i++) {
        sum += *(((uint32_t *)tcph->opts) + i);
    }

    uint8_t data_len = tcp_len - (tcph->doff << 2);

    tcph->check = checksum((uint16_t *)payload, data_len, sum);
    return 0;
}

int ip_checksum(ip_header *iph) {
    iph->check = 0;
    iph->check = checksum((uint16_t *)iph, iph->ihl << 2, 0);
    return 0;
}
