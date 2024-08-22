#include "header.h"
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>

int to_tcp_header(tcp_header *header, uint8_t *buffer) {
    *header = *(tcp_header *)buffer;
    header->src_port = ntohs(header->src_port);
    header->dest_port = ntohs(header->dest_port);
    header->seq = ntohl(header->seq);
    header->seq_ack = ntohl(header->seq_ack);

    header->wnd = ntohs(header->wnd);
    header->check = ntohs(header->check);
    header->urg_ptr = ntohs(header->urg_ptr);

    return 0;
}

int from_tcp_header(tcp_header *header, uint8_t *buffer) {
    tcp_header temp = *header;
    temp.src_port = htons(header->src_port);
    temp.dest_port = htons(header->dest_port);
    temp.seq = htonl(header->seq);
    temp.seq_ack = htonl(header->seq_ack);

    temp.wnd = htons(header->wnd);
    temp.check = htons(header->check);
    temp.urg_ptr = htons(header->urg_ptr);

    memcpy(buffer, &temp, sizeof(tcp_header));

    return 0;
}

uint16_t checksum(uint16_t *payload, uint32_t count, uint32_t start) {
    uint32_t sum = start;
    while (count > 1) {
        sum += *payload++;
        count -= 2;
    }

    if (count > 0) {
        sum += *(uint8_t *)(payload);
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

int tcp_checksum(tcp_ip_header *iph, tcp_header *tcph, uint8_t *payload) {
    tcph->check = 0;

    uint8_t tcp_len = iph->tcp_len;

    uint32_t sum = 0;

    sum += iph->src_addr;
    sum += iph->dest_addr;
    sum += (uint32_t)IPPROTO_TCP;
    sum += (uint32_t)iph->tcp_len;

    uint8_t data_len = tcp_len - (tcph->doff << 2);

    tcph->check = checksum((uint16_t *)payload, data_len, sum);
    return 0;
}

int ip_checksum(tcp_ip_header *iph, uint8_t *payload) {
    uint32_t checksum = 0;
    return 0;
}
