#include "tcp.h"
#include "header.h"
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/poll.h>
#include <unistd.h>

int tcp_connect(int *read_stream, int *write_stream) {
    printf("Connect");
    int input[2];
    int output[2];
    pipe(input);
    pipe(output);
    return 0;
}

int tcp_write() {
    printf("Write");
    return 0;
}

int tcp_read() {
    printf("Read");
    return 0;
}

int tcp_disconnect() {
    printf("Disconnect");
    return 0;
}

int tcp_open(uint16_t port, uint32_t addr, uint8_t active) {
    if (!active) {
        return -1;
    }
    return 0;
}

int tcp_send() {
    printf("Send");
    return 0;
}

int tcp_receive() {
    printf("Receive");
    return 0;
}

int tcp_close() {
    printf("Close");
    return 0;
}

int tcp_abort() {
    printf("Abort");
    return 0;
}

int tcp_status() {
    printf("Status");
    return 0;
}

int tcp_loop(tcp_connection *tcb) {
    int ready;
    while (1) {
        ready = poll(tcb->rw_pipes,
                     sizeof(tcb->rw_pipes) / sizeof(struct pollfd), 10);
        if (ready == -1) {
            printf("Poll errored");
            break;
        }
        tcb->state_func(tcb);
    }
    return 0;
}

int tcp_transmit_dev(tcp_connection *tcb, uint8_t *payload, int payload_len) {
    int dev_fd = tcb->rw_pipes[TCP_FD_DEV].fd;
    uint8_t buf[4096];

    tcp_header tcph = create_tcp_header(tcb->src.port, tcb->dest.port);
    ip_header iph =
        create_ip_header(tcb->src.addr, tcb->dest.addr,
                         (tcph.doff << 2) + payload_len + IP_HEADER_SIZE);
    tcp_ip_header piph;
    piph.tcp_len = htons(ntohs(iph.len) - IP_HEADER_SIZE);
    piph.src_addr = iph.src_addr;
    piph.dest_addr = iph.dest_addr;
    piph.protocol = htons(IP_PROTO_TCP);

    tcph.check = tcp_checksum(&piph, &tcph, payload);
    int offset = from_ip_header(&iph, buf);
    offset += from_tcp_header(&tcph, buf + offset);
    memcpy(buf + offset, payload, payload_len);

    write(dev_fd, buf, offset + payload_len);
    return 0;
}

int tcp_state_closed(tcp_connection *tcb) {
    printf("Closed state");

    tcp_header tcph = create_tcp_header(tcb->src.port, tcb->dest.port);
    tcph.seq = 0;
    tcph.seq_ack = htonl(tcb->snd.nxt);
    tcph.flags |= TCP_FLAG_SYN;
    uint8_t data[0];

    tcp_transmit_dev(tcb, data, 0);

    tcb->state = TCP_SYN_SENT;
    tcb->state_func = tcp_state_syn_sent;

    return 0;
}

int tcp_state_syn_sent(tcp_connection *tcb) {
    printf("Syn sent state");

    return 0;
}

int tcp_state_established(tcp_connection *tcb) {
    printf("Established state");

    return 0;
}
