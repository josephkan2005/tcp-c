#include "tcp.h"
#include "utils.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int tun_alloc(char *dev, int flags) {
    struct ifreq ifr;
    int fd, err;
    char *clonedev = "/dev/net/tun";
    if ((fd = open(clonedev, O_RDWR)) < 0) {
        perror("Opening /dev/net/tun");
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = flags;

    if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr))) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return err;
    }

    strcpy(dev, ifr.ifr_name);

    return fd;
}

int main(int argc, char **argv) {
    int sender = 0;
    if (argc > 0) {
        sender = atoi(argv[1]);
    }

    int tun_fd;
    char tun_name[IFNAMSIZ];
    strcpy(tun_name, "tun0");
    tun_fd = tun_alloc(tun_name, IFF_TUN | IFF_NO_PI);
    if (tun_fd < 0) {
        perror("Allocating interface");
        _exit(1);
    }

    printf("TUN TAP FD: %d\n", tun_fd);

    sleep(5);

    printf("Sending\n");

    tcp_connection connection;
    endpoint src, dest;
    src = create_endpoint(0xc0a80003, 8000);
    dest = create_endpoint(0xc0a80001, 9001);
    tcp_connect(&connection, src, dest, tun_fd);

    /* uint32_t buf = 0x00110011;
    tcp_write(&connection, (uint8_t *)&buf, 4); */

    while (1) {
        /* int nread = read(tun_fd, buffer, sizeof(buffer));
        if (nread < 0) {
            perror("Reading from interface");
            close(tun_fd);
            exit(1);
        }

        ip_header iph;

        to_ip_header(&iph, buffer);

        if (iph.ver != 4)
            continue;

        printf("\n");

        printf("nread: %d\n", nread);

        print_hex(buffer, nread);

        tcp_header tcph;

        to_tcp_header(&tcph, buffer + (iph.ihl << 2));

        uint8_t buf[4096];

        uint32_t temp = iph.src_addr;
        iph.src_addr = iph.dest_addr;
        iph.dest_addr = temp;
        iph.len = htons(IP_HEADER_SIZE + TCP_HEADER_SIZE);

        uint8_t empty[0];

        tcp_ip_header piph;
        piph.dest_addr = iph.dest_addr;
        piph.src_addr = iph.src_addr;
        piph.protocol = htons((uint16_t)IP_PROTO_TCP);
        piph.tcp_len = htons(20);

        uint16_t temp1 = tcph.src_port;
        tcph.src_port = tcph.dest_port;
        tcph.dest_port = temp1;
        tcph.seq_ack = htonl(ntohl(tcph.seq) + 1);
        tcph.wnd = htons((uint16_t)1024);
        tcph.seq = 0;
        tcph.flags |= TCP_FLAG_ACK;
        tcph.doff = 5;
        tcp_checksum(&piph, &tcph, empty);

        from_ip_header(&iph, buf);
        from_tcp_header(&tcph, buf + IP_HEADER_SIZE);

        printf("\n");*/
    }

    return 0;
}
