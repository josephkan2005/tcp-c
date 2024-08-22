#include "header.h"
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
    uint8_t buffer[4096];
    int nwrite;
    unsigned long x = 0;
    strcpy(tun_name, "tun0");
    tun_fd = tun_alloc(tun_name, IFF_TUN | IFF_NO_PI);
    if (tun_fd < 0) {
        perror("Allocating interface");
        exit(1);
    }

    if (sender > 0) {
        while (1) {
            char data[2] = {'0', '1'};
            nwrite = write(tun_fd, data, sizeof(data));
            if (nwrite < 0) {
                perror("writing data");
            }
            printf("Write %d bytes\n", nwrite);
            sleep(1);
        }
    } else {
        while (1) {
            int nread = read(tun_fd, buffer, sizeof(buffer));
            printf("nread: %d\n", nread);
            if (nread < 0) {
                perror("Reading from interface");
                close(tun_fd);
                exit(1);
            }

            for (int i = 0; i < nread; i++) {
                printf("%02X", buffer[i]);
            }

            printf("\n");

            ip_header iph;

            to_ip_header(&iph, &buffer);

            printf("size: %lu, ipsz: %lu, %lx\n", sizeof(uint32_t),
                   sizeof(ip_header), iph.src_addr);

            printf("v: %02X, ihl: %02X, tos: %02X, len:  %02X, id:  "
                   "%02X, frag:  %02X, ttl: %02X, proto: %02X, dest: %02X, "
                   "src: %02X\n",
                   iph.ver, iph.ihl, iph.tos, iph.len, iph.id, iph.frag,
                   iph.ttl, iph.proto, iph.dest_addr, iph.src_addr);

            char str[INET6_ADDRSTRLEN];

            printf("\n");

            uint32_t converted = htonl(iph.src_addr);

            printf("%s", inet_ntop(AF_INET, &converted, str, INET_ADDRSTRLEN));

            printf("\n");
        }
    }

    return 0;
}
