#include "helper.h"
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
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
static const char pkt_data[] =
    "\x3c\xfd\xfe\x9e\x7f\x71\xec\xb1\xd7\x98\x3a\xc0\x08\x00\x45\x00"
    "\x00\x2e\x00\x00\x00\x00\x40\x11\x88\x97\x05\x08\x07\x08\xc8\x14"
    "\x1e\x04\x10\x92\x10\x92\x00\x1a\x6d\xa3\x34\x33\x1f\x69\x40\x6b"
    "\x54\x59\xb6\x14\x2d\x11\x44\xbf\xaf\xd9\xbe\xaa";

int main(int argc, char **argv) {
  int sender = 0;
  if (argc > 0) {
    sender = atoi(argv[1]);
  }

  int tap_fd;
  char tun_name[IFNAMSIZ];
  char buffer[4096];
  int nwrite;
  unsigned long x = 0;
  strcpy(tun_name, "tap0");
  tap_fd = tun_alloc(tun_name, IFF_TAP | IFF_MULTI_QUEUE | IFF_NAPI);
  if (tap_fd < 0) {
    perror("Allocating interface");
    exit(1);
  }

  if (sender) {
    printf("Sender\n");
  } else {
    printf("Receiver\n");
  }

  if (sender > 0) {
    while (1) {
      nwrite = write(tap_fd, pkt_data, sizeof(pkt_data));
      if (nwrite < 0) {
        perror("writing data");
      }
      printf("Write %d bytes\n", nwrite);
      sleep(1);
    }
  } else {
    while (1) {
      int nread = read(tap_fd, buffer, sizeof(buffer));
      if (nread < 0) {
        perror("Reading from interface");
        close(tap_fd);
        exit(1);
      }

      /* Do whatever with the data */
      if ((x++ % 1000) == 0)
        printf("Read %d bytes from device %s\n", nread, tun_name);
    }
  }

  return 0;
}
