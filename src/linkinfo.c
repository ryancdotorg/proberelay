/* SPDX-License-Identifier: BSD-3-Clause
Copyright ©2023 Ryan Castellucci, some rights reserved.
gcc -O2 -std=c11 -Wall -Wextra -pedantic proberelay.c -lpcap -o proberelay #*/

// asprintf
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <netdb.h>

#include <grp.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <net/if.h>
#include <net/ethernet.h>

#include <arpa/inet.h>

#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

static int init_ifreq(struct ifreq *ifr, const char *ifname) {
  size_t ifname_len = strlen(ifname);
  if (ifname_len < sizeof(ifr->ifr_name)) {
    memcpy(ifr->ifr_name, ifname, ifname_len);
    ifr->ifr_name[ifname_len] = 0;
    return 0;
  } else {
    return -1;
  }
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s IFNAME\n", argv[0]);
    return -1;
  }

  char *ifname = argv[1];

  int fd;
  if ((fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
    perror("socket");
    return -1;
  }

  struct ifreq ifr = {0};
  if (init_ifreq(&ifr, ifname) < 0) return -1;

  if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
    perror("ioctl");
    return -1;
  }

  printf("link index: %d\n", ifr.ifr_ifindex);

  if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
    perror("ioctl");
    return -1;
  }

  int linktype = ifr.ifr_hwaddr.sa_family;
  printf("link type:  %d (0x%04x)\n", linktype, linktype);

  if (ioctl(fd, SIOCGIFMTU, &ifr) < 0) {
    perror("ioctl");
    return -1;
  }

  printf("link mtu:   %d\n", ifr.ifr_mtu);

  return 0;
}
