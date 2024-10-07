/* SPDX-License-Identifier: BSD-3-Clause
Copyright ©2024 Ryan Castellucci, some rights reserved. */
#pragma once

#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>

#include <grp.h>

#include <netdb.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <net/if.h>
#include <net/ethernet.h>

#include <arpa/inet.h>

#include <linux/filter.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/net_tstamp.h>

#define FLAGS_OFFSET_UNKNOWN 0
#define FLAGS_OFFSET_NONE -1

// state object
struct capture_s {
  struct addrinfo *ai;
  char *filter;
  int fd;
  int linktype;
  int flags_offset;
  uint32_t snaplen;
};
