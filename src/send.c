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

#include "common.h"
#include "send.h"

ssize_t fill_header(
  struct header_s *h,
  const struct capture_s *c,
  const struct timespec *ts,
  uint32_t orig_len,
  uint32_t incl_len
) {
  // set file header data
  h->magic_number = PCAP_MAGIC_MICRO;
  h->version_major = 2;
  h->version_minor = 4;
  h->thiszone = 0;
  h->sigfigs = 0;
  h->snaplen = c->snaplen;
  h->fcs = 0;
  h->pad0 = 0;
  h->linktype = c->linktype;
  // set packet record data
  h->ts_sec = (uint32_t)(ts->tv_sec); /* may truncate */
  h->ts_usec = ts->tv_nsec / 1000;
  h->orig_len = orig_len;
  h->incl_len = incl_len;
}

void send_packet(struct capture_s *c, uint8_t *buf) {
  struct header_s *h = (struct header_s *)buf;
  const uint8_t *pkt = h->data;

  // set up filter once the first packet arrives
  if (c->flags_offset == FLAGS_OFFSET_UNKNOWN) {
    if (init_filter(c, pkt, 0) == 0) return;
  } else if (c->flags_offset > 0) {
    // reject packets with bad fcs
    if (pkt[c->flags_offset] & 0x40) return;
  }

  // send the packet
  ssize_t len = sizeof(struct header_s) + h->incl_len;
  ssize_t n = sendto(c->fd, buf, len, 0, c->ai->ai_addr, c->ai->ai_addrlen);
  if (n != len) { perror("sendto"); }
}
