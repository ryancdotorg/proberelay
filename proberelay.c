/* SPDX-License-Identifier: BSD-3-Clause
Copyright ©2023 Ryan Castellucci, some rights reserved.
gcc -O2 -std=c11 -Wall -Wextra -pedantic proberelay.c -lpcap -o proberelay #*/

// asprintf
#define _GNU_SOURCE

#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>

#include <grp.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <pcap/pcap.h>

#define MTU 1500

#define IP4_HDR_LEN 20
#define IP6_HDR_LEN 40
#define UDP_HDR_LEN  8

#define MIN(A, B) ((A) < (B) ? (A) : (B))
#define MAX(A, B) ((A) > (B) ? (A) : (B))

#define PCAP_CHECK(F, P, ...) { \
int _rv; \
if ((_rv = F(P, __VA_ARGS__)) != 0) { \
  pcap_perror(P, #F); \
  return _rv; \
}}

/* 40 bytes - this is a pcap file header plus a packet record header */
struct header_s {
  uint32_t  magic_number;
  uint16_t  version_major;
  uint16_t  version_minor;
  int32_t   thiszone;
  uint32_t  sigfigs;
  uint32_t  snaplen;
  uint32_t  network;
  uint32_t  ts_sec;
  uint32_t  ts_usec;
  uint32_t  incl_len;
  uint32_t  orig_len;
};

// state object for packet handler callback
struct userdata_s {
  pcap_t *pcap;
  struct addrinfo *ai;
  char *filter;
  int fd;
  int linktype;
  int flags_off;
  uint32_t snaplen;
};

static inline int rt_flags_offset(const uint8_t *pkt) {
  int flags_off = -1, p = 1;
  uint32_t *radiotap = (uint32_t *)pkt;

  // check whether bit 1 (flags) is set in the it_present bitmask
  if (radiotap[p] & (1<<1)) {
    // check whether bit 0 (tsft) is set in the it_present bitmask
    bool has_tsft = radiotap[p] & (1<<0);

    // high bit indicates another it_present bitmasks
    while (radiotap[p] & (1<<31)) ++p;
    // end of it_present bitmasks

    flags_off = 4 + 4 * p;
    // tsft is 8 bytes and must be aligned to a multiple of 8 bytes
    if (has_tsft) flags_off = (flags_off + 15) & (~7);
  }

  return flags_off;
}

// lock the filter so that it can't be removed or changed
static inline int lock_filter(pcap_t *pcap) {
  int lock = 1, fd;
  if ((fd = pcap_fileno(pcap)) < 0) {
    pcap_perror(pcap, "pcap_fileno");
    return fd;
  }
  return setsockopt(fd, SOL_SOCKET, SO_LOCK_FILTER, &lock, sizeof(lock));
}

static int filter_init(struct userdata_s *u, const struct pcap_pkthdr *h, const uint8_t *pkt) {
  struct bpf_program fp[1];
  fp->bf_insns = NULL;
  int wlan_off = -1;
  u->flags_off = -1;

  do {
    // is there a radiotap header?
    if (u->linktype != DLT_IEEE802_11_RADIO) break;

    // find the flags offset (if present)
    if ((u->flags_off = rt_flags_offset(pkt)) < 0) break;
    wlan_off = *((uint16_t *)(pkt + 2));

    if (u->filter == NULL) {
      // valid fcs, probe request, non-broadcast
      //
      // The SSID is required to be the first TLV item in the probe request,
      // and is type 0. Length 0 means the probe request is broadcast,
      // otherwise the length can be 1-32 inclusive.
      //
      // This Python code shows the bit twiddling is correct:
      // for x in range(65536):
      //     if (x - 1) & 0xffe0 == 0:
      //         print((x >> 8), x & 0xff)
      if (asprintf(&(u->filter),
        "radio[%d] & 0x40 == 0 and "
        "radio[%d] & 0xfc == 0x40 and "
        "(radio[%d:2] - 1) & 0xffe0 == 0",
        u->flags_off, wlan_off, wlan_off + 24
      ) < 0) {
        fprintf(stderr, "could not build filter\n");
        exit(1);
      }
    }
  } while (0);

  // less efficient filter used if not radiotap
  if (u->filter == NULL) {
    u->filter = "wlan[0] & 0xfc == 40 and wlan[24:2] - 1) & 0xffe0 == 0";
  }

  if (pcap_compile(u->pcap, fp, u->filter, 1, PCAP_NETMASK_UNKNOWN) != 0) {
    pcap_perror(u->pcap, "pcap_compile");
    exit(1);
  }

  if (pcap_setfilter(u->pcap, fp) != 0) {
    pcap_perror(u->pcap, "pcap_setfilter");
    exit(1);
  }

  if (lock_filter(u->pcap) != 0) {
    perror("lock_filter");
    exit(1);
  }

  fprintf(stderr, "set filter: %s\n", u->filter);

  // run the filter against this packet
  int ret = pcap_offline_filter(fp, h, pkt);
  pcap_freecode(fp);

  return ret;
}

void handler(uint8_t *user, const struct pcap_pkthdr *h, const uint8_t *pkt) {
  uint8_t buf[65536];

  struct userdata_s *u = (struct userdata_s *)user;
  struct header_s *hdr = (struct header_s *)buf;

  uint32_t caplen = MIN(h->caplen, u->snaplen);

  // set up filter once the first packet arrives
  if (u->flags_off == 0) {
    if (filter_init(u, h, pkt) == 0) return;
  } else if (u->flags_off > 0) {
    // reject packets with bad fcs
    if (pkt[u->flags_off] & 0x40) return;
  }

  // set header data
  hdr->magic_number = 0xa1b2c3d4;
  hdr->version_major = 2;
  hdr->version_minor = 4;
  hdr->thiszone = 0;
  hdr->sigfigs = 0;
  hdr->snaplen = u->snaplen;
  hdr->network = u->linktype;
  hdr->ts_sec = h->ts.tv_sec;
  hdr->ts_usec = h->ts.tv_usec;
  hdr->incl_len = caplen;
  hdr->orig_len = h->len;

  // copy the packet into the buffer
  memcpy(buf + sizeof(struct header_s), pkt, caplen);
  ssize_t len = sizeof(struct header_s) + caplen;

  // send the packet
  ssize_t n = sendto(u->fd, buf, len, 0, u->ai->ai_addr, u->ai->ai_addrlen);
  if (n != len) { perror("sendto"); }
}

// chroot, first creating directory if required
static int do_chroot(char *dir) {
  int rv = 0;

  if (access(dir, R_OK|X_OK) != 0) {
    // assume it dosn't exist...
    if ((rv = mkdir(dir, 0555)) != 0) { perror("mkdir"); return rv; }
  }
  if ((rv = chroot(dir)) != 0) { perror("chroot"); return rv; }
  if ((rv = chdir("/")) != 0) { perror("chdir"); return rv; }

  return rv;
}

// set uid/gid to nobody/nogroup
static int droproot() {
  int rv = 0;

  if (getuid() == 0) {
    // groups can't be dropped once setuid is called, so do them first
    if ((rv = setgroups(0, NULL)) !=0 ) { perror("setgroups"); return rv; }
    if ((rv = setgid(65534)) != 0) { perror("setgid"); return rv; }

    do_chroot("/var/empty");

    if ((rv = setuid(65534)) != 0) { perror("setuid"); return rv; }
  }

  return rv;
}

int main(int argc, char *argv[]) {
  char errbuf[PCAP_ERRBUF_SIZE];

  struct addrinfo hints, *res, *ai;
  struct userdata_s u[1];

  if (argc < 4 || argc > 5) {
    fprintf(stderr, "Usage: %s IFACE HOST PORT [FILTER]\n", argv[0]);
    return -1;
  } else if (argc == 4) {
    u->filter = NULL;
  } else if (argc == 5) {
    u->filter = argv[4];
  }

  char *iface = argv[1];
  char *host = argv[2];
  char *port = argv[3];

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_ADDRCONFIG;

  getaddrinfo(host, port, &hints, &res);

  // try to find a usable address
  for (ai = res; ai != NULL; ai = ai->ai_next) {
    u->fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (u->fd == -1) continue;

    break;
  }

  if (ai == NULL) {
    fprintf(stderr, "Could not open socket.");
    return -1;
  }

  u->ai = ai;

  if (ai->ai_family == AF_INET) {
    u->snaplen = MTU - (IP4_HDR_LEN + UDP_HDR_LEN + sizeof(struct header_s));
  } else if (ai->ai_family == AF_INET6) {
    u->snaplen = MTU - (IP6_HDR_LEN + UDP_HDR_LEN + sizeof(struct header_s));
  } else {
    fprintf(stderr, "Unexpected address family: %d\n", ai->ai_family);
    return -1;
  }

  pcap_t *pcap = pcap_create(iface, errbuf);

  PCAP_CHECK(pcap_set_snaplen, pcap, u->snaplen);
  PCAP_CHECK(pcap_set_promisc, pcap, 1);
  PCAP_CHECK(pcap_set_timeout, pcap, 100);
  PCAP_CHECK(pcap_set_immediate_mode, pcap, 1);

  int rv;
  if ((rv = pcap_activate(pcap)) != 0) {
    pcap_perror(pcap, "pcap_activate");
    return rv;
  }

  // not actually checking that this worked...
  droproot();

  PCAP_CHECK(pcap_setdirection, pcap, PCAP_D_IN);

  u->pcap = pcap;
  u->linktype = pcap_datalink(pcap);
  u->flags_off = 0;

  // setting the filter is deferred until the first packet arrives
  return pcap_loop(pcap, -1, &handler, (uint8_t *)u);
}
