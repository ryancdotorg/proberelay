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

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <pcap/pcap.h>


#define FLAGS_OFFSET_UNKNOWN 0
#define FLAGS_OFFSET_NONE -1

#define MTU 1500

#define IP4_HDR_LEN 20
#define IP6_HDR_LEN 40
#define UDP_HDR_LEN  8

#define PCAP_MAGIC_MICRO 0xA1B2C3D4
#define PCAP_MAGIC_NANO  0xA1B23C4D

#ifndef DLT_IEEE802_11
#define DLT_IEEE802_11       105 /* IEEE 802.11 wireless */
#endif
#ifndef DLT_IEEE802_11_RADIO
#define DLT_IEEE802_11_RADIO 127 /* 802.11 plus radiotap radio header */
#endif

#define MIN(A, B) ((A) < (B) ? (A) : (B))
#define MAX(A, B) ((A) > (B) ? (A) : (B))

#ifndef SO_TIMESTAMPING_OLD
#define SO_TIMESTAMPING_OLD 37
#endif
#ifndef SO_TIMESTAMPING_NEW
#define SO_TIMESTAMPING_NEW 65
#endif





#define _FIRST(X, ...) X
#define PCAP_CHECK(F, ...) { \
  int _rv; \
  if ((_rv = F(__VA_ARGS__)) != 0) { \
    pcap_perror(_FIRST(__VA_ARGS__), #F); \
    return _rv; \
  } \
}

/* 40 bytes - this is a pcap file header plus a packet record header */
struct header_s {
  /* PCAP FILE HEADER */
  /*  0 */ uint32_t  magic_number;
  /*  4 */ uint16_t  version_major;
  /*  6 */ uint16_t  version_minor;
  /*  8 */ int32_t   thiszone;
  /* 12 */ uint32_t  sigfigs;
  /* 16 */ uint32_t  snaplen;
  /* 20 */ uint32_t  linktype;
  /* PCAP PACKET RECORD */
  /* 24 */ uint32_t  ts_sec;
  /* 28 */ uint32_t  ts_fsec;
  /* 32 */ uint32_t  incl_len;
  /* 36 */ uint32_t  orig_len;
  /* PCAP PACKET DATA */
  /* 40 */ uint8_t   packet[];
};

// state object for packet handler callback
struct capture_s {
  pcap_t *pcap;
  struct addrinfo *ai;
  char *filter;
  int cap_fd;
  int dst_fd;
  int linktype;
  int flags_offset;
  int wlan_offset;
  uint32_t snaplen;
};

static inline int rt_flags_offset(const uint8_t *pkt) {
  int flags_offset = FLAGS_OFFSET_NONE, p = 1;
  uint32_t *radiotap = (uint32_t *)pkt;

  // check whether bit 1 (flags) is set in the it_present bitmask
  if (radiotap[p] & (1<<1)) {
    // check whether bit 0 (tsft) is set in the it_present bitmask
    bool has_tsft = radiotap[p] & (1<<0);

    // high bit indicates another it_present bitmasks
    while (radiotap[p] & (1<<31)) ++p;
    // end of it_present bitmasks

    flags_offset = 4 + 4 * p;
    // tsft is 8 bytes and must be aligned to a multiple of 8 bytes
    if (has_tsft) flags_offset = (flags_offset + 15) & (~7);
    //fprintf(stderr, "Found radiotap flags offset: %d\n", flags_offset);
  }

  return flags_offset;
}

// lock the filter so that it can't be removed or changed
static inline int lock_filter(const struct capture_s *c) {
  int lock = 1;
  return setsockopt(c->cap_fd, SOL_SOCKET, SO_LOCK_FILTER, &lock, sizeof(lock));
}

static ssize_t init_filter(struct capture_s *c, const struct pcap_pkthdr *p, const uint8_t *pkt) {
  struct bpf_program fp[1];
  fp->bf_insns = NULL;

  // is there a radiotap header?
  if (c->linktype == DLT_IEEE802_11_RADIO) {
    // find the flags offset (if present)
    if ((c->flags_offset = rt_flags_offset(pkt)) >= 0) {
      c->wlan_offset = *((uint16_t *)(pkt + 2));

      if (c->filter == NULL) {
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
        if (asprintf(&(c->filter),
          "radio[%d] & 0x40 == 0 and "
          "radio[%d] & 0xfc == 0x40 and "
          "(radio[%d:2] - 1) & 0xffe0 == 0",
          c->flags_offset, c->wlan_offset, c->wlan_offset + 24
        ) < 0) {
          fprintf(stderr, "could not build filter\n");
          exit(1);
        }
      }
    }
  }

  // less efficient filter with no fcs check used if not radiotap
  if (c->filter == NULL) {
    c->filter = "wlan[0] & 0xfc == 40 and (wlan[24:2] - 1) & 0xffe0 == 0";
  }

  if (pcap_compile(c->pcap, fp, c->filter, 1, PCAP_NETMASK_UNKNOWN) != 0) {
    pcap_perror(c->pcap, "pcap_compile");
    exit(1);
  }

  if (pcap_setfilter(c->pcap, fp) != 0) {
    pcap_perror(c->pcap, "pcap_setfilter");
    exit(1);
  }

  if (lock_filter(c) != 0) {
    perror("lock_filter");
    exit(1);
  }

  fprintf(stderr, "set filter: %s\n", c->filter);

  // run the filter against this packet
  int ret = pcap_offline_filter(fp, p, pkt);
  pcap_freecode(fp);

  return ret;
}

void send_packet(struct capture_s *c, uint8_t *buf) {
  struct header_s *h = (struct header_s *)buf;

  // send the packet
  if (h->incl_len) {
    ssize_t len = sizeof(struct header_s) + h->incl_len;
    ssize_t n = sendto(c->dst_fd, buf, len, 0, c->ai->ai_addr, c->ai->ai_addrlen);
    if (n != len) { perror("sendto"); }
  }
}

// chroot, first creating directory if required
static int do_chroot(char *dir) {
  int rv = 0;

  if (access(dir, R_OK|X_OK) != 0) {
    // assume it doesn't exist...
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

    if ((rv = do_chroot("/var/empty")) != 0) return rv;

    if ((rv = setuid(65534)) != 0) { perror("setuid"); return rv; }
  }

  return rv;
}

// p->caplen, p->len, p->ts
void handler(uint8_t *user, const struct pcap_pkthdr *p, const uint8_t *pkt) {
  uint8_t buf[65536];

  struct capture_s *c = (struct capture_s *)user;
  struct header_s *h = (struct header_s *)buf;

  uint32_t caplen = MIN(p->caplen, c->snaplen);

  // set file header data
  h->magic_number = PCAP_MAGIC_MICRO;
  h->version_major = 2;
  h->version_minor = 4;
  h->thiszone = 0;
  h->sigfigs = 0;
  h->snaplen = c->snaplen;
  h->linktype = c->linktype;
  // set packet record data
  h->ts_sec = p->ts.tv_sec;
  h->ts_fsec = p->ts.tv_usec;
  h->incl_len = caplen;
  h->orig_len = p->len;

  // set up filter once the first packet arrives
  if (c->flags_offset == FLAGS_OFFSET_UNKNOWN) {
    ssize_t rv = init_filter(
    if ((rv = init_filter(c, p, pkt) == 0) return;
  }

  // copy the packet into the buffer
  memcpy(buf + sizeof(struct header_s), pkt, caplen);
  send_packet(c, buf);
}

static int open_capture(struct capture_s *c, char *ifname) {
  char *errbuf = malloc(PCAP_ERRBUF_SIZE);
  if (errbuf == NULL) {
    perror("malloc");
    abort();
  }

  c->pcap = pcap_create(ifname, errbuf);

  PCAP_CHECK(pcap_set_snaplen, c->pcap, c->snaplen);
  PCAP_CHECK(pcap_set_promisc, c->pcap, 1);
  PCAP_CHECK(pcap_set_timeout, c->pcap, 100);
  PCAP_CHECK(pcap_set_immediate_mode, c->pcap, 1);
  // pcap_set_tstamp_precision?

  PCAP_CHECK(pcap_activate, c->pcap);

  // needs to be called *after* activation
  PCAP_CHECK(pcap_setdirection, c->pcap, PCAP_D_IN);

  if ((c->cap_fd = pcap_fileno(c->pcap)) < 0) {
    pcap_perror(c->pcap, "pcap_fileno");
    return -1;
  }

  c->linktype = pcap_datalink(c->pcap);

  return 0;
}

int relay(struct capture_s *c) {
  return pcap_loop(c->pcap, -1, &handler, (uint8_t *)c);
}

int main(int argc, char *argv[]) {
  struct addrinfo hints, *res, *ai;
  struct capture_s c[1];

  if (argc < 4 || argc > 5) {
    fprintf(stderr, "Usage: %s IFACE HOST PORT [FILTER]\n", argv[0]);
    return -1;
  } else if (argc == 4) {
    c->filter = NULL;
  } else if (argc == 5) {
    c->filter = argv[4];
  }

  c->flags_offset = FLAGS_OFFSET_UNKNOWN;
  c->wlan_offset = 0;

  char *ifname = argv[1];
  char *host = argv[2];
  char *port = argv[3];

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_ADDRCONFIG;

  getaddrinfo(host, port, &hints, &res);

  // try to find a usable address
  for (ai = res; ai != NULL; ai = ai->ai_next) {
    c->dst_fd = socket(ai->ai_family, ai->ai_socktype | SOCK_NONBLOCK, ai->ai_protocol);
    if (c->dst_fd == -1) continue;

    break;
  }

  if (ai == NULL) {
    fprintf(stderr, "Could not open destination socket!");
    return -1;
  }

  c->ai = ai;

  char addrstr[INET6_ADDRSTRLEN+1];
  char dststr[INET6_ADDRSTRLEN+9];

  if (ai->ai_family == AF_INET) {
    c->snaplen = MTU - (IP4_HDR_LEN + UDP_HDR_LEN + sizeof(struct header_s));
    struct sockaddr_in *sin = (struct sockaddr_in *)ai->ai_addr;
    inet_ntop(AF_INET, &sin->sin_addr, addrstr, sizeof(addrstr));
    snprintf(dststr, sizeof(dststr), "%s:%u", addrstr, sin->sin_port);
  } else if (ai->ai_family == AF_INET6) {
    c->snaplen = MTU - (IP6_HDR_LEN + UDP_HDR_LEN + sizeof(struct header_s));
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ai->ai_addr;
    inet_ntop(AF_INET6, &sin6->sin6_addr, addrstr, sizeof(addrstr));
    snprintf(dststr, sizeof(dststr), "[%s]:%u", addrstr, sin6->sin6_port);
  } else {
    fprintf(stderr, "Unexpected address family: %d\n", ai->ai_family);
    return -1;
  }

  if (open_capture(c, ifname) != 0) {
    fprintf(stderr, "Failed to start capture on %s!\n", ifname);
    return -1;
  } else {
    fprintf(stderr, "Forwarding from %s to %s, capture size %u bytes\n", ifname, dststr, c->snaplen);
  }

  if (droproot() != 0) {
    fprintf(stderr, "Failed to drop root!\n");
    return -1;
  }

  // setting the filter is deferred until the first packet arrives
  return relay(c);
}
