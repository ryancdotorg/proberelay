/* SPDX-License-Identifier: BSD-3-Clause
Copyright ©2023 Ryan Castellucci, some rights reserved.
gcc -Os -std=c11 -Wall -Wextra -pedantic proberelay_nopcap.c -o proberelay_nopcap #*/

#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>

#include <time.h>

#include <poll.h>

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
#include <linux/net_tstamp.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#ifndef ARPHRD_IEEE80211_RADIOTAP
#include <linux/if_arp.h>
#endif

#define FLAGS_OFFSET_UNKNOWN 0
#define FLAGS_OFFSET_NONE -1

#define MTU 1500

#define IP4_HDR_LEN 20
#define IP6_HDR_LEN 40
#define UDP_HDR_LEN  8

#define PCAP_MAGIC_MICRO 0xA1B2C3D4
#define PCAP_MAGIC_NANO  0xA1B23C4D

#define DLT_IEEE802_11       105 /* IEEE 802.11 wireless */
#define DLT_IEEE802_11_RADIO 127 /* 802.11 plus radiotap radio header */

#define MIN(A, B) ((A) < (B) ? (A) : (B))
#define MAX(A, B) ((A) > (B) ? (A) : (B))

#ifndef SO_TIMESTAMPING_OLD
#define SO_TIMESTAMPING_OLD 37
#endif
#ifndef SO_TIMESTAMPING_NEW
#define SO_TIMESTAMPING_NEW 65
#endif

static int so_tstamp = SO_TIMESTAMPING_NEW;
static int has_nsec = 0;

static struct sock_filter template_filter[] = {
/*   0 */ { 0x30,                         0,                         0, 0xffffffff },
/*   1 */ { 0x45, /*   9 - (  1 + 1) */   7,                         0, 0x00000040 },
/*   2 */ { 0x30,                         0,                         0, 0xffffffff },
/*   3 */ { 0x45, /*   9 - (  3 + 1) */   5,                         0, 0x0000000c },
/*   4 */ { 0x15, /*   5 - (  4 + 1) */   0, /*   9 - (  4 + 1) */   4, 0x00000040 },
/*   5 */ { 0x28,                         0,                         0, 0xffffffff },
/*   6 */ { 0x14,                         0,                         0, 0x00000001 },
/*   7 */ { 0x45, /*   9 - (  7 + 1) */   1,                         0, 0x0000ffe0 },
/*   8 */ { 0x06,                         0,                         0,     262144 },
/*   9 */ { 0x06,                         0,                         0, 0x00000000 },
};

struct scm_timestamping {
  struct timespec ts[3];
};

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
  struct addrinfo *ai;
  char *filter;
  int cap_fd;
  int dst_fd;
  int linktype;
  int flags_offset;
  int wlan_offset;
  uint32_t snaplen;
};

static int arphdr_to_dlt(int arphdr) {
  int dlt;
  switch (arphdr) {
    case ARPHRD_IEEE80211:
      dlt = DLT_IEEE802_11;
      break;
    case ARPHRD_IEEE80211_RADIOTAP:
      dlt = DLT_IEEE802_11_RADIO;
      break;
    default:
      dlt = -1;
      break;
  }

  return dlt;
}

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

static ssize_t init_filter(struct capture_s *c, const uint8_t *pkt, size_t sz) {
  const int ninst = sizeof(template_filter)/sizeof(template_filter[0]);

  struct sock_filter filter[ninst];
  struct sock_fprog prog = { .len = ninst, .filter = filter };

  // is there a radiotap header?
  if (c->linktype == DLT_IEEE802_11_RADIO) {
    // find the flags offset (if present)
    if ((c->flags_offset = rt_flags_offset(pkt)) >= 0) {
      c->wlan_offset = *((uint16_t *)(pkt + 2));

      for (int i = 0; i < ninst; ++i) {
        filter[i] = template_filter[i];
      }

      // fill in offsets
      filter[0].k = c->flags_offset;
      filter[2].k = c->wlan_offset;
      filter[5].k = c->wlan_offset + 24;

      // fill in snaplen
      filter[8].k = c->snaplen;
    }
  }

  if (c->flags_offset < 0) {
    prog.len -= 2;
    for (int i = 2; i < ninst; ++i) {
      filter[i - 2] = template_filter[i];
    }

    // fill in offsets
    filter[0].k = 0;
    filter[3].k = 24;

    // fill in snaplen
    filter[7].k = c->snaplen;
  }

  if (setsockopt(c->cap_fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0) {
    perror("setsockopt (attach filter)");
    return -1;
  }

  int lock = 1;
  if (setsockopt(c->cap_fd, SOL_SOCKET, SO_LOCK_FILTER, &lock, sizeof(lock)) < 0) {
    perror("setsockopt (lock filter)");
    return -1;
  }

  // return packet length
  return MAX(sz, c->snaplen);
}

static ssize_t read_packet(struct capture_s *c, uint8_t *buf, size_t buf_sz) {
  struct header_s *h = (struct header_s *)buf;
  uint8_t *pkt = h->packet;
  size_t pkt_sz = buf_sz - sizeof(struct header_s);

  uint8_t control[1024];
  struct sockaddr_ll src;

  struct iovec iov[] = {0};
  iov->iov_base = pkt;
  iov->iov_len = pkt_sz;

  struct cmsghdr *cmsg;
  struct msghdr msg[] = {0};
  msg->msg_name = &src;
  msg->msg_namelen = sizeof(src);
  msg->msg_iov = iov;
  msg->msg_iovlen = 1;
  msg->msg_control = control;
  msg->msg_controllen = sizeof(control);

  ssize_t orig_len;
  if ((orig_len = recvmsg(c->cap_fd, msg, MSG_TRUNC)) < 0) {
    perror("recvmsg");
    return -1;
  } else if (orig_len > INT32_MAX) {
    fprintf(stderr, "bogus packet length: %zd\n", orig_len);
    return -1;
  }

  // set up filter once the first packet arrives
  if (c->flags_offset == FLAGS_OFFSET_UNKNOWN) {
    ssize_t sz = init_filter(c, pkt, h->incl_len);
    if (sz < 0) {
      exit(-1);
    } else {
      h->incl_len = (uint32_t)sz;
    }
  }

  // set file header data
#ifdef PCAP_USE_NANO
  h->magic_number = PCAP_MAGIC_NANO;
#else
  h->magic_number = PCAP_MAGIC_MICRO;
#endif
  h->version_major = 2;
  h->version_minor = 4;
  h->thiszone = 0;
  h->sigfigs = 0;
  h->snaplen = c->snaplen;
  h->linktype = c->linktype;
  // set packet record data (timestamp filled below)
  h->ts_sec = 0;
  h->ts_fsec = 0;
  h->orig_len = (uint32_t)orig_len;
  h->incl_len = MIN(h->orig_len, pkt_sz);

  if (c->flags_offset > 0) {
    // reject packets with bad fcs
    if (pkt[c->flags_offset] & 0x40) {
      fprintf(stderr, "bad fcs @ %d [%02x]\n", c->flags_offset, pkt[c->flags_offset]);
      return 0;
    }
  }

  // ensure this is a probe request
  if ((pkt[c->wlan_offset] & 0xfc) != 0x40) return 0;

  // ensure that the SSID isn't broadcast
  uint16_t bits = (pkt[c->wlan_offset + 24] << 8) + pkt[c->wlan_offset + 25];
  if ((bits & 0xffe0) != 0) return 0;

  /*
  char ssid[33];
  size_t ssid_len = pkt[c->wlan_offset + 25];
  for (size_t i = 0;;) {
    char b = pkt[c->wlan_offset + 26 + i];
    ssid[i] = (b < 32 || b > 126) ? '?' : b;

    if (++i >= ssid_len) {
      ssid[i] = '\0';
      break;
    }
  }

  printf("ssid: `%s`\n", ssid);
  */

  // find the timestamping data
  for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
    struct scm_timestamping* scm_ts = NULL;
    if (cmsg->cmsg_level != SOL_SOCKET) {
      continue;
    } else if (cmsg->cmsg_type == so_tstamp) {
      scm_ts = (struct scm_timestamping*) CMSG_DATA(cmsg);
      // try to get nanoseconds
      uint32_t nsec = scm_ts->ts[0].tv_nsec;

      // check handling mode
      if (has_nsec == 0 && nsec == 0) {
        // fall back to gettime
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        // copy timestamp seconds, truncating to 32 bits
        h->ts_sec = (uint32_t)ts.tv_sec;
        nsec = ts.tv_nsec;
      } else {
        has_nsec = 1;
        // copy timestamp seconds, truncating to 32 bits
        h->ts_sec = (uint32_t)scm_ts->ts[0].tv_sec;
      }

#ifndef PCAP_USE_NANO
      // convert nanoseconds to microseconds
      h->ts_fsec = nsec / 1000;
#else
      h->ts_fsec = nsec;
#endif
      break;
    }
  }

  return sizeof(struct header_s) + h->incl_len;
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

static int promisc(int fd, int idx) {
  struct packet_mreq mreq = {0};
  mreq.mr_ifindex = idx;
  mreq.mr_type = PACKET_MR_PROMISC;
  if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
    perror("setsockopt (promisc)");
    return -1;
  }

  return 0;
}

static int timestamping(int fd, bool enable_hw) {
  int flags = 0;
  flags |= SOF_TIMESTAMPING_SOFTWARE;
  flags |= SOF_TIMESTAMPING_RX_SOFTWARE;
  if (enable_hw) {
    flags |= SOF_TIMESTAMPING_RAW_HARDWARE;
    flags |= SOF_TIMESTAMPING_RX_HARDWARE;
  }

  if (setsockopt(fd, SOL_SOCKET, so_tstamp, &flags, sizeof(int)) < 0) {
    so_tstamp = SO_TIMESTAMPING_OLD;
    if (setsockopt(fd, SOL_SOCKET, so_tstamp, &flags, sizeof(int)) < 0) {
      perror("setsockopt (timestamping)");
      return -1;
    }
  }

  return 0;
}

static int ifbind(int fd, int idx) {
  struct sockaddr_ll addr = {0};
  addr.sll_family = AF_PACKET;
  addr.sll_ifindex = idx;
  addr.sll_protocol = htons(ETH_P_ALL);

  return bind(fd, (struct sockaddr*)&addr, sizeof(addr));
}

static int open_capture(struct capture_s *c, char *ifname) {
  if ((c->cap_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
    perror("socket");
    return -1;
  }

  struct ifreq ifr = {0};
  if (init_ifreq(&ifr, ifname) < 0) return -1;

  if (ioctl(c->cap_fd, SIOCGIFINDEX, &ifr) < 0) {
    perror("ioctl");
    return -1;
  }

  int idx = ifr.ifr_ifindex;

  if (ioctl(c->cap_fd, SIOCGIFHWADDR, &ifr) < 0) {
    perror("ioctl");
    return -1;
  }

  if ((c->linktype = arphdr_to_dlt(ifr.ifr_hwaddr.sa_family)) < 0) {
    fprintf(stderr, "Unsupported link type: %d\n", ifr.ifr_hwaddr.sa_family);
    return -1;
  }

  if (ifbind(c->cap_fd, idx) < 0) return -1;
  if (timestamping(c->cap_fd, false) < 0) return -1;
  if (promisc(c->cap_fd, idx) < 0) return -1;

  return 0;
}

int main(int argc, char *argv[]) {
  struct addrinfo hints, *res, *ai;
  struct capture_s c[1];

  if (argc != 4) {
    fprintf(stderr, "Usage: %s IFNAME HOST PORT\n", argv[0]);
    return -1;
  }

  c->filter = NULL;
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
    fprintf(stderr, "Failed to open capture socket on %s!\n", ifname);
    return -1;
  } else {
    fprintf(stderr, "Forwarding from %s to %s, capture size %u bytes\n", ifname, dststr, c->snaplen);
  }

  if (droproot() != 0) {
    fprintf(stderr, "Failed to drop root!\n");
    return -1;
  }

  // capture buffer
  uint8_t buf[65536];

  // set up polling
  struct pollfd pfds[1];
  pfds[0].fd = c->cap_fd;
  pfds[0].events = POLLIN;

  // capture loop
  for (;;) {
    int n = poll(pfds, 1, 1000);

    if (n > 0) {
      int captured = pfds[0].revents & POLLIN;
      if (captured) {
        //fprintf(stderr, "Ready!\n");
        ssize_t rv = read_packet(c, buf, sizeof(buf));
        //fprintf(stderr, "Captured! %zd\n", rv);
        if (rv > 0) {
          /*
          fprintf(stderr, "Data: ");
          for (ssize_t i = 0; i < rv; ++i) fprintf(stderr, "%02x", buf[i]);
          fprintf(stderr, " (%zd octets)\n", rv);
          */
          send_packet(c, buf);
        }
      } else {
        fprintf(stderr, "Unexpected poll response!\n");
      }
    }
  }
}
