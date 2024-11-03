/* SPDX-License-Identifier: BSD-3-Clause
Copyright ©2024 Ryan Castellucci, some rights reserved.
gcc -Os -std=gnu17 -Wall -Wextra -pedantic proberelay.c -o proberelay #*/

#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <endian.h>
#include <errno.h>
#include <stdio.h>
#include <netdb.h>
#include <time.h>
#include <poll.h>
#include <pwd.h>
#include <grp.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

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

#include "escape.h"

#include "radiotap.h"

#include "common.h"

#ifndef BUILD_TIME
#define BUILD_TIME __TIMESTAMP__
#endif
#ifndef VERSION
#define VERSION "0.0.1"
#endif
#ifndef VERSION_EXTRA
#define VERSION_EXTRA ""
#endif

#ifndef BPF_INST
#define _BPFJ(I, J) (J == 0 ? 0 : (J - (I + 1)))
#define BPF_INST(I, CODE, JT, JF, K) { CODE, _BPFJ(I, JT), _BPFJ(I, JF), K }
#endif

#ifndef DLT_IEEE802_11
#define DLT_IEEE802_11       105 /* IEEE 802.11 wireless */
#endif
#ifndef DLT_IEEE802_11_RADIO
#define DLT_IEEE802_11_RADIO 127 /* 802.11 plus radiotap radio header */
#endif

#ifndef SO_TIMESTAMPING_OLD
#define SO_TIMESTAMPING_OLD 37
#endif
#ifndef SO_TIMESTAMPING_NEW
#define SO_TIMESTAMPING_NEW 65
#endif

static int so_tstamp = SO_TIMESTAMPING_NEW;

struct scm_timestamping {
  struct timespec ts[3];
};

static int arphdr_to_dlt(int arphdr) {
  int dlt;
  switch (arphdr) {
    case ARPHRD_IEEE80211_RADIOTAP:
      dlt = DLT_IEEE802_11_RADIO;
      break;
    case ARPHRD_IEEE80211:
      dlt = DLT_IEEE802_11;
      break;
    default:
      dlt = -1;
      break;
  }

  return dlt;
}

static int read_kernel_tstamp(struct header_s *h, struct msghdr *msg) {
  struct cmsghdr *cmsg;
  for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
    struct scm_timestamping* scm_ts = NULL;
    if (cmsg->cmsg_level != SOL_SOCKET) {
      continue;
    } else if (cmsg->cmsg_type == so_tstamp) {
      scm_ts = (struct scm_timestamping*) CMSG_DATA(cmsg);
      // copy timestamp seconds, truncating to 32 bits
      h->ts_sec = (uint32_t)scm_ts->ts[0].tv_sec;
      // get fractional seconds
      h->ts_fsec = TS_SCALE(scm_ts->ts[0].tv_nsec);
      return 0;
    }
  }

  return -1;
}

static ssize_t read_raw(const struct capture_s *c, uint8_t *buf, size_t buf_sz) {
  struct header_s *h = (struct header_s *)buf;
  uint8_t *pkt = h->packet;
  size_t pkt_sz = buf_sz - sizeof(struct header_s);

  struct timespec ts;

  uint8_t control[2048];
  struct sockaddr_ll src;

  struct iovec iov[] = {0};
  iov->iov_base = pkt;
  iov->iov_len = pkt_sz;

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
    fprintf(stderr, "Bogus packet length: %zd\n", orig_len);
    return -1;
  }

  // set file header data
  h->magic_number = PCAP_MAGIC;
  h->version_major = 2;
  h->version_minor = 4;
  h->thiszone = 0;
  h->sigfigs = 0;
  h->snaplen = c->snaplen;
  h->linktype = c->linktype;

  // set packet record data
  switch (c->tstamp_mode) {
    case TS_KERNEL:
      if (read_kernel_tstamp(h, msg) != 0) {
        fprintf(stderr, "Failed to read kernel timestamp!\n");
        return -1;
      }
      break;
    case TS_SYSTEM:
      clock_gettime(CLOCK_REALTIME, &ts);
      h->ts_sec = ts.tv_sec;
      h->ts_fsec = TS_SCALE(ts.tv_nsec);
      break;
    case TS_COARSE:
      clock_gettime(CLOCK_REALTIME_COARSE, &ts);
      h->ts_sec = ts.tv_sec;
      h->ts_fsec = TS_SCALE(ts.tv_nsec);
      break;
    case TS_NONE:
      h->ts_sec = 0;
      h->ts_fsec = 0;
      break;
    default:
      fprintf(stderr, "Invalid timestamp mode: %d\n", c->tstamp_mode);
      return -1;
  }
  h->incl_len = MIN((uint32_t)orig_len, pkt_sz);
  h->orig_len = (uint32_t)orig_len;

  return sizeof(struct header_s) + h->incl_len;
}

void send_packet(const struct capture_s *c, const uint8_t *buf) {
  const struct header_s *h = (struct header_s *)buf;

  // send the packet
  if (h->incl_len) {
    ssize_t len = sizeof(struct header_s) + h->incl_len;
    ssize_t n = sendto(c->dst_fd, buf, len, 0, c->ai->ai_addr, c->ai->ai_addrlen);
    if (n != len) { perror("sendto"); }
  }
}

int fprint_packet(FILE *f, const struct capture_s *c, const uint8_t *buf) {
  static char last_ssid[33];
  static double last_time = 0;

  const struct header_s *h = (struct header_s *)buf;
  const uint8_t *pkt = h->packet;

  double time;
  struct timespec ts;

  char str[32*6+1];
  size_t pkt_ssid_sz = pkt[c->wlan_offset + 25];
  const uint8_t *pkt_ssid = pkt + c->wlan_offset + 26;

  if (clock_gettime(CLOCK_MONOTONIC_COARSE, &ts) < 0) return -1;
  time = ts.tv_sec + ts.tv_nsec * 1e-9;

  // suppress duplicates
  if (memcmp(last_ssid, pkt + c->wlan_offset + 25, pkt_ssid_sz + 1) == 0) {
    if (time - last_time < 5) {
      last_time = time;
      return 0;
    }
  } else {
    memcpy(last_ssid, pkt + c->wlan_offset + 25, pkt_ssid_sz + 1);
  }

  last_time = time;

  json_escape(str, sizeof(str), pkt_ssid, pkt_ssid_sz);

  return fprintf(
    f, "%02x:%02x:%02x:%02x:%02x:%02x \"%s\"\n",
    pkt[c->wlan_offset + 10], pkt[c->wlan_offset + 11],
    pkt[c->wlan_offset + 12], pkt[c->wlan_offset + 13],
    pkt[c->wlan_offset + 14], pkt[c->wlan_offset + 15],
    str
  );
}

void handle_packet(struct capture_s *c, const uint8_t *buf) {
  const struct header_s *h = (struct header_s *)buf;
  const uint8_t *pkt = h->packet;

#ifndef NDEBUG
  fprintf(stderr, "got packet: ");
  for (unsigned i = 0; i < h->incl_len; ++i) {
    fprintf(stderr, "%02x", pkt[i]);
  }
  fprintf(stderr, " (%u octets)\n", h->incl_len);
#endif

  // rather than trying to parse the radiotap header in the filter, we examine
  // the radiotap header and generate an appropriate filter at runtime
  if (c->wlan_offset == RT_OFFSET_UNKNOWN) {
    debugp("setting filter");
    if (calc_filter(c, pkt, h->incl_len) < 0) { exit(-1); }
    // drop the unfiltered packet
    return;
  }

  // are we filtering on ssid?
  if (c->exclude[0] > 0 && pkt[c->wlan_offset] == 0x40) {
    unsigned exclude_len, exclude_pos = 0;
    const uint8_t *ssid = pkt + c->wlan_offset + 25;

    while ((exclude_len = c->exclude[exclude_pos]) > 0) {
      if (memcmp(ssid, c->exclude + exclude_pos, exclude_len + 1) == 0) {
        debugp("ssid filtered");
        return;
      }

      exclude_pos += exclude_len + 1;
    }
  }

  debugp("send packet %p %p", (void *)c, buf);
  send_packet(c, buf);
  if (c->log_file != NULL) {
    fprint_packet(c->log_file, c, buf);
  }
}

// set uid/gid to nobody/nogroup
static int droproot() {
  int rv = 0;

  if (getuid() == 0) {
#if !defined(UNPRIV_GID) || !defined(UNPRIV_UID)
    struct passwd *pwd;
    if ((pwd = getpwnam("nobody")) == NULL) { perror("getpwnam"); return -1; }
#endif
#ifndef UNPRIV_GID
#define UNPRIV_GID pwd->pw_gid
#endif
#ifndef UNPRIV_UID
#define UNPRIV_UID pwd->pw_uid
#endif
    char dir[] = "/var/empty";
    // groups can't be dropped once setuid is called, so do them first
    if ((rv = setgroups(0, NULL)) !=0 ) { perror("setgroups"); return rv; }
    if ((rv = setgid(UNPRIV_GID)) != 0) { perror("setgid"); return rv; }
    if (access(dir, R_OK|X_OK) != 0) {
      // assume it doesn't exist...
      if ((rv = mkdir(dir, 0555)) != 0) { perror("mkdir"); return rv; }
    }
    if ((rv = chroot(dir)) != 0) { perror("chroot"); return rv; }
    if ((rv = chdir("/")) != 0) { perror("chdir"); return rv; }
    if ((rv = setuid(UNPRIV_UID)) != 0) { perror("setuid"); return rv; }
  }

  return rv;
}

static int bind_ifname(struct capture_s *c, const char *ifname) {
  c->ifname = ifname;
  size_t ifname_len = strlen(ifname);

  struct ifreq ifr;
  if (ifname_len < sizeof(ifr.ifr_name)) {
    memcpy(ifr.ifr_name, ifname, ifname_len);
    ifr.ifr_name[ifname_len] = 0;
  } else {
    return -1;
  }

  if (ioctl(c->cap_fd, SIOCGIFHWADDR, &ifr) < 0) {
    perror("ioctl");
    return -1;
  }

  if ((c->linktype = arphdr_to_dlt(ifr.ifr_hwaddr.sa_family)) < 0) {
    fprintf(stderr, "Unsupported link type: %d\n", ifr.ifr_hwaddr.sa_family);
    return -1;
  }

  if (ioctl(c->cap_fd, SIOCGIFINDEX, &ifr) < 0) {
    perror("ioctl");
    return -1;
  }

  struct sockaddr_ll addr;
  addr.sll_family = AF_PACKET;
  addr.sll_ifindex = ifr.ifr_ifindex;
  addr.sll_protocol = htons(ETH_P_ALL);

  int err;
  if ((err = bind(c->cap_fd, (struct sockaddr*)&addr, sizeof(addr))) < 0) {
    perror("bind");
    return -1;
  }

  return ifr.ifr_ifindex;
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

static int open_capture(struct capture_s *c, const char *ifname) {
  if ((c->cap_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
    perror("socket");
    return -1;
  }

  int idx;
  if ((idx = bind_ifname(c, ifname)) < 0) {
    return -1;
  }

  if (c->tstamp_mode == TS_KERNEL) {
    if (timestamping(c->cap_fd, false) < 0) {
      return -1;
    }
  }

  if (promisc(c->cap_fd, idx) < 0) {
    return -1;
  }

  return 0;
}

int relay(struct capture_s *c) {
  // capture buffer
  uint8_t buf[4096];

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
        ssize_t rv = read_raw(c, buf, sizeof(buf));
        if (rv > 0) {
          handle_packet(c, buf);
        }
      } else {
        fprintf(stderr, "Unexpected poll response!\n");
      }
    }
  }

  return 0;
}

void usage(FILE *f, char *argv0) {
  fprintf(f,
    "Usage: %s [OPTIONS] ...\n\n"
    "  -i IFNAME                         name of capture interface (required)\n"
    "  -d HOST                           host to send probes to (required)\n"
    "  -p PORT                           port to send probes to (default: 26737)\n"
    "  -x SSID                           ssid to ignore (multiple allowed)\n"
    "  -r SIGNAL                         minimum signal strength (-127 to 255)\n"
    "  -t kernel|system|coarse|none      timestamp type (default: kernel)\n"
    "  -e                                log to stderr\n"
    , argv0
  );
}

int main(int argc, char *argv[]) {
  struct addrinfo hints, *res, *ai;
  struct capture_s c[] = {0};

  c->log_file = NULL;
  c->wlan_offset = RT_OFFSET_UNKNOWN;
  c->flags_offset = RT_OFFSET_UNKNOWN;
  c->channel_offset = RT_OFFSET_UNKNOWN;
  c->signal_offset = RT_OFFSET_UNKNOWN;
  c->tstamp_mode = TS_UNSET;
  c->min_signal = SIGNAL_MIN_DBM;
  c->exclude[0] = '\0';

  char *ifname = NULL, *host = NULL, *port = NULL;
  unsigned ssid_len;
  unsigned exclude_pos = 0;

  int opt;
  while ((opt = getopt(argc, argv, "-d:i:r:p:t:x:ehV")) >= 0) {
    switch (opt) {
      case 'h':
        usage(stdout, argv[0]);
        return 0;
      case 'V':
        printf("proberelay " VERSION VERSION_EXTRA " built " BUILD_TIME "\n");
        return 0;
      case 'e':
        c->log_file = stderr;
        break;
      case 'i':
        if (ifname == NULL) {
          ifname = optarg;
        } else {
          fprintf(stderr, "Multiple `-%c` options not supported!\n", opt);
          return -1;
        }
        break;
      case 'd':
        if (host == NULL) {
          host = optarg;
        } else {
          fprintf(stderr, "Multiple `-%c` options not supported!\n", opt);
          return -1;
        }
        break;
      case 'p':
        if (port == NULL) {
          port = optarg;
        } else {
          fprintf(stderr, "Multiple `-%c` options not supported!\n", opt);
          return -1;
        }
        break;
      case 'r':
        if (c->min_signal == SIGNAL_MIN_DBM) {
          c->min_signal = atoi(optarg);
          debugp("min signal: %d", c->min_signal);
          if (c->min_signal < -127 || c->min_signal > 255) {
            fprintf(stderr, "Value for `-%c` must be -127 to 255, not %d!\n", opt, c->min_signal);
            return -1;
          }
        } else {
          fprintf(stderr, "Multiple `-%c` options not supported!\n", opt);
          return -1;
        }
        break;
      case 't':
        if (c->tstamp_mode == TS_UNSET) {
          if (strcmp("kernel", optarg) == 0) {
            c->tstamp_mode = TS_KERNEL;
          } else if (strcmp("system", optarg) == 0) {
            c->tstamp_mode = TS_SYSTEM;
          } else if (strcmp("coarse", optarg) == 0) {
            c->tstamp_mode = TS_COARSE;
          } else if (strcmp("none", optarg) == 0) {
            c->tstamp_mode = TS_NONE;
          } else {
            fprintf(stderr, "Invalid timestamp mode: `%s`\n", optarg);
            return -1;
          }
        } else {
          fprintf(stderr, "Multiple `-%c` options not supported!\n", opt);
          return -1;
        }
        break;
      case 'x':
        ssid_len = strlen(optarg);
        if (ssid_len > 32) {
          fprintf(stderr, "SSID exceeds 32 byte limit: `%s` (%u bytes)\n", optarg, ssid_len);
          return -1;
        } else if (exclude_pos + 1 + ssid_len + 1 >= sizeof(c->exclude)) {
          fprintf(stderr, "No space left in SSID exclusion list! %u %u %zu\n", exclude_pos, ssid_len, sizeof(c->exclude));
          return -1;
        }

        // append ssid
        c->exclude[exclude_pos++] = ssid_len;
        memcpy(c->exclude + exclude_pos, optarg, ssid_len);
        exclude_pos += ssid_len;
        c->exclude[exclude_pos] = '\0';
        break;
      default:
        if (opt == '\1') {
          fprintf(stderr, "bad argument: `%s`\n", optarg);
        } else {
          fprintf(stderr, "unknown flag: `%c`\n", opt);
        }
        return -1;
    }
  }

  if (ifname == NULL || host == NULL) {
    usage(stderr, argv[0]);
    return -1;
  }

  // default arguments
  if (port == NULL) { port = "26737"; }
  if (c->tstamp_mode == TS_UNSET) { c->tstamp_mode = TS_KERNEL; }

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
    snprintf(dststr, sizeof(dststr), "%s:%u", addrstr, ntohs(sin->sin_port));
  } else if (ai->ai_family == AF_INET6) {
    c->snaplen = MTU - (IP6_HDR_LEN + UDP_HDR_LEN + sizeof(struct header_s));
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ai->ai_addr;
    inet_ntop(AF_INET6, &sin6->sin6_addr, addrstr, sizeof(addrstr));
    snprintf(dststr, sizeof(dststr), "[%s]:%u", addrstr, ntohs(sin6->sin6_port));
  } else {
    fprintf(stderr, "Unexpected address family: %d\n", ai->ai_family);
    return -1;
  }

  if (open_capture(c, ifname) != 0) {
    fprintf(stderr, "Failed to start capture on %s!\n", ifname);
    return -1;
  } else {
    printf("Forwarding from %s to %s, capture size %u bytes\n", ifname, dststr, c->snaplen);
  }

  if (droproot() != 0) {
    fprintf(stderr, "Failed to drop root!\n");
    return -1;
  }

  return relay(c);
}
