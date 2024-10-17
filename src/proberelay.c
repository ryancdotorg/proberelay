/* SPDX-License-Identifier: BSD-3-Clause
Copyright ©2024 Ryan Castellucci, some rights reserved.
gcc -Os -std=gnu17 -Wall -Wextra -pedantic proberelay_nopcap.c -o proberelay_nopcap #*/

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
#include <endian.h>
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

#ifndef NDEBUG
#include "debugp.h"
#else
#define debugp(...) do {} while (0)
#endif

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

#define SIGNAL_NONE -128

#define RT_OFFSET_UNKNOWN -1
#define RT_OFFSET_NONE -2

#define TS_UNSET   0
#define TS_KERNEL  1
#define TS_SYSTEM  2
#define TS_COARSE  3
#define TS_NONE    4

#define MTU 1500

#define IP4_HDR_LEN 20
#define IP6_HDR_LEN 40
#define UDP_HDR_LEN  8

#define PCAP_MAGIC_MICRO 0xA1B2C3D4
#define PCAP_MAGIC_NANO  0xA1B23C4D

#ifdef PCAP_USE_MICRO
#define PCAP_MAGIC PCAP_MAGIC_MICRO
// convert nanoseconds to microseconds
#define TS_SCALE(X) ((X) / 1000)
#else
#define PCAP_MAGIC PCAP_MAGIC_NANO
#define TS_SCALE(X) (X)
#endif

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

static int so_tstamp = SO_TIMESTAMPING_NEW;

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
  int cap_fd;
  int dst_fd;
  int linktype;
  int filter_state;
  int wlan_offset;
  int flags_offset;
  int signal_offset;
  int tstamp_mode;
  int min_signal;
  uint32_t snaplen;
  uint8_t exclude[1024];
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

static int rt_flags_offset(const uint8_t *pkt) {
  int flags_offset = RT_OFFSET_NONE, p = 1;
  uint32_t *radiotap = (uint32_t *)pkt;
  uint32_t it_present = le32toh(radiotap[p]);

  // check whether bit 1 (flags) is set in the it_present bitmask
  if (it_present & (1<<1)) {
    // check whether bit 0 (tsft) is set in the it_present bitmask
    bool has_tsft = it_present & (1<<0);

    // high bit indicates another it_present bitmasks
    while (it_present & (1<<31)) {
      it_present = le32toh(radiotap[++p]);
    }
    // end of it_present bitmasks

    flags_offset = 4 + 4 * p;
    // tsft is 8 bytes and must be aligned to a multiple of 8 bytes
    if (has_tsft) flags_offset = (flags_offset + 15) & (~7);
    printf("Found radiotap flags offset: %d\n", flags_offset);
  }

  return flags_offset;
}

static int rt_signal_offset(const uint8_t *pkt) {
  int signal_offset = RT_OFFSET_NONE, p = 1;
  uint32_t *radiotap = (uint32_t *)pkt;
  uint32_t it_present = le32toh(radiotap[p]);

  // check whether bit 5 (antenna signal) is set in the it_present bitmask
  if (it_present & (1<<5)) {
    // check whether bit 0 (tsft) is set in the it_present bitmask
    bool has_tsft = it_present & (1<<0);
    bool has_flags = it_present & (1<<1);
    bool has_rate = it_present & (1<<2);
    bool has_channel = it_present & (1<<3);
    bool has_fhss = it_present & (1<<4);

    // high bit indicates another it_present bitmasks
    while (it_present & (1<<31)) {
      it_present = le32toh(radiotap[++p]);
    }
    // end of it_present bitmasks

    signal_offset = 4 + 4 * p;

    // tsft is 8 bytes and must be aligned to a multiple of 8 bytes
    if (has_tsft) signal_offset = (signal_offset + 15) & (~7);
    // flags is 1 byte
    if (has_flags) signal_offset = (signal_offset + 1);
    // rate is 1 byte
    if (has_rate) signal_offset = (signal_offset + 1);
    // channel is 4 bytes and must be aligned to a multiple of 2 bytes
    if (has_channel) signal_offset = (signal_offset + 5) & (~1);
    // fhss is 2 bytes
    if (has_fhss) signal_offset = (signal_offset + 1);
    printf("Found radiotap signal offset: %d\n", signal_offset);
  }

  return signal_offset;
}

static int attach_filter(struct capture_s *c, struct sock_fprog *prog) {
#ifndef NDEBUG
  fprintf(stderr, "%u,", prog->len);
  for (unsigned i = 0; i < prog->len; ++i) {
    fprintf(
      stderr, "%u %u %u %u,",
      prog->filter[i].code, prog->filter[i].jt,
      prog->filter[i].jf, prog->filter[i].k
    );
  }
  fprintf(stderr, "\n");
#endif

  if (setsockopt(c->cap_fd, SOL_SOCKET, SO_ATTACH_FILTER, prog, sizeof(struct sock_fprog)) < 0) {
    perror("setsockopt (attach filter)");
    return -1;
  }

  return 0;
}

static int one_filter(struct capture_s *c) {
  // truncate the packet to one byte
  struct sock_filter filter[] = { { 0x06, 0, 0, 1} };
  struct sock_fprog prog = { .len = 1, .filter = filter };

  return attach_filter(c, &prog);
}

static int slow_filter(struct capture_s *c) {
  uint32_t min_signal = c->min_signal & 0xff;

  struct sock_filter filter[] = {
    BPF_INST(  0, 0x30,   0,   0, 0x00000003), // ldb [3]                     ; high byte of it_len
    BPF_INST(  1, 0x64,   0,   0, 0x00000008), // lsh #8                      ; left shift into place
    BPF_INST(  2, 0x07,   0,   0, 0x00000000), // tax                         ; save it
    BPF_INST(  3, 0x30,   0,   0, 0x00000002), // ldb [2]                     ; low byte of it_len
    BPF_INST(  4, 0x0c,   0,   0, 0x00000000), // add x                       ; calculate radiotap header len
    BPF_INST(  5, 0x07,   0,   0, 0x00000000), // tax                         ; only x can be used as an offset
    BPF_INST(  6, 0x50,   0,   0, 0x00000000), // ldb [x + 0]                 ; load first byte of frame control
    BPF_INST(  7, 0x15,   0,  57, 0x00000040), // jne #0x40, drop             ; drop everything except probe requests
    BPF_INST(  8, 0x48,   0,   0, 0x00000018), // ldh [x + 24]                ; type and length of first probe request TLV
    BPF_INST(  9, 0x14,   0,   0, 0x00000001), // sub #1                      ; type needs to be 0, length 1-32
    BPF_INST( 10, 0x45,  57,   0, 0x0000ffe0), // jset #0xffe0, drop          ; bad type and/or length if any of these are set
    BPF_INST( 11, 0x01,   0,   0, 0x00000008), // ldx #8                      ; set base data offset for radiotap header fields
    BPF_INST( 12, 0x30,   0,   0, 0x00000007), // ldb [7]                     ; high byte of it_present
    BPF_INST( 13, 0x45,   0,  23, 0x00000080), // jset #0x80, mb1, nmb        ; more bits?
    BPF_INST( 14, 0x01,   0,   0, 0x0000000c), // mb1: ldx #12                ; set base data offset
    BPF_INST( 15, 0x30,   0,   0, 0x0000000b), // ldb [11]                    ; high byte of second it_present
    BPF_INST( 16, 0x45,   0,  23, 0x00000080), // jset #0x80, mb2, nmb        ; more bits?
    BPF_INST( 17, 0x01,   0,   0, 0x00000010), // mb2: ldx #16                ; set base data offset
    BPF_INST( 18, 0x30,   0,   0, 0x0000000f), // ldb [15]                    ; high byte of third it_present
    BPF_INST( 19, 0x45,   0,  23, 0x00000080), // jset #0x80, mb3, nmb        ; more bits?
    BPF_INST( 20, 0x01,   0,   0, 0x00000014), // mb3: ldx #20                ; set base data offset
    BPF_INST( 21, 0x30,   0,   0, 0x00000013), // ldb [19]                    ; high byte of fourth it_present
    BPF_INST( 22, 0x45,  57,   0, 0x00000080), // jset #0x80, drop, nmb       ; too many bits!
    BPF_INST( 23, 0x30,   0,   0, 0x00000004), // nmb: ldb [4]                ; low byte of first it_present
    BPF_INST( 24, 0x45,   0,  30, 0x00000001), // jset #0x01, b0t, b0f        ; tsfn present?
    BPF_INST( 25, 0x87,   0,   0, 0x00000000), // b0t: txa                    ; get data offset
    BPF_INST( 26, 0x04,   0,   0, 0x0000000f), // add #15                     ; tsfn is 8 bytes, with 8 byte aligment
    BPF_INST( 27, 0x54,   0,   0, 0xfffffff8), // and #0xfffffff8             ; mask to alignment
    BPF_INST( 28, 0x07,   0,   0, 0x00000000), // tax                         ; update data offset
    BPF_INST( 29, 0x30,   0,   0, 0x00000004), // ldb [4]                     ; low byte of first it_present
    BPF_INST( 30, 0x45,   0,  37, 0x00000002), // b0f: jset #0x02, b1t, b1f   ; flags present?
    BPF_INST( 31, 0x50,   0,   0, 0x00000000), // b1t: ldb [x + 0]            ; load flags byte
    BPF_INST( 32, 0x45,  57,   0, 0x00000040), // jset #0x40, drop            ; drop if frame failed FCS check
    BPF_INST( 33, 0x87,   0,   0, 0x00000000), // txa                         ; load data offset
    BPF_INST( 34, 0x04,   0,   0, 0x00000001), // add #1                      ; flags is 1 byte
    BPF_INST( 35, 0x07,   0,   0, 0x00000000), // tax                         ; update data offset
    BPF_INST( 36, 0x30,   0,   0, 0x00000004), // ldb [4]                     ; low byte of first it_present
    BPF_INST( 37, 0x45,   0,  42, 0x00000004), // b1f: jset #0x04, b2t, b2f   ; rate present?
    BPF_INST( 38, 0x87,   0,   0, 0x00000000), // b2t: txa                    ; get data offset
    BPF_INST( 39, 0x04,   0,   0, 0x00000001), // add #1                      ; rate is 1 byte
    BPF_INST( 40, 0x07,   0,   0, 0x00000000), // tax                         ; update data offset
    BPF_INST( 41, 0x30,   0,   0, 0x00000004), // ldb [4]                     ; low byte of first it_present
    BPF_INST( 42, 0x45,   0,  48, 0x00000008), // b2f: jset #0x08, b3t, b3f   ; channel present?
    BPF_INST( 43, 0x87,   0,   0, 0x00000000), // b3t: txa                    ; get data offset
    BPF_INST( 44, 0x04,   0,   0, 0x00000005), // add #5                      ; channel isis 4 bytes, with 2 byte alignment
    BPF_INST( 45, 0x54,   0,   0, 0xfffffffe), // and #0xfffffffe             ; mask to alignment
    BPF_INST( 46, 0x07,   0,   0, 0x00000000), // tax                         ; update data offset
    BPF_INST( 47, 0x30,   0,   0, 0x00000004), // ldb [4]                     ; low byte of first it_present
    BPF_INST( 48, 0x45,   0,  53, 0x00000010), // b3f: jset #0x10, b4t, b4f   ; fhss present?
    BPF_INST( 49, 0x87,   0,   0, 0x00000000), // b4t: txa                    ; get data offset
    BPF_INST( 50, 0x04,   0,   0, 0x00000002), // add #2                      ; fhss  2 bytes
    BPF_INST( 51, 0x07,   0,   0, 0x00000000), // tax                         ; update data offset
    BPF_INST( 52, 0x30,   0,   0, 0x00000004), // ldb [4]                     ; low byte of first it_present
    BPF_INST( 53, 0x45,   0,  56, 0x00000020), // b4f: jset #0x20, b5t, accept; signal present?
    BPF_INST( 54, 0x50,   0,   0, 0x00000000), // b5t: ldb [x + 0]            ; load signal byte
    BPF_INST( 55, 0x25,   0,  57, min_signal), // jle #0xc3, drop             ; drop if signal below threshold
    BPF_INST( 56, 0x06,   0,   0, 0x00040000), // accept: ret #262144         ; truncate to snaplen
    BPF_INST( 57, 0x06,   0,   0, 0x00000000), // drop: ret #0                ; drop the packet
  };

  struct sock_fprog prog = {
    .len = sizeof(filter)/sizeof(filter[0]),
    .filter = filter
  };

  return attach_filter(c, &prog);
}

static inline void set_inst(struct sock_filter *filter, int n, uint16_t code, uint8_t jt, uint8_t jf, uint32_t k) {
  filter[n].code = code;
  filter[n].jt = jt;
  filter[n].jf = jf;
  filter[n].k = k;
}

static int fast_filter(struct capture_s *c, const uint8_t *pkt, size_t pkt_sz) {
  struct sock_filter filter[11];
  struct sock_fprog prog = { .len = 0, .filter = filter };

  // is there a radiotap header?
  if (c->linktype == DLT_IEEE802_11_RADIO) {
    // per radiotap spec
    c->wlan_offset = le16toh(*((uint16_t *)(pkt + 2)));
    printf("Found radiotap header length: %d\n", c->wlan_offset);
    // find the flags offset (if present)
    c->flags_offset = rt_flags_offset(pkt);
    // find the signal offset (if present);
    c->signal_offset = rt_signal_offset(pkt);
  } else {
    c->wlan_offset = 0;
    c->flags_offset = RT_OFFSET_NONE;
    c->signal_offset = RT_OFFSET_NONE;
  }

  int i = 0;
  int jflg = c->flags_offset >= 0 ? 2 : 0;
  int jsig = (c->min_signal != SIGNAL_NONE && c->signal_offset >= 0) ? 2 : 0;

  // ldb[c->wlan_offset]        ; load first byte of frame control
  set_inst(filter, i++, 0x30, 0, 0, c->wlan_offset);
  // jne #0x40, drop            ; drop everything except probe requests
  set_inst(filter, i++, 0x15, 0, jsig + jflg + 4, 0x40);
  // ldh[c->wlan_offset + 24]   ; type and length of first probe request TLV
  set_inst(filter, i++, 0x28, 0, 0, c->wlan_offset + 24);
  // sub #1                     ; type needs to be 0, length 1-32
  set_inst(filter, i++, 0x14, 0, 0, 1);
  // jset #0xffe0, drop         ; bad type and/or length if any of these are
  set_inst(filter, i++, 0x45, jsig + jflg + 1, 0, 0xffe0);
  if (jsig > 0) {
    // ldb [c->signal_offset]   ; radiotap signal byte
    set_inst(filter, i++, 0x30, 0, 0, c->signal_offset);
    // jlt #c->min_signal, drop ; drop if less than specified signal
    set_inst(filter, i++, 0x35, 0, jflg + 1, c->min_signal & 0xff);
  }
  if (jflg > 0) {
    // ldb [c->flags_offset]    ; radiotap flags byte
    set_inst(filter, i++, 0x30, 0, 0, c->flags_offset);
    // jset #0x40, drop         ; drop if frame failed FCS check
    set_inst(filter, i++, 0x45, 1, 0, 0x40);
  }
  // accept: ret c->snaplen     ; truncate to snaplen
  set_inst(filter, i++, 0x06, 0, 0, c->snaplen);
  // drop: ret #0               ; drop the packet
  set_inst(filter, i++, 0x06, 0, 0, 0);

  prog.len = i;

  if (attach_filter(c, &prog) < 0) {
    return -1;
  }

  int lock = 1;
  if (setsockopt(c->cap_fd, SOL_SOCKET, SO_LOCK_FILTER, &lock, sizeof(lock)) < 0) {
    perror("setsockopt (lock filter)");
    return -1;
  }

  // return packet length
  return MAX(c->snaplen, pkt_sz);
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

static ssize_t read_raw(struct capture_s *c, uint8_t *buf, size_t buf_sz) {
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
    fprintf(stderr, "bogus packet length: %zd\n", orig_len);
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

void send_packet(struct capture_s *c, const uint8_t *buf) {
  const struct header_s *h = (struct header_s *)buf;

  // send the packet
  if (h->incl_len) {
    ssize_t len = sizeof(struct header_s) + h->incl_len;
    ssize_t n = sendto(c->dst_fd, buf, len, 0, c->ai->ai_addr, c->ai->ai_addrlen);
    if (n != len) { perror("sendto"); }
  }
}

void handle_packet(struct capture_s *c, uint8_t *buf, size_t buf_sz) {
  struct header_s *h = (struct header_s *)buf;
  uint8_t *pkt = h->packet;
  size_t pkt_sz = buf_sz - sizeof(struct header_s);

#ifndef NDEBUG
  fprintf(stderr, "got packet: ");
  for (unsigned i = 0; i < h->incl_len; ++i) {
    fprintf(stderr, "%02x", pkt[i]);
  }
  fprintf(stderr, " (%u octets)\n", h->incl_len);
#endif

  /* Even if a filter is set before the socket is bound to an interface,
   * some packets still "leak" initially. We address this by setting an
   * initial "filter" the accepts all packets, but truncates them to a single
   * byte. Since no actual packets can be this small, this tells us that the
   * filter is filtering, and we can set the "slow" filter.
   *
   * The slow filter parses the radiotap header in bpf which is rather
   * tedious. When we get the first normal sized packet, we use it to
   * initialize the "fast" filter, which computes and inlines the offsets we
   * need to look at.
   */
  if (c->filter_state != 2) {
    if ((c->filter_state == 1 && h->incl_len > 1) || c->linktype == DLT_IEEE802_11) {
      debugp("setting fast filter");
      if (fast_filter(c, pkt, pkt_sz) < 0) { exit(-1); }
      c->filter_state = 2;
    } else if (c->filter_state == 0) {
      if (h->incl_len == 1) {
        debugp("setting slow filter");
        if (slow_filter(c) < 0) { exit(-1); }
        c->filter_state = 1;
      }

      return;
    } else {
      debugp("waiting for slow filter to activate");
      return;
    }
  }

  // are we filtering on ssid?
  if (c->exclude[0] > 0 && pkt[c->wlan_offset] == 0x40) {
    unsigned exclude_len, exclude_pos = 0;
    uint8_t *ssid = pkt + c->wlan_offset + 25;

#ifndef NDEBUG
    uint8_t ssid_buf[33];
    memcpy(ssid_buf, ssid + 1, ssid[0]);
    ssid_buf[ssid[0]] = '\0';
    fprintf(stderr, "Check SSID: `%s` (%u octets)\n", ssid_buf, ssid[0]);
#endif

    while ((exclude_len = c->exclude[exclude_pos]) > 0) {

      if (memcmp(ssid, c->exclude + exclude_pos, exclude_len + 1) == 0) {
#ifndef NDEBUG
        uint8_t exclude_buf[33];
        memcpy(exclude_buf, c->exclude + exclude_pos + 1, exclude_len);
        exclude_buf[exclude_len] = '\0';
        fprintf(stderr, "Excluded SSID: `%s` (%u octets)\n", exclude_buf, exclude_len);
#endif
        return;
      }

      exclude_pos += exclude_len + 1;
    }
  }

#ifndef NDEBUG
  debugp("send packet %p %p\n", (void *)c, buf);
#endif
  send_packet(c, buf);
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

  if (one_filter(c) < 0) {
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

  if (c->tstamp_mode == TS_KERNEL) {
    if (timestamping(c->cap_fd, false) < 0) {
      return -1;
    }
  }

  if (ifbind(c->cap_fd, idx) < 0) {
    return -1;
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
          handle_packet(c, buf, sizeof(buf));
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
    "  -r SIGNAL                         minimum signal strength (-127 to -1)\n"
    "  -t kernel|system|coarse|none      timestamp type (default: kernel)\n"
    , argv0
  );
}

int main(int argc, char *argv[]) {
  struct addrinfo hints, *res, *ai;
  struct capture_s c[] = {0};

  c->filter_state = 0;
  c->wlan_offset = RT_OFFSET_UNKNOWN;
  c->flags_offset = RT_OFFSET_UNKNOWN;
  c->signal_offset = RT_OFFSET_UNKNOWN;
  c->tstamp_mode = TS_UNSET;
  c->min_signal = SIGNAL_NONE;
  c->exclude[0] = '\0';

  char *ifname = NULL, *host = NULL, *port = NULL;
  unsigned ssid_len;
  unsigned exclude_pos = 0;

  int opt;
  while ((opt = getopt(argc, argv, "-d:i:r:p:t:x:hV")) >= 0) {
    switch (opt) {
      case 'h':
        usage(stdout, argv[0]);
        return 0;
      case 'V':
        printf("proberelay " VERSION VERSION_EXTRA " built " BUILD_TIME "\n");
        return 0;
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
        if (c->min_signal == SIGNAL_NONE) {
          c->min_signal = atoi(optarg);
          debugp("min signal: %d", c->min_signal);
          if (c->min_signal < -127 || c->min_signal > -1) {
            fprintf(stderr, "Value for `-%c` must be -127 to -1, not %d!\n", opt, c->min_signal);
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
