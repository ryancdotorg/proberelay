/* SPDX-License-Identifier: BSD-3-Clause
Copyright ©2024 Ryan Castellucci, some rights reserved. */

#include <stdio.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <linux/filter.h>
#ifndef ARPHRD_IEEE80211_RADIOTAP
#include <linux/if_arp.h>
#endif

#include "radiotap.h"

#include "common.h"

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

// indirection expands arguments
#define RT_FIELD_CHECK(...) _RT_FIELD_CHECK(__VA_ARGS__)
#define _RT_FIELD_CHECK(N, W, A) { \
  unsigned _n = (N); \
  if (field == _n) break; \
  if (it_present & (1 << _n)) { \
    field_offset += W + (A - 1); \
    field_offset &= ~(A - 1); \
  } \
}

static int rt_field_offset(const uint8_t *pkt, unsigned field) {
  int field_offset = RT_OFFSET_NONE, p = 1;
  uint32_t *radiotap = (uint32_t *)pkt;
  uint32_t it_present = le32toh(radiotap[p]);

  // check whether the field bit is set in the it_present bitmask
  if (it_present & (1 << field)) {
    // high bit indicates another it_present bitmask
    while (le32toh(radiotap[p]) & (1<<31)) { ++p; }

    field_offset = 4 + 4 * p;

    do {
      RT_FIELD_CHECK(RT_TSFT_PARAMS);
      RT_FIELD_CHECK(RT_FLAGS_PARAMS);
      RT_FIELD_CHECK(RT_RATE_PARAMS);
      RT_FIELD_CHECK(RT_CHANNEL_PARAMS);
      RT_FIELD_CHECK(RT_FHSS_PARAMS);
      RT_FIELD_CHECK(RT_DBM_SIGNAL_PARAMS);
      RT_FIELD_CHECK(RT_DBM_NOISE_PARAMS);
      RT_FIELD_CHECK(RT_LOCK_QUALITY_PARAMS);
      RT_FIELD_CHECK(RT_TX_ATTENUATION_PARAMS);
      RT_FIELD_CHECK(RT_DB_TX_ATTENUATION_PARAMS);
      RT_FIELD_CHECK(RT_DBM_TX_POWER_PARAMS);
      RT_FIELD_CHECK(RT_ANTENNA_PARAMS);
      RT_FIELD_CHECK(RT_DB_SIGNAL_PARAMS);
      RT_FIELD_CHECK(RT_DB_NOISE_PARAMS);
      RT_FIELD_CHECK(RT_RX_FLAGS_PARAMS);
      RT_FIELD_CHECK(RT_TX_FLAGS_PARAMS);
      RT_FIELD_CHECK(RT_RTS_RETRIES_PARAMS);
      RT_FIELD_CHECK(RT_DATA_RETRIES_PARAMS);
      RT_FIELD_CHECK(RT_XCHANNEL_PARAMS);
      RT_FIELD_CHECK(RT_MCS_PARAMS);
      RT_FIELD_CHECK(RT_A_MPDU_STATUS_PARAMS);
      RT_FIELD_CHECK(RT_VHT_PARAMS);
      RT_FIELD_CHECK(RT_TIMESTAMP_PARAMS);
      RT_FIELD_CHECK(RT_HE_PARAMS);
      RT_FIELD_CHECK(RT_HE_MU_PARAMS);
      RT_FIELD_CHECK(RT_HE_MU_OTHER_USER_PARAMS);
      RT_FIELD_CHECK(RT_ZERO_LENGTH_PSDU_PARAMS);
      RT_FIELD_CHECK(RT_L_SIG_PARAMS);

      return RT_OFFSET_ERROR;
    } while (0);

    printf("Found radiotap field %u offset: %d\n", field, field_offset);
  }

  return field_offset;
}

static inline int attach_filter(int fd, struct sock_fprog *prog) {
  return setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, prog, sizeof(struct sock_fprog));
}

// wrapper to attach a filter without leaking unfiltered packets
// https://natanyellin.com/posts/ebpf-filtering-done-right/
static int apply_filter(struct capture_s *c, struct sock_fprog *prog) {
  // drop all
  struct sock_fprog drop = { 1, &(struct sock_filter){ BPF_RET, 0, 0, 0 } };

  if (attach_filter(c->cap_fd, &drop) < 0) {
    perror("setsockopt (attach drop)");
    return -1;
  }

  // read until we get an error meaing no more data to read
  for (int n = 0; n >= 0; n = recv(c->cap_fd, (void *)&drop, 1, MSG_DONTWAIT)) {}

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

  if (attach_filter(c->cap_fd, prog) < 0) {
    perror("setsockopt (attach filter)");
    return -1;
  }

  return 0;
}

static inline void set_inst(struct sock_filter *filter, int n, uint16_t code, uint8_t jt, uint8_t jf, uint32_t k) {
  filter[n].code = code;
  filter[n].jt = jt;
  filter[n].jf = jf;
  filter[n].k = k;
}

int calc_filter(struct capture_s *c, const uint8_t *pkt, size_t pkt_sz) {
  struct sock_filter filter[11];
  struct sock_fprog prog = { .len = 0, .filter = filter };

  // is there a radiotap header?
  if (c->linktype == DLT_IEEE802_11_RADIO) {
    // per radiotap spec
    c->wlan_offset = le16toh(*((uint16_t *)(pkt + 2)));

    // find the flags offset (if present)
    c->flags_offset = rt_field_offset(pkt, RT_FLAGS);

    // find the channel offset (if present)
    c->channel_offset = rt_field_offset(pkt, RT_CHANNEL);

    // find the signal offset (if present);
    do {
      if (c->min_signal < 0) {
        // if the value is negative, we're comparing against dBm
        if ((c->signal_offset = rt_field_offset(pkt, RT_DBM_SIGNAL)) >= 0) {
          break;
        } else if (c->min_signal == SIGNAL_MIN_DBM) {
          // a minimum signal wasn't specified, so indicate dB
          c->min_signal = SIGNAL_MIN_DB;
        } else {
          break;
        }
      }

      // at this point, c->min_signal must be non-negative, so look at dB
      c->signal_offset = rt_field_offset(pkt, RT_DB_SIGNAL);
    } while(0);
  } else {
    c->wlan_offset = 0;
    c->flags_offset = RT_OFFSET_NONE;
    c->signal_offset = RT_OFFSET_NONE;
  }

  int jflg, jsig;
  if (c->flags_offset < 0) {
    fprintf(stderr, "FCS flag not available.\n");
    jflg = 0;
  } else {
    jflg = 2;
  }

  if (c->min_signal == SIGNAL_MIN_DBM || c->min_signal == SIGNAL_MIN_DB) {
    jsig = 0;
  } else if (c->signal_offset < 0) {
    fprintf(stderr, "Signal not available.\n");
    jsig = 0;
  } else {
    jsig = 2;
  }



  if (c->min_signal != SIGNAL_MIN_DBM && c->signal_offset < 0) {
    fprintf(stderr, "Unable to filter on signal.\n");
    jsig = 0;
  } else {
    jsig = 2;
  }

  int i = 0;

  // ldb[c->wlan_offset]        ; load first byte of frame control
  // BPF_LD | BPF_B | BPF_ABS
  set_inst(filter, i++, 0x30, 0, 0, c->wlan_offset);
  // jne #0x40, drop            ; drop everything except probe requests
  // BPF_JMP | BPF_JEQ
  set_inst(filter, i++, 0x15, 0, jsig + jflg + 4, 0x40);
  // ldh[c->wlan_offset + 24]   ; type and length of first probe request TLV
  // BPF_LD | BPF_H | BPF_ABS
  set_inst(filter, i++, 0x28, 0, 0, c->wlan_offset + 24);
  // sub #1                     ; type needs to be 0, length 1-32
  // BPF_ALU | BPF_SUB
  set_inst(filter, i++, 0x14, 0, 0, 1);
  // jset #0xffe0, drop         ; bad type and/or length if any of these are
  // BPF_JMP | BPF_JSET
  set_inst(filter, i++, 0x45, jsig + jflg + 1, 0, 0xffe0);
  if (jsig > 0) {
    // ldb [c->signal_offset]   ; radiotap signal byte
    // BPF_LD | BPF_B | BPF_ABS
    set_inst(filter, i++, 0x30, 0, 0, c->signal_offset);
    // jlt #c->min_signal, drop ; drop if less than specified signal
    // BPF_JMP | BPF_JGE
    set_inst(filter, i++, 0x35, 0, jflg + 1, c->min_signal & 0xff);
  }
  if (jflg > 0) {
    // ldb [c->flags_offset]    ; radiotap flags byte
    // BPF_LD | BPF_B | BPF_ABS
    set_inst(filter, i++, 0x30, 0, 0, c->flags_offset);
    // jset #0x40, drop         ; drop if frame failed FCS check
    // BPF_JMP | BPF_JSET
    set_inst(filter, i++, 0x45, 1, 0, 0x40);
  }
  // accept: ret c->snaplen     ; truncate to snaplen
  // BPF_RET
  set_inst(filter, i++, 0x06, 0, 0, c->snaplen);
  // drop: ret #0               ; drop the packet
  // BPF_RET
  set_inst(filter, i++, 0x06, 0, 0, 0);

  prog.len = i;

  if (apply_filter(c, &prog) < 0) {
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

int get_channel(struct capture_s *c, const uint8_t *pkt) {
  if (c->channel_offset < 0) { return 0; }

  uint16_t freq = le16toh(*((uint16_t *)(pkt + c->channel_offset)));

  if      (2412 <= freq && freq <= 2472) { return (freq - 2407) / 5; }
  else if (5100 <= freq && freq <= 5920) { return (freq - 5000) / 5; }
  else if (2484 == freq) { return 14; }
  else { return freq; }
}

int get_signal(struct capture_s *c, const uint8_t *pkt) {
  if (c->signal_offset < 0) { return 0; }

  // c->min_signal is non-negative if dB values are being used
  if (c->min_signal < 0) {
    return (int8_t)(pkt[c->signal_offset]);
  } else {
    return (uint8_t)(pkt[c->signal_offset]);
  }
}
