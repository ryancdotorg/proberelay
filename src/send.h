/* SPDX-License-Identifier: BSD-3-Clause
Copyright ©2023 Ryan Castellucci, some rights reserved.
gcc -O2 -std=c11 -Wall -Wextra -pedantic proberelay.c -lpcap -o proberelay #*/

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>

#include <sys/time.h>

#define PCAP_MAGIC_MICRO 0xA1B2C3D4
#define PCAP_MAGIC_NANO  0xA1B23C4D

/* 40 bytes - this is a pcap file header plus a packet record header */
struct header_s {
  /* PCAP FILE HEADER */
  /*  0 */ uint32_t  magic_number;
  /*  4 */ uint16_t  version_major;
  /*  6 */ uint16_t  version_minor;
  /*  8 */ int32_t   thiszone;
  /* 12 */ uint32_t  sigfigs;
  /* 16 */ uint32_t  snaplen;
  /* 20 */ uint8_t   fcs;
  /* 21 */ uint8_t   pad0;
  /* 22 */ uint16_t  linktype;
  /* PCAP PACKET RECORD */
  /* 24 */ uint32_t  ts_sec;
  /* 28 */ uint32_t  ts_usec;
  /* 32 */ uint32_t  incl_len;
  /* 36 */ uint32_t  orig_len;
  /* PCAP PACKET DATA */
  /* 40 */ uint8_t   data[];
};
