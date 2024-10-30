/* SPDX-License-Identifier: BSD-3-Clause
Copyright ©2024 Ryan Castellucci, some rights reserved. */
#pragma once

#include <stdint.h>
#include <netdb.h>

#include <sys/socket.h>
#include <sys/types.h>

#ifndef NDEBUG
#include "debugp.h"
#else
#define debugp(...) do {} while (0)
#endif

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

#define TS_UNSET   0
#define TS_KERNEL  1
#define TS_SYSTEM  2
#define TS_COARSE  3
#define TS_NONE    4

#define RT_OFFSET_UNKNOWN -1
#define RT_OFFSET_NONE -2
#define RT_OFFSET_ERROR -3

#define SIGNAL_MIN_DBM -128
#define SIGNAL_MIN_DB 0

#define MIN(A, B) ((A) < (B) ? (A) : (B))
#define MAX(A, B) ((A) > (B) ? (A) : (B))

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
  const char *ifname;
  struct addrinfo *ai;
  int cap_fd;
  int dst_fd;
  int linktype;
  int wlan_offset;
  int flags_offset;
  int channel_offset;
  int signal_offset;
  int tstamp_mode;
  int min_signal;
  uint32_t snaplen;
  uint8_t exclude[1024];
};
