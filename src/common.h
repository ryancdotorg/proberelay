/* SPDX-License-Identifier: BSD-3-Clause
Copyright ©2024 Ryan Castellucci, some rights reserved. */
#pragma once

#define MTU 1500

#define IP4_HDR_LEN 20
#define IP6_HDR_LEN 40
#define UDP_HDR_LEN  8

#define MIN(A, B) ((A) < (B) ? (A) : (B))
#define MAX(A, B) ((A) > (B) ? (A) : (B))
