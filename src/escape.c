#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "bnprintf.h"
#include "debugp.h"
#include "utf8d.h"

int json_escape(char *dst, size_t dst_sz, const uint8_t *src, size_t src_sz) {
  size_t n = dst_sz;
  uint32_t utf8_state = 0;
  uint32_t utf8_codep = 0;
  uint8_t lookback[] = {0,0,0,0};
  uint8_t *ptr = lookback;
  for (size_t p = 0; p < src_sz; ++p) {
    uint8_t c = src[p];

    utf8_decode(&utf8_state, &utf8_codep, c);
    if (utf8_state == UTF8_ACCEPT) {
      debugp("%3zu:%02x state: %2u codep:%7u U+%04X %p\n", p, c, utf8_state, utf8_codep, utf8_codep, dst);
    } else {
      debugp("%3zu:%02x state: %2u codep:%7u        %p\n", p, c, utf8_state, utf8_codep, dst);
    }
    if (utf8_state == UTF8_ACCEPT) {
      ptr = lookback;
      if (utf8_codep <= 0x7F) {
        switch (c) {
          case '\b': bnchrcpy(&dst, &n, '\\', 'b'); break;
          case '\f': bnchrcpy(&dst, &n, '\\', 'f'); break;
          case '\n': bnchrcpy(&dst, &n, '\\', 'n'); break;
          case '\r': bnchrcpy(&dst, &n, '\\', 'r'); break;
          case '\t': bnchrcpy(&dst, &n, '\\', 't'); break;
          case '"':  bnchrcpy(&dst, &n, '\\', '"'); break;
#ifdef BACKSLASH_ESCAPE
          case '\\': bnchrcpy(&dst, &n, '\\', '\\', '\\', '\\'); break;
#else
          case '\\': bnchrcpy(&dst, &n, '\\', '\\'); break;
#endif
          default:
            if (c >= ' ' && c <= '~') {
              if (n > 1) { *dst = c; dst++; --n; }
            } else {
              bnprintf(&dst, &n, "\\u%04x", c);
            }
        }
      } else if (utf8_codep <= 0xFFFF) {
        bnprintf(&dst, &n, "\\u%04x", utf8_codep);
      } else {
        bnprintf(&dst, &n, "\\u%04x", 0xD7C0 + (utf8_codep >> 10));
        bnprintf(&dst, &n, "\\u%04x", 0xDC00 + (utf8_codep & 0x3FF));
      }
    } else if (utf8_state == UTF8_REJECT) {
      for (uint8_t *x = lookback; x < ptr; ++x) {
#ifdef BACKSLASH_ESCAPE
        bnprintf(&dst, &n, "\\\\x%02x", *x);
#else
        bnprintf(&dst, &n, "\\udc%02x", *x);
#endif
      }
      ptr = lookback;
      utf8_state = 0;
      // try to process this byte again if it's a valid starting byte
      if (c <= 0x7F || (c > 0xC2 && c < 0xF4)) {
        --p;
      } else {
#ifdef BACKSLASH_ESCAPE
        bnprintf(&dst, &n, "\\\\x%02x", c);
#else
        bnprintf(&dst, &n, "\\udc%02x", c);
#endif
      }
    } else {
      *ptr++ = c;
    }
  }

  for (uint8_t *x = lookback; x < ptr; ++x) {
    bnprintf(&dst, &n, "\\\\x%02x", *x);
  }

  *dst = '\0'; --n;
  return dst_sz - n;
}

#ifdef TEST
#include <stdio.h>

int main() {
  uint8_t buf[256];
  char esc[1024];
  size_t n = fread(buf, 1, sizeof(buf), stdin);
  int x = json_escape(esc, sizeof(esc), buf, n);
  printf("escaped[%zu]: \"%s\"\n", n, esc);
  printf("x: %d\n", x);
}
#endif
