#pragma once

#ifndef NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#define debugp(...) _debugp(__FILE__, __func__, __LINE__, __VA_ARGS__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
static void _debugp(const char *file, const char *func, unsigned int line, const char *fmt, ...) {
  char f[256];
  va_list args;
  va_start(args, fmt);

  size_t n = strnlen(fmt, sizeof(f));
  // check if fmt with null terminator will fit in f
  if (sizeof(f) == n) {
    fprintf(stderr, "%s(%s:%u,%d): bad format, aborting\n", file, func, line, errno);
    abort();
  } else {
    strcpy(f, fmt);
  }

  // remove newline from format string
  f[n-(f[n-1] == '\n' ? 1 : 0)] = 0;

  fprintf(stderr, "%s(%s:%u,%d): ", file, func, line, errno);
  vfprintf(stderr, f, args);
  fprintf(stderr, "\n");
}
#pragma GCC diagnostic pop
#else
#define debugp(...) do {} while (0)
#endif
