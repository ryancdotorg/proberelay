#!/usr/bin/env python3

from sys import argv, exit, stdin, stdout, stderr, version_info
from functools import partial
eprint = partial(print, file=stderr)

# Python standard library imports


# Third party library imports
import bpf_asm

# End imports

# 0 association request
# 1 association response
# 2 reassociation request
# 3 reassociation response
# 4 probe request
# 5 probe response
# 6 timing advertisement
# 8 beacon
# a disassocation
# b authentication
# c deauthentication
# e action

def print_insn(prog):
    for i, insn in enumerate(prog):
        code, jt, jf, k = insn
        jf_a = ' ' * 21
        jt_a = jf_a
        if code & 0x0f == 0x05:
            jt_a = f'/* {(jt + i + 1):3d} - ({i:3d} + 1) */'
            if jf:
                jf_a = f'/* {(jf + i + 1):3d} - ({i:3d} + 1) */'

        print(f'/* {i:3d} */ {{ 0x{code:02x}, {jt_a} {jt:3d}, {jf_a} {jf:3d}, 0x{k:08x} }}')

# masked list of types
A1 = """\
    ldb [16]                    /* radiotap flags byte */
    jset #0x40, drop            /* drop if frame failed FCS check */
    ldb [52]                    /* load first byte of frame control */
    jset #0xc, drop             /* drop if not management frame */
    jeq #0x80, drop             /* drop beacon frames */
    jeq #0x40, ssid             /* fast path for probe requests */
other:
    rsh #4                      /* extract subtype */
    tax                         /* save A in X */
    ldi #1                      /* load 1 into A */
    lsh x                       /* left shift A by X */
    jset #0x142f, accept, drop  /* mask allowed subtypes */
ssid:
    ldh [76]                    /* type and length of first probe request TLV */
    sub #1                      /* type needs to be 0, length 1-32 */
    jset #0xffe0, drop          /* bad type and/or length if any of these are set */
accept:
    ret #1432                   /* truncate to snaplen */
drop:
    ret #0                      /* drop the packet */
"""

print('A1')
print_insn(bpf_asm.assemble(A1))


A2 = """\
    ldb [16]                    /* radiotap flags byte */
    jset #0x40, drop            /* drop if frame failed FCS check */
    ldb [52]                    /* load first byte of frame control */
    jset #0xc, drop             /* drop if not management frame */
    jeq #0x80, drop             /* drop beacon frames */
    jeq #0x40, ssid             /* fast track for probe requests */
    jeq #0x10, accept           /* accept association request */
    jeq #0x70, accept, drop     /* accept reserved (extended?), drop anything else */
ssid:
    ldh [76]                    /* type and length of first probe request TLV */
    sub #1                      /* type needs to be 0, length 1-32 */
    jset #0xffe0, drop          /* bad type and/or length if any of these are set */
accept:
    ret #1432                   /* truncate to snaplen */
drop:
    ret #0                      /* drop the packet */
"""

print('A2')
print_insn(bpf_asm.assemble(A2))

A3 = """\
    ldb [16]                    /* radiotap flags byte */
    jset #0x40, drop            /* drop if frame failed FCS check */
    ldb [52]                    /* load first byte of frame control */
    jset #0xc, drop             /* drop if not management frame */
    jne #0x40, drop             /* drop everything except probe requests */
    ldh [76]                    /* type and length of first probe request TLV */
    sub #1                      /* type needs to be 0, length 1-32 */
    jset #0xffe0, drop          /* bad type and/or length if any of these are set */
accept:
    ret #1432                   /* truncate to snaplen */
drop:
    ret #0                      /* drop the packet */
"""

print('A3')
print_insn(bpf_asm.assemble(A3))
