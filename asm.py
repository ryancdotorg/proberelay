#!/usr/bin/env python3

from sys import argv, exit, stdin, stdout, stderr, version_info
from functools import partial
eprint = partial(print, file=stderr)

# Python standard library imports
import re
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

def print_detail(asm):
    asm_lines = []
    for line in map(str.strip, asm.split('\n')):
        line = line.strip()
        if line: asm_lines.append(line)

    prog = bpf_asm.assemble('\n'.join(asm_lines) + '\n')

    for i, tup in enumerate(zip(asm_lines, prog)):
        line, insn = tup
        code, jt, jf, k = insn
        jt_a, jf_a = '0', '0'
        #if code & 0x0f == 0x05:
        if jt: jt_a = f'{(jt + i + 1):3d} - ({i:3d} + 1)'
        if jf: jf_a = f'{(jf + i + 1):3d} - ({i:3d} + 1)'

        if m := re.fullmatch(r'(.*?)(?:\s*(?:;|/[*])\s*(.*?)(?:\s*[*]/\s*)?)?', line):
            asm, comment = m.groups()
            comment = f'; {comment}' if comment else ''
            src = f' // {asm:28}{comment}'
        else:
            src = ''

        print(f'/* {i:3d} */ {{ 0x{code:02x}, {jt_a:>15}, {jf_a:>15}, 0x{k:08x} }},{src}')

if len(argv) == 3:
    print(f'struct sock_filter {argv[1]}[] = {{')
    print_detail(open(argv[2]).read())
    print('};')
    exit(0)
elif len(argv) == 2:
    print_detail(open(argv[1]).read())
    exit(0)

'''
# masked list of types
A1 = """\
    ldb [16]                    /* radiotap flags byte */
    jset #0x40, drop            /* drop if frame failed FCS check */
    ldb [52]                    /* load first byte of frame control */
    jset #0xc, drop             /* drop if not management frame */
    jeq #0x80, drop             /* drop beacon frames */
    jeq #0x40, ssid             /* fast path for probe requests */
    other: rsh #4               /* extract subtype */
    tax                         /* save A in X */
    ldi #1                      /* load 1 into A */
    lsh x                       /* left shift A by X */
    jset #0x142f, accept, drop  /* mask allowed subtypes */
    ssid: ldh [76]              /* type and length of first probe request TLV */
    sub #1                      /* type needs to be 0, length 1-32 */
    jset #0xffe0, drop          /* bad type and/or length if any of these are set */
    accept: ret #262144         /* truncate to snaplen */
    drop: ret #0                /* drop the packet */
"""

print('A1')
print_detail(A1)

A2 = """\
    ldb [16]                    /* radiotap flags byte */
    jset #0x40, drop            /* drop if frame failed FCS check */
    ldb [52]                    /* load first byte of frame control */
    jset #0xc, drop             /* drop if not management frame */
    jeq #0x80, drop             /* drop beacon frames */
    jeq #0x40, ssid             /* fast track for probe requests */
    jeq #0x10, accept           /* accept association request */
    jeq #0x70, accept, drop     /* accept reserved (extended?), drop anything else */
    ssid: ldh [76]              /* type and length of first probe request TLV */
    sub #1                      /* type needs to be 0, length 1-32 */
    jset #0xffe0, drop          /* bad type and/or length if any of these are set */
    accept: ret #262144         /* truncate to snaplen */
    drop: ret #0                /* drop the packet */
"""

print('A2')
print_detail(A2)

ZZ = """\
    ldx #8                      /* data offset */
    ldb [7]                     /* high byte of it_present */
    jset #0x80, mb1, nmb        /* more bits? */
    mb1: ldx #12
    ldb [11]
    jset #0x80, mb2, nmb        /* more bits? */
    mb2: ldx #16
    ldb [15]
    jset #0x80, mb3, nmb        /* more bits? */
    mb3: ldx #20
    jset #0x80, drop, nmb       /* too many bits! */
    nmb: ldb [4]                /* low bit of first it_present */
    jset #0x01, tsft_y, tsft_n
    tsft_y: txa
    add #15
    and #0xfffffff8
    tax
    ldb [4]
    tsft_n: jset #0x02, flags_y, flags_n
    flags_y: ldb [x+0]
    jset #0x40, drop            /* drop if frame failed FCS check */
    txa
    add #1
    tax
    ldb [4]
    flags_n: jset #0x04, rate_y, rate_n
    rate_y: txa
    add #1
    tax
    ldb [4]
    rate_n: jset #0x08, chan_y, chan_n
    chan_y: txa
    add #3
    and #0xfffffffe
    tax
    ldb [4]
    chan_n: jset #0x10, fhss_y, fhss_n
    fhss_y: txa
    add #2
    tax
    ldb [4]
    fhss_n: jset #0x20, sig_y, sig_n
    sig_y: ldb [x + 0]
    jle #0xaa, drop             /* drop if signal below -85dBm */
    ldb [4294967295]            /* radiotap flags byte */
    jset #0x40, drop            /* drop if frame failed FCS check */
    ldb [4294967295]            /* radiotap signal byte */
    jlt #0xaa, drop             /* drop if less than -85dBm signal */
    ldb [4294967295]            /* load first byte of frame control */
    jset #0xc, drop             /* drop if not management frame */
    jne #0x40, drop             /* drop everything except probe requests */
    ldh [4294967295]            /* type and length of first probe request TLV */
    sub #1                      /* type needs to be 0, length 1-32 */
    jset #0xffe0, drop          /* bad type and/or length if any of these are set */
    accept: ret #262144         /* truncate to snaplen */
    drop: ret #0                /* drop the packet */
"""

print('ZZ')
print_detail(ZZ)

A3 = """\
    ldb [4294967295]            /* radiotap flags byte */
    jset #0x40, drop            /* drop if frame failed FCS check */
    ldb [4294967295]            /* radiotap signal byte */
    jlt #0xaa, drop             /* drop if less than -85dBm signal */
    ldb [4294967295]            /* load first byte of frame control */
    jset #0xc, drop             /* drop if not management frame */
    jne #0x40, drop             /* drop everything except probe requests */
    ldh [4294967295]            /* type and length of first probe request TLV */
    sub #1                      /* type needs to be 0, length 1-32 */
    jset #0xffe0, drop          /* bad type and/or length if any of these are set */
    accept: ret #262144         /* truncate to snaplen */
    drop: ret #0                /* drop the packet */
"""

print('A3')
print_detail(A3)
'''

A4 = """\
    ldb [4294967295]            /* load first byte of frame control */
    jne #0x40, drop             /* drop everything except probe requests */
    ldh [4294967295]            /* type and length of first probe request TLV */
    sub #1                      /* type needs to be 0, length 1-32 */
    jset #0xffe0, drop          /* bad type and/or length if any of these are set */
    ldb [4294967295]            /* radiotap signal byte */
    jlt #0x80, drop             /* drop if less than -127dBm signal */
    ldb [4294967295]            /* radiotap flags byte */
    jset #0x40, drop            /* drop if frame failed FCS check */
    accept: ret #262144         /* truncate to snaplen */
    drop: ret #0                /* drop the packet */
"""

print('A4')
print_detail(A4)
