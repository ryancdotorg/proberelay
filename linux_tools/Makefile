prefix = /usr

CC = gcc
LEX = flex
YACC = bison

%.yacc.c: %.y
	$(YACC) -o $@ -d $<

%.lex.c: %.l
	$(LEX) -o $@ $<

all : bpf_asm bpf_dbg

bpf_dbg : CFLAGS = -Wall -O2 -I.
bpf_dbg : LDLIBS = -lreadline
bpf_dbg : bpf_dbg.o

bpf_asm : CFLAGS = -Wall -O2 -I.
bpf_asm : LDLIBS =
bpf_asm : bpf_asm.o bpf_exp.yacc.o bpf_exp.lex.o
bpf_exp.lex.o : bpf_exp.yacc.c

clean :
	rm -rf *.o bpf_dbg bpf_asm bpf_exp.yacc.* bpf_exp.lex.*
