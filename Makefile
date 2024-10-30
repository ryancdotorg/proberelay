ORIG_MAKEFLAGS ::= $(MAKEFLAGS)
MAKEFLAGS += --no-builtin-rules
export LANG=C LC_ALL=C

.PHONY: all clean _clean _nop

C ?= gcc
AS ?= gcc
PP ?= cpp
LD ?= ld
STRIP ?= strip

BUILD_TIME ?= $(shell date --utc '+%Y-%m-%dT%H:%M:%SZ')

VERSION ?= $(shell git describe --abbrev=0 --tags 2> /dev/null || printf '')
VERSION_EXTRA ?=

GIT_TAGGED := $(shell git tag --points-at HEAD 2> /dev/null | grep . || printf '')
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2> /dev/null | tr -c '\n0-9A-Za-z' - || printf '')
GIT_COMMIT := $(shell git log -1 --format=.%h 2> /dev/null || printf '')
GIT_STATUS := $(shell git status --porcelain -uno 2> /dev/null | grep -q . && printf '%s' '-dirty' || printf '')

ifeq ($(VERSION_EXTRA),)
	ifneq ($(GIT_BRANCH),)
		GIT_INFO := $(GIT_BRANCH)$(GIT_COMMIT)$(GIT_STATUS)
		ifeq ($(GIT_TAGGED),)
			VERSION_EXTRA := +$(GIT_INFO)
		else
			ifneq ($(GIT_STATUS),)
				VERSION_EXTRA := +$(GIT_INFO)
			endif
		endif
	endif
endif

CPPFLAGS ?=
override CPPFLAGS += -D_ALL_SOURCE -D_GNU_SOURCE \
	-D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 \
	-DBUILD_TIME='"$(BUILD_TIME)"'

ifneq ($(VERSION),)
	override CPPFLAGS += -DVERSION='"$(VERSION)"'
endif

ifneq ($(VERSION_EXTRA),)
	override CPPFLAGS += -DVERSION_EXTRA='"$(VERSION_EXTRA)"'
endif

ifneq ($(UNPRIV_GID),)
	override CPPFLAGS += -DUNPRIV_GID=$(UNPRIV_GID)
endif

ifneq ($(UNPRIV_UID),)
	override CPPFLAGS += -DUNPRIV_UID=$(UNPRIV_UID)
endif

CFLAGS ?= -Os
override CFLAGS += -std=gnu17 -Wall -Wextra -pedantic
LDFLAGS ?=

DEBUG_FLAGS ?= -ggdb
RELEASE_FLAGS ?= -DNDEBUG

COMPILE = $(CC) $(CPPFLAGS) $(CFLAGS)

all: bin/proberelay

linux_tools/bpf_asm: linux_tools/Makefile linux_tools/bpf_asm.c linux_tools/bpf_exp.y linux_tools/bpf_exp.l
	MAKEFLAGS=$(ORIG_MAKEFLAGS) $(MAKE) -C linux_tools bpf_asm LDFLAGS=-static

linux_tools/bpf_dbg: linux_tools/Makefile linux_tools/bpf_dbg.c linux_tools/bpf_exp.y linux_tools/bpf_exp.l
	MAKEFLAGS=$(ORIG_MAKEFLAGS) $(MAKE) -C linux_tools bpf_dbg

bin/test_%: src/%.c
	@mkdir -p $(@D)
	$(COMPILE) -DTEST $(DEBUG_FLAGS) $< $(LDFLAGS) -o $@

bin/test_escape: src/escape.c obj/bnprintf.o
	@mkdir -p $(@D)
	$(COMPILE) -DTEST $(DEBUG_FLAGS) $^ $(LDFLAGS) -o $@

bin/proberelay: obj/proberelay.o obj/radiotap.o obj/escape.o obj/bnprintf.o
	@mkdir -p $(@D)
	$(COMPILE) $(RELEASE_FLAGS) $^ $(LDFLAGS) -o $@
	$(STRIP) -s $@

bin/proberelay_sym: obj/proberelay.o obj/radiotap.o obj/escape.o obj/bnprintf.o
	@mkdir -p $(@D)
	$(COMPILE) $(RELEASE_FLAGS) $^ $(LDFLAGS) -o $@

bin/proberelay_debug: obj/proberelay_debug.o
	@mkdir -p $(@D)
	$(COMPILE) $(DEBUG_FLAGS) $^ $(LDFLAGS) -o $@

# generic build rules
obj/%.o: src/%.c src/%.h
	@mkdir -p $(@D)
	$(COMPILE) $(RELEASE_FLAGS) -c $< -o $@

obj/%.o: src/%.c
	@mkdir -p $(@D)
	$(COMPILE) $(RELEASE_FLAGS) -c $< -o $@

obj/%_debug.o: src/%.c src/%.h src/debugp.h
	@mkdir -p $(@D)
	$(COMPILE) $(DEBUG_FLAGS) -c $< -o $@

obj/%_debug.o: src/%.c src/debugp.h
	@mkdir -p $(@D)
	$(COMPILE) $(DEBUG_FLAGS) -c $< -o $@

# hack to force clean to run first *to completion* even for parallel builds
# note that $(info ...) prints everything on one line
clean: _nop $(foreach _,$(filter clean,$(MAKECMDGOALS)),$(info $(shell $(MAKE) _clean)))
_clean:
	$(MAKE) -C linux_tools clean
	rm -rf obj bin gen || /bin/true
_nop:
	@true
