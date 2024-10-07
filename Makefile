MAKEFLAGS += --no-builtin-rules
export LANG=C LC_ALL=C

.PHONY: all clean _clean _nop

C ?= gcc
AS ?= gcc
PP ?= cpp
LD ?= ld
STRIP ?= strip

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
	-D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64

ifneq ($(VERSION),)
	override CPPFLAGS += -DVERSION=$(VERSION)
endif

ifneq ($(VERSION_EXTRA),)
	override CPPFLAGS += -DVERSION_EXTRA=$(VERSION_EXTRA)
endif

CFLAGS ?= -Os
override CFLAGS += -std=gnu17 -Wall -Wextra -pedantic

COMPILE = $(CC) $(CPPFLAGS) $(CFLAGS)

all: bin/proberelay bin/proberelay_nopcap

bin/test_%: src/%.c
	@mkdir -p $(@D)
	$(COMPILE) -DTEST $< $(LDFLAGS) -o $@

bin/proberelay: obj/proberelay.o
	@mkdir -p $(@D)
	$(COMPILE) $^ -lpcap $(LDFLAGS) -o $@

bin/proberelay_nopcap: obj/proberelay_nopcap.o
	@mkdir -p $(@D)
	$(COMPILE) $^ $(LDFLAGS) -o $@

bin/proberelay_stripped: bin/proberelay_nopcap
	@mkdir -p $(@D)
	cp $^ $@
	$(STRIP) $@

bin/linkinfo: obj/linkinfo.o
	@mkdir -p $(@D)
	$(COMPILE) $^ $(LDFLAGS) -o $@

# generic build rules
obj/%.o: src/%.c src/%.h
	@mkdir -p $(@D)
	$(COMPILE) -c $< -o $@

obj/%.o: src/%.c
	@mkdir -p $(@D)
	$(COMPILE) -c $< -o $@


# hack to force clean to run first *to completion* even for parallel builds
# note that $(info ...) prints everything on one line
clean: _nop $(foreach _,$(filter clean,$(MAKECMDGOALS)),$(info $(shell $(MAKE) _clean)))
_clean:
	rm -rf obj bin gen || /bin/true
_nop:
	@true
