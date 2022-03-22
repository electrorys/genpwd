VERSION:=$(shell cat VERSION)
override CFLAGS+=-D_GENPWD_VERSION=\"$(VERSION)\" -Wall
UPX=upx

ifneq (,$(DEBUG))
override CFLAGS+=-O0 -g
else
override CFLAGS+=-O3
endif

ifneq (,$(STATIC))
override LDFLAGS+=-static
endif

ifneq (,$(STRIP))
override LDFLAGS+=-s
endif

SRCS = $(wildcard *.c)
HDRS = $(wildcard *.h)
OBJS = $(SRCS:.c=.o)

default: genpwd
all: genpwd

%.o: %.c VERSION $(HDRS)
	$(CC) $(CFLAGS) -c -o $@ $<

genpwd: $(OBJS) $(HDRS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o $@

genpwd.upx: $(OBJS) $(HDRS)
	$(CC) $(CFLAGS) $(LDFLAGS) -static -s $(OBJS) -o $@
	$(UPX) --best $@

clean:
	rm -f genpwd *.upx *.o
