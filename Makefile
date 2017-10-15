VERSION:=$(shell cat VERSION)
override CFLAGS+=-D_GENPWD_VERSION=\"$(VERSION)\" -Wall
UPX=upx

ifneq (,$(DEBUG))
override CFLAGS+=-O0 -g
else
override CFLAGS+=-O2 -D_SELFTEST_CURRENT
endif

XFORMS_CFLAGS:=-I/local/X11/include -I/local/include/freetype2
XFORMS_LDFLAGS:=-lforms -lfreetype -L/local/X11/lib -Wl,-rpath-link -Wl,/local/X11/lib -lX11
XFORMS_STATIC_LDFLAGS:=-lforms -lfreetype -L/local/X11/lib -Wl,-rpath-link -Wl,/local/X11/lib -lXft -lXpm -lX11 -lxcb -lfontconfig -lexpat -lXrender -lfreetype -lXau -lXdmcp -lbz2 -lz

SRCS = $(wildcard *.c)
GENPWD_OBJS = $(filter-out xgenpwd.o, $(SRCS:.c=.o))
XGENPWD_OBJS = $(filter-out genpwd.o, $(SRCS:.c=.o))

default: genpwd
all: genpwd xgenpwd

%: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

xgenpwd.o: xgenpwd.c
	$(CC) $(CFLAGS) $(XFORMS_CFLAGS) -c -o $@ $<

genpwd: $(GENPWD_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(GENPWD_OBJS) -o $@

genpwd.upx: $(GENPWD_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -static -s $(GENPWD_OBJS) -o $@
	$(UPX) --best $@

xgenpwd: $(XGENPWD_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(XGENPWD_OBJS) -o $@ $(XFORMS_LDFLAGS)

xgenpwd.upx: $(XGENPWD_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -static -s $(XGENPWD_OBJS) -o $@ $(XFORMS_STATIC_LDFLAGS)
	$(UPX) --best $@

clean:
	rm -f genpwd xgenpwd *.upx *.o icon.h
