override CFLAGS+=-Wall -DTF_FAST -D_XOPEN_SOURCE=700 -D_BSD_SOURCE -O2 -DDAEMONISE -D_SELFTEST_CURRENT

XFORMS_CFLAGS:=-I/local/include/freetype2
XFORMS_LDFLAGS:=-lforms -lfreetype -L/local/X11/lib -Wl,-rpath-link -Wl,/local/X11/lib -lX11

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

xgenpwd: $(XGENPWD_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(XGENPWD_OBJS) -o $@ $(XFORMS_LDFLAGS)

clean:
	rm -f genpwd xgenpwd *.o icon.h
