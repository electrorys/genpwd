override CFLAGS+=-Wall -DTF_FAST -D_XOPEN_SOURCE=700 -D_BSD_SOURCE -O2 -DDAEMONISE
# override CFLAGS+=-Wall -DTF_FAST -D_XOPEN_SOURCE=700 -D_BSD_SOURCE -O2 -DDAEMONISE -D_SELFTEST_CURRENT

GTK2_CFLAGS:=`pkg-config --cflags gtk+-2.0`
GTK2_LDFLAGS:=`pkg-config --libs gtk+-2.0`

XFORMS_CFLAGS:=-I/local/include/freetype2
XFORMS_LDFLAGS:=-lforms -lfreetype -L/local/X11/lib -Wl,-rpath-link -Wl,/local/X11/lib -lX11

SRCS = $(wildcard *.c)
GENPWD_OBJS = $(filter-out ggenpwd.o xgenpwd.o, $(SRCS:.c=.o))
GGENPWD_OBJS = $(filter-out genpwd.o xgenpwd.o, $(SRCS:.c=.o))
XGENPWD_OBJS = $(filter-out ggenpwd.o genpwd.o, $(SRCS:.c=.o))

default: genpwd
all: genpwd ggenpwd xgenpwd

%: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

ggenpwd.o: ggenpwd.c
	xxd -i icon.png >icon.h
	$(CC) $(CFLAGS) $(GTK2_CFLAGS) -c -o $@ $<

xgenpwd.o: xgenpwd.c
	$(CC) $(CFLAGS) $(XFORMS_CFLAGS) -c -o $@ $<

genpwd: $(GENPWD_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(GENPWD_OBJS) -o $@

xgenpwd: $(XGENPWD_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(XGENPWD_OBJS) -o $@ $(XFORMS_LDFLAGS)

ggenpwd: $(GGENPWD_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(GGENPWD_OBJS) -o $@ $(GTK2_LDFLAGS)

clean:
	rm -f genpwd xgenpwd ggenpwd *.o icon.h
