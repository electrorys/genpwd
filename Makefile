override CFLAGS+=-Wall -DTF_FAST -D_XOPEN_SOURCE=700 -D_BSD_SOURCE -O2 -DDAEMONISE

GTK2_CFLAGS:=`pkg-config --cflags gtk+-2.0`
GTK2_LDFLAGS:=`pkg-config --libs gtk+-2.0`

SRCS = $(wildcard *.c)
GENPWD_OBJS = $(filter-out ggenpwd.o, $(SRCS:.c=.o))
GGENPWD_OBJS = $(filter-out genpwd.o, $(SRCS:.c=.o))

default: genpwd
all: genpwd ggenpwd

%: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

ggenpwd.o: ggenpwd.c
	xxd -i icon.png >icon.h
	$(CC) $(CFLAGS) $(GTK2_CFLAGS) -c -o $@ $<

genpwd: $(GENPWD_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(GENPWD_OBJS) -o $@

ggenpwd: $(GGENPWD_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(GGENPWD_OBJS) -o $@ $(GTK2_LDFLAGS)

clean:
	rm -f genpwd ggenpwd *.o icon.h
