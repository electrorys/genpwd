CFLAGS+=-Wall -D_XOPEN_SOURCE=500 -D_BSD_SOURCE -O2

default: genpwd
all: genpwd ggenpwd

genpwd: mkpwd.o genpwd.c
	$(CC) $(CFLAGS) $(LDFLAGS) mkpwd.o genpwd.c -o genpwd

ggenpwd: mkpwd.o ggenpwd.c icon.h
	$(CC) $(CFLAGS) $(LDFLAGS) mkpwd.o ggenpwd.c `pkg-config --cflags gtk+-2.0` -o ggenpwd `pkg-config --libs gtk+-2.0`

icon.h: icon.png
	xxd -i icon.png >icon.h

clean:
	rm -f genpwd ggenpwd *.o icon.h
