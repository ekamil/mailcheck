all: mailcheck

debug: mailcheck.c netrc.c netrc.h socket.c
	$(CC) -Wall -O0 mailcheck.c netrc.c socket.c -g -o mailcheck

mailcheck: mailcheck.c netrc.c netrc.h socket.c
	$(CC) -Wall -O2 mailcheck.c netrc.c socket.c -s -o mailcheck

install: mailcheck
	install mailcheck $(prefix)/usr/bin
	install -m 644 mailcheckrc $(prefix)/etc

distclean: clean

clean:
	rm -f mailcheck *~
