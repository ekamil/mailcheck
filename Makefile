all: mailcheck

debug: mailcheck.c
	$(CC) -Wall -O0 mailcheck.c -g -o mailcheck

mailcheck: mailcheck.c
	$(CC) -Wall -O2 mailcheck.c -o mailcheck

install: mailcheck
	install mailcheck $(prefix)/usr/bin
	install -m 644 mailcheckrc $(prefix)/etc

distclean: clean

clean:
	rm -f mailcheck *~
