all: mysql_sniff

mysql_sniff: tcpsniff.c buffer.c mysql_sniff.c
	$(CC) -std=gnu99 -D_GNU_SOURCE -g3 -O0 -Wall -lpcap -o $@ $^

clean:
	-/bin/rm -f mysql_sniff
	-/bin/rm -rf *.dSYM