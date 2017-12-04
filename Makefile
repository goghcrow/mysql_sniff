all: mysql_sniff

mysql_sniff: tcpsniff.c buffer.c mysql_sniff.c
	$(CC) -std=c99 -g3 -O0 -Wall -lpcap -o $@ $^

clean:
	-/bin/rm -f mysql_sniff
	-/bin/rm -rf *.dSYM