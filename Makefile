all: mysqlsniff

mysqlsniff: tcpsniff.c buffer.c mysql_sniff.c mysql_log.c
	$(CC) -std=gnu99 -D_GNU_SOURCE -g3 -O0 -Wall -lpcap -o $@ $^

clean:
	-/bin/rm -f mysqlsniff
	-/bin/rm -rf *.dSYM