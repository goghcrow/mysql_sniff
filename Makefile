all: mysqlsniff

mysqlsniff: tcpsniff.c buffer.c mysql_sniff.c mysql_log.c
	$(CC) -std=gnu99 -D_GNU_SOURCE -g -O2 -Wall -lpcap -o $@ $^

mysqlsniff_debug: tcpsniff.c buffer.c mysql_sniff.c mysql_log.c
	$(CC) -fsanitize=address -fno-omit-frame-pointer -std=gnu99 -D_GNU_SOURCE -g3 -O0 -Wall -lpcap $(ASAN_FLAGS) -o $@ $^
# ASAN_OPTIONS=symbolize=1 ASAN_SYMBOLIZER_PATH=$(which llvm-symbolizer)


clean:
	-/bin/rm -f mysqlsniff
	-/bin/rm -f mysqlsniff_debug
	-/bin/rm -rf *.dSYM