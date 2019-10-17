
all:
	g++ -I/usr/include test.c sendicmp.c hping2.c sendtcp.c waitpacket.c util.c logging.c socket.c cache.c redis.c -o test -lnetfilter_queue -lnfnetlink -lhiredis -lev -pthread

debug:
	g++ -g -I/usr/include test.c sendicmp.c hping2.c sendtcp.c waitpacket.c util.c logging.c socket.c cache.c redis.c -o test -lnetfilter_queue -lnfnetlink -lhiredis -lev -pthread

clean:
	rm *.o
	rm test


