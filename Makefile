CFLAGS=-c -g -pthread -Werror -Wunused -Wuninitialized
CFLAGS6=-c -g -pthread -Werror -Wunused -Wuninitialized -DIPV6

#all: dslgateway dslgateway6 dslgateway_ui dslgateway_ui6 mempool_ut circular_buffer_ut
all: dslgateway dslgateway6 dslgateway_ui dslgateway_ui6
	
dslgateway: dslgateway.o circular_buffer.o mempool.o log.o util.o
	gcc -g -pthread dslgateway.o circular_buffer.o mempool.o log.o util.o -o dslgateway -lrt
	
dslgateway6: dslgateway.6.o circular_buffer.o mempool.o log.o util.o
	gcc -g -pthread dslgateway.6.o circular_buffer.o mempool.o log.o util.o -o dslgateway6 -lrt
	
dslgateway_ui: dslgateway_ui.o log.o util.o
	gcc -g -pthread dslgateway_ui.o log.o util.o -o dslgateway_ui -lrt
	
dslgateway_ui6: dslgateway_ui.6.o log.o util.o
	gcc -g -pthread dslgateway_ui.6.o log.o util.o -o dslgateway_ui6 -lrt

dslgateway.o: dslgateway.c	
	gcc $(CFLAGS) dslgateway.c -o dslgateway.o

circular_buffer.o: circular_buffer.c	
	gcc $(CFLAGS) circular_buffer.c -o circular_buffer.o

mempool.o: mempool.c	
	gcc $(CFLAGS) mempool.c -o mempool.o

log.o: log.c	
	gcc $(CFLAGS) log.c -o log.o

util.o: util.c	
	gcc $(CFLAGS) util.c -o util.o

dslgateway.6.o: dslgateway.c	
	gcc $(CFLAGS6) dslgateway.c -o dslgateway.6.o

dslgateway_ui.o: dslgateway_ui.c	
	gcc $(CFLAGS) dslgateway_ui.c -o dslgateway_ui.o

dslgateway_ui.6.o: dslgateway_ui.c	
	gcc $(CFLAGS6) dslgateway_ui.c -o dslgateway_ui.6.o

circular_buffer_ut.o: circular_buffer_ut.cpp
	g++ $(CFLAGS) circular_buffer_ut.cpp -o circular_buffer_ut.o

mempool_ut.o: mempool_ut.cpp
	g++ $(CFLAGS) mempool_ut.cpp -o mempool_ut.o
	
circular_buffer_ut: circular_buffer_ut.o mempool.o log.o circular_buffer.o
	g++ -g -pthread circular_buffer_ut.o mempool.o log.o circular_buffer.o circular_buffer_ut.o -o circular_buffer_ut -lrt
	
mempool_ut: mempool_ut.o mempool.o log.o
	g++ -g -pthread mempool_ut.o mempool.o log.o -o mempool_ut -lrt

clean:
	rm -f *.o *.6.o dslgateway dslgateway6 dslgateway_ui dslgateway_ui6 mempool_ut circular_buffer_ut
