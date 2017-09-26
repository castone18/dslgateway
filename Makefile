CFLAGS=-c -g -pthread -Werror -Wunused -Wuninitialized

#all: dslgateway dslgateway6 dslgateway_ui dslgateway_ui6 mempool_ut circular_buffer_ut
all: dslgateway dslgateway_ui
	
dslgateway: dslgateway.o circular_buffer.o mempool.o log.o util.o
	gcc -g -pthread dslgateway.o circular_buffer.o mempool.o log.o util.o -o dslgateway -lrt -lconfig
	
dslgateway_ui: dslgateway_ui.o log.o util.o
	gcc -g -pthread dslgateway_ui.o log.o util.o -o dslgateway_ui -lrt -lconfig

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

dslgateway_ui.o: dslgateway_ui.c	
	gcc $(CFLAGS) dslgateway_ui.c -o dslgateway_ui.o

circular_buffer_ut.o: circular_buffer_ut.cpp
	g++ $(CFLAGS) circular_buffer_ut.cpp -o circular_buffer_ut.o

mempool_ut.o: mempool_ut.cpp
	g++ $(CFLAGS) mempool_ut.cpp -o mempool_ut.o
	
circular_buffer_ut: circular_buffer_ut.o mempool.o log.o circular_buffer.o
	g++ -g -pthread circular_buffer_ut.o mempool.o log.o circular_buffer.o circular_buffer_ut.o -o circular_buffer_ut -lrt
	
mempool_ut: mempool_ut.o mempool.o log.o
	g++ -g -pthread mempool_ut.o mempool.o log.o -o mempool_ut -lrt

clean:
	rm -f *.o dslgateway dslgateway_ui mempool_ut circular_buffer_ut
