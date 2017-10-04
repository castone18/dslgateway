CFLAGS=-g -pthread -Werror -Wunused -Wuninitialized

all: dslserver dslclient dslui mempool_ut circular_buffer_ut
	
dslserver: dslgateway.o dslgateway_common.o circular_buffer.o mempool.o log.o util.o
	gcc -g -pthread -o $@ $^ -lconfig
	
dslui: dslgateway_ui.o log.o util.o
	gcc -g -pthread -o $@ $^ -lconfig 
	
dslclient: dslgateway_client.o dslgateway_common.o circular_buffer.o mempool.o log.o util.o
	gcc -g -pthread -o $@ $^ -lconfig -lrt 

circular_buffer_ut: circular_buffer_ut.o mempool.o log.o circular_buffer.o
	g++ -g -pthread -o $@ $^ 
	
mempool_ut: mempool_ut.o mempool.o log.o
	g++ -g -pthread -o $@ $^ 
	
%.o: %.c
	gcc $(CFLAGS) -c -o $@ $< 
	
%.o: %.cpp
	g++ $(CFLAGS) -c -o $@ $< 

clean:
	rm -f *.o dslserver dslui dslclient mempool_ut circular_buffer_ut
