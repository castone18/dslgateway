CFLAGS=-g -pthread -Werror -Wunused -Wuninitialized

all: dslserver dslclient dslui
	
dslserver: dslgateway.o dslgateway_common.o log.o util.o
	gcc -g -pthread -o $@ $^ -lconfig -lnetfilter_queue
	
dslui: dslgateway_ui.o log.o util.o dslgateway_common.o
	gcc -g -pthread -o $@ $^ -lconfig -lnetfilter_queue
	
dslclient: dslgateway_client.o dslgateway_common.o log.o util.o
	gcc -g -pthread -o $@ $^ -lconfig -lrt -lnetfilter_queue

%.o: %.c
	gcc $(CFLAGS) -c -o $@ $< 
	
%.o: %.cpp
	g++ $(CFLAGS) -c -o $@ $< 

clean:
	rm -f *.o dslserver dslui dslclient
