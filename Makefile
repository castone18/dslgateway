CFLAGS=-g -pthread -Werror -Wunused -Wuninitialized

all: dslserver dslclient dslui mempool_ut circular_buffer_ut

clean:
	rm -rf *.o dslserver dslui dslclient mempool_ut circular_buffer_ut .d

dslserver: dslgateway.o dslgateway_common.o circular_buffer.o mempool.o log.o util.o
	$(CC) -g -pthread -o $@ $^ -lconfig

dslui: dslgateway_ui.o log.o util.o
	$(CC) -g -pthread -o $@ $^ -lconfig

dslclient: dslgateway_client.o dslgateway_common.o circular_buffer.o mempool.o log.o util.o
	$(CC) -g -pthread -o $@ $^ -lconfig -lrt

circular_buffer_ut: circular_buffer_ut.o mempool.o log.o circular_buffer.o
	$(CXX) -g -pthread -o $@ $^
	
mempool_ut: mempool_ut.o mempool.o log.o
	$(CXX) -g -pthread -o $@ $^

DEPDIR := .d
$(shell mkdir -p $(DEPDIR) >/dev/null)
DEPFLAGS = -MT $@ -MMD -MP -MF $(DEPDIR)/$*.Td
POSTCOMPILE = @mv -f $(DEPDIR)/$*.Td $(DEPDIR)/$*.d && touch $@

%.o : %.c
%.o : %.c $(DEPDIR)/%.d
	$(CC) $(DEPFLAGS) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<
	$(POSTCOMPILE)

%.o : %.cc
%.o : %.cc $(DEPDIR)/%.d
	$(CXX) $(DEPFLAGS) $(CXXFLAGS) $(CPPFLAGS) -c -o $@ $<
	$(POSTCOMPILE)

%.o : %.cxx
%.o : %.cxx $(DEPDIR)/%.d
	$(CXX) $(DEPFLAGS) $(CXXFLAGS) $(CPPFLAGS) -c -o $@ $<
	$(POSTCOMPILE)

$(DEPDIR)/%.d: ;
.PRECIOUS: $(DEPDIR)/%.d

include $(wildcard $(patsubst %,$(DEPDIR)/%.d,$(basename $(SRCS))))	

