CONTIKI_PROJECT = nested-test
all: $(CONTIKI_PROJECT)

CONTIKI = ../..

MAKE_WITH_OSCORE = 1
CFLAGS += -DOSCORE_CLIENT_MODE
ifdef CHUNK
  CFLAGS += -DTEST_CHUNK_SIZE=$(CHUNK)
endif

MODULES += os/net/app-layer/coap

include $(CONTIKI)/Makefile.include
