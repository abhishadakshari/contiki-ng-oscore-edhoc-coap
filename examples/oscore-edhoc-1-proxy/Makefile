CONTIKI_PROJECT = oscore-edhoc-1-proxy-client
all: $(CONTIKI_PROJECT)

CONTIKI = ../..

# Your nested OSCORE code in client mode, plus the EDHOC module
MAKE_WITH_OSCORE = 1
CFLAGS += -DOSCORE_EP_CTX_ASSOCIATION -DOSCORE_CLIENT_MODE

MODULES += os/net/app-layer/coap
MODULES += os/net/security/edhoc

include $(CONTIKI)/Makefile.include
