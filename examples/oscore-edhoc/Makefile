CONTIKI_PROJECT = oscore-edhoc-client
all: $(CONTIKI_PROJECT)

CONTIKI = ../..

# OSCORE (your nested OSCORE code) in client mode, plus the EDHOC module
MAKE_WITH_OSCORE = 1
CFLAGS += -DOSCORE_EP_CTX_ASSOCIATION -DOSCORE_CLIENT_MODE

MODULES += os/net/app-layer/coap
MODULES += os/net/security/edhoc

include $(CONTIKI)/Makefile.include
