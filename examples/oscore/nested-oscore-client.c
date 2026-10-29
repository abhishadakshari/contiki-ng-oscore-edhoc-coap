/*
 * Copyright (c) 2018, SICS, RISE AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/**
 * \file
 *      OSCORE client example.
 * \author
 *      Martin Gunnarsson <martin.gunnarsson@ri.se>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"
#include "contiki-net.h"
#include "coap-engine.h"
#include "coap-blocking-api.h"
#if PLATFORM_SUPPORTS_BUTTON_HAL
#include "dev/button-hal.h"
#else
#include "dev/button-sensor.h"
#endif

#ifdef WITH_OSCORE
#include "oscore.h"
#include "oscore-layer.h"
/* Key material, sender-ID and receiver-ID used for deriving an OSCORE-Security-Context. Note that Sender-ID and Receiver-ID is 
 * mirrored in the Client and Server. */
uint8_t master_secret[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
uint8_t salt[8] = {0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40};
/* sender/receiver IDs: [0] = CTX_C_P (client-proxy), [1] = CTX_C_S (client-server) */
#endif /* WITH_OSCORE */

/* Log configuration */
#include "coap-log.h"
#define LOG_MODULE "client"
#define LOG_LEVEL  LOG_LEVEL_COAP

#define TOGGLE_INTERVAL 20

/* Update these addresses to match setup. */
// #define PROXY_EP  "coap://[fe80::212:4b00:9df:8ecb]"
// #define SERVER_EP "coap://[fe80::212:4b00:9df:904f]"
#define PROXY_EP "coap://[fd00::1]:5685"
#define SERVER_EP "coap://[fd00::1]:5675"

/* Number of OSCORE layers: one per proxy plus one for the server.
 * Set it when building: make TARGET=native nested-oscore-client.native NUM_LAYERS=3
 * 2 matches the Java proxy and server in examples/java-nested. */
#ifndef NUM_LAYERS
#define NUM_LAYERS 2
#endif

/* Layer k uses the context shared with hop k: layer 0 = first proxy
 * (outermost), layer NUM_LAYERS-1 = server (innermost).
 * forward_to[k] is where hop k-1 forwards after removing its layer, so it is
 * NULL for layer 0, which goes straight to PROXY_EP.
 * The IDs and addresses of the extra proxies are placeholders: agree them
 * with whoever runs those proxies. */
#if NUM_LAYERS == 2
static uint8_t sender_id[NUM_LAYERS][1]   = { {0xAA}, {0x01} };
static uint8_t receiver_id[NUM_LAYERS][1] = { {0xAA}, {0x05} };
static uint8_t id_context[NUM_LAYERS][1]  = { {0xAA}, {0x01} };
static const char *forward_to[NUM_LAYERS] = { NULL, SERVER_EP };
#elif NUM_LAYERS == 3
#define PROXY2_EP "coap://[fd00::1]:5695"
static uint8_t sender_id[NUM_LAYERS][1]   = { {0xAA}, {0xBB}, {0x01} };
static uint8_t receiver_id[NUM_LAYERS][1] = { {0xAA}, {0xBB}, {0x05} };
static uint8_t id_context[NUM_LAYERS][1]  = { {0xAA}, {0xBB}, {0x01} };
static const char *forward_to[NUM_LAYERS] = { NULL, PROXY2_EP, SERVER_EP };
#elif NUM_LAYERS == 4
#define PROXY2_EP "coap://[fd00::1]:5695"
#define PROXY3_EP "coap://[fd00::1]:5705"
static uint8_t sender_id[NUM_LAYERS][1]   = { {0xAA}, {0xBB}, {0xCC}, {0x01} };
static uint8_t receiver_id[NUM_LAYERS][1] = { {0xAA}, {0xBB}, {0xCC}, {0x05} };
static uint8_t id_context[NUM_LAYERS][1]  = { {0xAA}, {0xBB}, {0xCC}, {0x01} };
static const char *forward_to[NUM_LAYERS] = { NULL, PROXY2_EP, PROXY3_EP, SERVER_EP };
#else
#error "Add contexts and addresses for this NUM_LAYERS"
#endif

PROCESS(er_example_client, "Nested OSCORE Example Client");
AUTOSTART_PROCESSES(&er_example_client);

static struct etimer et;

/* Example URIs that can be queried. */
#define SERVICE_URI "hello/1"

/* This function is will be passed to COAP_BLOCKING_REQUEST() to handle responses. */
void
client_chunk_handler(coap_message_t *response)
{
  const uint8_t *chunk;

  if(response == NULL) {
    /* Timeout, or the request could not be protected and was not sent;
     * coap_error_message says which (e.g. "OSCORE: message too large ...") */
    printf("No response: %s\n", coap_error_message);
    return;
  }

  int len = coap_get_payload(response, &chunk);
  printf("response: \n");
  printf("|%.*s", len, (char *)chunk);
}

static oscore_ctx_t contexts[NUM_LAYERS];
static oscore_layer_t layers[NUM_LAYERS];
static oscore_path_t client_path;

PROCESS_THREAD(er_example_client, ev, data)
{
  PROCESS_BEGIN();

  static coap_message_t request[1];      /* This way the packet can be treated as pointer as usual. */
  static coap_endpoint_t proxy_ep;
  static coap_endpoint_t server_ep;

  coap_endpoint_parse(PROXY_EP,  strlen(PROXY_EP),  &proxy_ep);
  coap_endpoint_parse(SERVER_EP, strlen(SERVER_EP), &server_ep);

  #ifdef WITH_OSCORE
  /* One context and one layer per hop, then register the path once. */
  for(int k = 0; k < NUM_LAYERS; k++) {
    oscore_derive_ctx(&contexts[k], master_secret, 16, salt, 8, 10,
                      sender_id[k], 1, receiver_id[k], 1, id_context[k], 1);
    layers[k].ctx = &contexts[k];
    layers[k].forward_to_uri = forward_to[k];
  }
  client_path.layers = layers;
  client_path.num_layers = NUM_LAYERS;
  if(!oscore_ep_path_set(&proxy_ep, &client_path)) {
    printf("Could not set the OSCORE path (NUM_LAYERS %d)\n", NUM_LAYERS);
  }
  printf("Nested OSCORE client with %d layers\n", NUM_LAYERS);
  #endif /* WITH_OSCORE */

  

  etimer_set(&et, TOGGLE_INTERVAL * CLOCK_SECOND);
  
#if PLATFORM_HAS_BUTTON
#if !PLATFORM_SUPPORTS_BUTTON_HAL
  SENSORS_ACTIVATE(button_sensor);
#endif
  LOG_INFO("Press a button to request %s\n", SERVICE_URI);
#endif /* PLATFORM_HAS_BUTTON */

  while(1) {
    PROCESS_YIELD();

    if(etimer_expired(&et)) {
      LOG_DBG("--Toggle timer--\n");

      /* prepare request, TID is set by COAP_BLOCKING_REQUEST() */
      coap_init_message(request, COAP_TYPE_NON, COAP_GET, 0);
      coap_set_header_uri_path(request, SERVICE_URI);

      request->dest_ep = &proxy_ep;

      // const char msg[] = "Toggle!";
      // coap_set_payload(request, (uint8_t *)msg, sizeof(msg) - 1);

      printf("Target: ");
      LOG_INFO_COAP_EP(&proxy_ep);
      printf("\n");

      COAP_BLOCKING_REQUEST(&proxy_ep, request, client_chunk_handler);

      printf("\n--Done--\n");

      //etimer_reset(&et);

#if PLATFORM_HAS_BUTTON
#if PLATFORM_SUPPORTS_BUTTON_HAL
    } else if(ev == button_hal_release_event) {
#else
    } else if(ev == sensors_event && data == &button_sensor) {
#endif

      /* send a request to notify the end of the process */

      coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
      coap_set_header_uri_path(request, SERVICE_URI);

      printf("--Requesting %s--\n", SERVICE_URI);

      LOG_INFO_COAP_EP(&server_ep);
      LOG_INFO_("\n");

      COAP_BLOCKING_REQUEST(&server_ep, request,
                            client_chunk_handler);

      printf("\n--Done--\n");
#endif /* PLATFORM_HAS_BUTTON */
    }
  }

  PROCESS_END();
}
 
