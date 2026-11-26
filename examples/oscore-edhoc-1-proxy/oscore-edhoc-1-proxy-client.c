/**
 * \file
 *         Stage 2: a nested OSCORE client with one proxy, where every OSCORE
 *         security context comes from EDHOC.
 *
 *         The circuit is built one hop at a time, as in Onion CoAP
 *         (Section VI):
 *         1. EDHOC with the proxy, sent straight to it, unprotected. Its
 *            result is the OSCORE context of layer 0 (client <-> proxy).
 *         2. EDHOC with the server, sent through the proxy. Each EDHOC
 *            message goes to the proxy inside the layer-0 OSCORE layer, with
 *            a Proxy-Uri naming the server's EDHOC resource. The proxy
 *            removes its layer and forwards plain EDHOC to the server. The
 *            result is the OSCORE context of layer 1 (client <-> server).
 *         3. GET /helloWorld with both layers, as the nested OSCORE client
 *            does.
 *
 *         The proxy is the Java EdhocProxy (port 5685) and the server the
 *         Java EdhocServer (port 5686), both in examples/java-edhoc. The
 *         outcome is written to ../java-edhoc/logs/client-result.txt for
 *         summarise-edhoc-proxy.py.
 *
 *         SECURITY NOTICE: the RFC 9529 test credentials and the proxy key
 *         are publicly known. Never use them outside testing.
 *
 * \author
 *         Abhishek Shadakshari
 */
#include <stdio.h>
#include <string.h>
#include "contiki.h"
#include "contiki-net.h"
#include "coap-engine.h"
#include "coap-blocking-api.h"
#include "oscore.h"
#include "oscore-layer.h"
#include "edhoc-client.h"
#include "edhoc-error.h"
#include "edhoc-exporter.h"
#include "edhoc-key-storage.h"
#include "edhoc-cred-rfc9529.h"

#include "sys/log.h"
#define LOG_MODULE "client"
#define LOG_LEVEL  LOG_LEVEL_INFO

/*
 * Addresses: the Java EdhocProxy on 5685, the Java EdhocServer on 5686.
 * SERVER_EDHOC_URI is the Proxy-Uri of the EDHOC messages of hop 2, and
 * SERVER_URI the Proxy-Uri of the application request (layer 1).
 */
#define PROXY_URI         "coap://[fd00::1]:5685"
#define SERVER_URI        "coap://[fd00::1]:5686"
#define SERVER_EDHOC_URI  "coap://[fd00::1]:5686/.well-known/edhoc"
#define SERVICE_URI       "helloWorld"
#define COSE_ALG_AES_CCM_16_64_128 10

/*
 * The proxy's credential (public key only), kid 0x33. The CCS that EDHOC
 * builds from it must match the proxy's CRED_R byte for byte, so the kid,
 * subject ("proxy.example"), x and y are the same as in EdhocProxy.java.
 */
static cose_key_t proxy_key = {
  .next = NULL,
  .kid = { 0x33 },
  .kid_sz = 1,
  .identity = { "proxy.example" },
  .identity_sz = sizeof("proxy.example") - 1,
  .kty = 2,                                   /* EC2 */
  .crv = 1,                                   /* P-256 */
  .ecc = {
    .pub = {
      .x = { 0xe5, 0x13, 0x67, 0xf6, 0x41, 0x83, 0xd8, 0xca, 0xd2, 0x98, 0xca, 0x0d, 0x09, 0xf3, 0xa3, 0x6e,
             0xfd, 0x45, 0x96, 0xc5, 0x2d, 0x83, 0x3f, 0x66, 0xa3, 0xff, 0x3c, 0x05, 0xf9, 0x1d, 0x7c, 0x73 },
      .y = { 0xe4, 0xa7, 0x43, 0x32, 0x0d, 0x80, 0x2d, 0x4d, 0x35, 0x50, 0xb3, 0x3f, 0xb5, 0xc2, 0xd2, 0xc3,
             0xc4, 0x82, 0x32, 0x01, 0x0e, 0xd8, 0xc4, 0x3a, 0xcd, 0x3e, 0x9e, 0xb8, 0x85, 0xb8, 0x0d, 0x96 }
    }
  }
};

/*---------------------------------------------------------------------------*/
/*
 * Results file read by summarise-edhoc-proxy.py. Each line is one step of the run:
 * "start ...", then one "edhoc..." line per EDHOC run, then "result ...".
 * Only on native, where the client can write to the host's file system.
 */
#if CONTIKI_TARGET_NATIVE
#define RESULT_FILE "../java-edhoc/logs/client-result.txt"
static void
record_result(const char *mode, const char *line)
{
  FILE *f = fopen(RESULT_FILE, mode);
  if(f != NULL) {
    fprintf(f, "%s\n", line);
    fclose(f);
  }
}
#else
#define record_result(mode, line)
#endif

/*---------------------------------------------------------------------------*/
/* Write len bytes of b as hex into out, for the log and the results file */
static void
hex(char *out, size_t out_sz, const uint8_t *b, uint8_t len)
{
  out[0] = '\0';
  for(uint8_t i = 0; i < len && 2 * (size_t)i + 3 <= out_sz; i++) {
    snprintf(out + 2 * i, 3, "%02x", b[i]);
  }
}
/*---------------------------------------------------------------------------*/
/* One OSCORE context per hop: [0] = proxy (outermost layer), [1] = server */
static oscore_ctx_t contexts[2];
static oscore_layer_t layers[2];
static oscore_path_t path;            /* the path registered for proxy_ep */
static coap_endpoint_t proxy_ep;      /* every request goes to the proxy */
/* OSCORE IDs per hop; oscore_derive_ctx() keeps pointers to these */
static uint8_t sender_id[2][EDHOC_MAX_CID_LEN], recipient_id[2][EDHOC_MAX_CID_LEN];
static uint8_t sender_id_len[2], recipient_id_len[2];
/*---------------------------------------------------------------------------*/
/*
 * Called once the EDHOC run with hop `hop` has finished: export its keys and
 * derive contexts[hop]. Must run before edhoc_client_close(), which frees
 * edhoc_ctx. Returns 0 on success, -1 on failure.
 */
static int
edhoc_to_oscore(int hop)
{
  edhoc_oscore_secret_t secret;
  char line[96], s[2 * EDHOC_MAX_CID_LEN + 1], r[2 * EDHOC_MAX_CID_LEN + 1];

  if(edhoc_exporter_oscore(&secret, edhoc_ctx) < 0) {
    LOG_ERR("EDHOC exporter failed (hop %d)\n", hop);
    return -1;
  }
  print_oscore_ctx(&secret);

  /* RFC 9528 A.1: the Initiator's Sender ID is C_R, its Recipient ID is C_I */
  sender_id_len[hop] = edhoc_ctx->state.cid_rx_len;
  memcpy(sender_id[hop], edhoc_ctx->state.cid_rx, sender_id_len[hop]);
  recipient_id_len[hop] = edhoc_ctx->state.cid_len;
  memcpy(recipient_id[hop], edhoc_ctx->state.cid, recipient_id_len[hop]);

  oscore_derive_ctx(&contexts[hop], secret.master_secret, OSCORE_KEY_SZ,
                    secret.master_salt, OSCORE_SALT_SZ, COSE_ALG_AES_CCM_16_64_128,
                    sender_id[hop], sender_id_len[hop],
                    recipient_id[hop], recipient_id_len[hop], NULL, 0);

  hex(s, sizeof(s), sender_id[hop], sender_id_len[hop]);
  hex(r, sizeof(r), recipient_id[hop], recipient_id_len[hop]);
  LOG_INFO("Hop %d OSCORE context from EDHOC: Sender ID %s, Recipient ID %s\n", hop, s, r);
  snprintf(line, sizeof(line), "edhoc%d OK sid=%s rid=%s", hop + 1, s, r);
  record_result("a", line);
  return 0;
}
/*---------------------------------------------------------------------------*/
/*
 * Called by COAP_BLOCKING_REQUEST with the decrypted response, or with NULL
 * if no response arrived (coap_error_message then says why). Only 2.05
 * (Content) counts as a successful run.
 */
static void
response_handler(coap_message_t *response)
{
  const uint8_t *chunk;
  char line[96];

  if(response == NULL) {
    printf("No response: %s\n", coap_error_message);
    snprintf(line, sizeof(line), "result FAILED %s",
             coap_error_message ? coap_error_message : "");
    record_result("a", line);
    return;
  }
  int len = coap_get_payload(response, &chunk);
  printf("response %u.%02u: \n|%.*s\n", response->code >> 5, response->code & 0x1f,
         len, (char *)chunk);
  if(response->code == CONTENT_2_05) {
    snprintf(line, sizeof(line), "result OK %.*s", len, (char *)chunk);
  } else {
    snprintf(line, sizeof(line), "result FAILED %u.%02u %.*s", response->code >> 5,
             response->code & 0x1f, len, (char *)chunk);
  }
  record_result("a", line);
}
/*---------------------------------------------------------------------------*/
PROCESS(oscore_edhoc_1_proxy_client, "OSCORE over EDHOC client, 1 proxy (Stage 2)");
AUTOSTART_PROCESSES(&oscore_edhoc_1_proxy_client);

PROCESS_THREAD(oscore_edhoc_1_proxy_client, ev, data)
{
  static struct etimer timer;
  static coap_message_t request[1];
  static int8_t status;
  static int hop;
  static char line[64];

  PROCESS_BEGIN();

  coap_endpoint_parse(PROXY_URI, strlen(PROXY_URI), &proxy_ep);
  snprintf(line, sizeof(line), "start layers=2 chunk=%d method=%d suite=2",
           COAP_MAX_CHUNK_SIZE, EDHOC_METHOD);
  record_result("w", line);

  printf("Waiting 20 s for the EDHOC proxy and server...\n");
  etimer_set(&timer, 20 * CLOCK_SECOND);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));

  /*
   * Credentials: this client's key pair and the server's public key
   * (RFC 9529 Trace 2), plus the proxy's public key. EDHOC finds the peer's
   * key by the kid in ID_CRED_R, so the same list serves both runs.
   */
  if(edhoc_create_key_list() != EDHOC_SUCCESS) {
    LOG_ERR("Could not create the EDHOC key list\n");
    PROCESS_EXIT();
  }
  {
    cose_key_t client_key = auth_rfc9529_static_dh_client;
    cose_key_t server_key = auth_rfc9529_static_dh_server;
    if(edhoc_setup_key_pair(&client_key, &server_key, "Client", "Server") != EDHOC_SUCCESS ||
       edhoc_add_key(&proxy_key) != EDHOC_SUCCESS) {
      LOG_ERR("Could not set up the EDHOC credentials\n");
      PROCESS_EXIT();
    }
  }

  /* One EDHOC run per hop, nearest hop first */
  for(hop = 0; hop < 2; hop++) {
    if(hop == 0) {
      /* Hop 1: EDHOC straight to the proxy, no OSCORE yet */
      printf("EDHOC 1: with the proxy at %s\n", PROXY_URI);
      edhoc_client_set_server(PROXY_URI, EDHOC_COAP_URI_PATH);
    } else {
      /* Hop 2: EDHOC with the server through the proxy. The messages go to
       * the proxy protected by the proxy's context; target_uri adds the
       * Proxy-Uri (inside that layer) telling the proxy where to forward. */
      layers[0].ctx = &contexts[0];
      layers[0].forward_to_uri = NULL;
      path.layers = layers;
      path.num_layers = 1;
      path.target_uri = SERVER_EDHOC_URI;
      if(!oscore_ep_path_set(&proxy_ep, &path)) {
        LOG_ERR("Could not set the OSCORE path for EDHOC 2\n");
        PROCESS_EXIT();
      }
      printf("EDHOC 2: with the server, through the proxy (Proxy-Uri %s)\n", SERVER_EDHOC_URI);
      edhoc_client_set_server(PROXY_URI, NULL);   /* no Uri-Path: Proxy-Uri instead */
    }

    /* Run EDHOC and wait for its process to report that it finished or failed */
    edhoc_client_run();
    while(1) {
      PROCESS_WAIT_EVENT();
      status = edhoc_client_callback(ev, data);
      if(status != 0) {
        break;          /* > 0 finished, < 0 failed */
      }
    }
    if(status < 0) {
      LOG_ERR("EDHOC %d failed (%d)\n", hop + 1, status);
      snprintf(line, sizeof(line), "edhoc%d FAILED %d", hop + 1, status);
      record_result("a", line);
      edhoc_client_close();
      PROCESS_EXIT();
    }
    printf("EDHOC %d finished\n", hop + 1);
    /* Keep only the OSCORE context; free the handshake state for the next run */
    status = edhoc_to_oscore(hop);
    edhoc_client_close();
    if(status < 0) {
      record_result("a", "result FAILED no OSCORE context");
      PROCESS_EXIT();
    }
  }

  /* 3. Both layers: [0] proxy (outermost), [1] server with the server's URI
   *    as the Proxy-Uri inside the proxy's layer */
  layers[0].ctx = &contexts[0];
  layers[0].forward_to_uri = NULL;
  layers[1].ctx = &contexts[1];
  layers[1].forward_to_uri = SERVER_URI;
  path.layers = layers;
  path.num_layers = 2;
  path.target_uri = NULL;
  if(!oscore_ep_path_set(&proxy_ep, &path)) {   /* replaces the EDHOC 2 path */
    LOG_ERR("Could not set the 2-layer OSCORE path\n");
    PROCESS_EXIT();
  }

  /* CON, so the response reaches the handler (Contiki drops responses to NON) */
  coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
  coap_set_header_uri_path(request, SERVICE_URI);
  request->dest_ep = &proxy_ep;
  printf("Sending GET /%s with 2 OSCORE layers via the proxy\n", SERVICE_URI);
  COAP_BLOCKING_REQUEST(&proxy_ep, request, response_handler);
  printf("--Done--\n");

  PROCESS_END();
}
