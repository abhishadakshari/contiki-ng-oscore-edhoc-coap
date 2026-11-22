/*
 * Stage 1: EDHOC with the server only, then a 1-layer OSCORE request.
 *
 * 1. Run EDHOC (method 3, suite 2, CCS by kid) with the Java EdhocServer at
 *    EDHOC_CONF_SERVER_EP.
 * 2. Export the OSCORE Master Secret and Salt, and turn the EDHOC connection
 *    identifiers into OSCORE IDs (RFC 9528, Appendix A.1):
 *    client Sender ID = C_R (the server's), Recipient ID = C_I (our own).
 * 3. Register a 1-layer OSCORE path to the server and send GET /helloWorld.
 *
 * The outcome is written to ../java-edhoc/logs/client-result.txt for
 * summarise-edhoc.py.
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
#include "edhoc-cred-rfc9529.h"

#include "sys/log.h"
#define LOG_MODULE "client"
#define LOG_LEVEL  LOG_LEVEL_INFO

#define SERVICE_URI "helloWorld"
#define COSE_ALG_AES_CCM_16_64_128 10

/*---------------------------------------------------------------------------*/
/* Results file for summarise-edhoc.py (native only) */
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

static void
hex(char *out, size_t out_sz, const uint8_t *b, uint8_t len)
{
  out[0] = '\0';
  for(uint8_t i = 0; i < len && 2 * (size_t)i + 3 <= out_sz; i++) {
    snprintf(out + 2 * i, 3, "%02x", b[i]);
  }
}
/*---------------------------------------------------------------------------*/
static oscore_ctx_t context;          /* the OSCORE context from EDHOC */
static oscore_layer_t layer;
static oscore_path_t path;
static coap_endpoint_t server_ep;
static uint8_t sender_id[EDHOC_MAX_CID_LEN];
static uint8_t recipient_id[EDHOC_MAX_CID_LEN];
static uint8_t sender_id_len, recipient_id_len;

/* Called once EDHOC has finished: export the keys and build the OSCORE context.
 * Must run before edhoc_client_close(), which frees edhoc_ctx. */
static int
edhoc_to_oscore(void)
{
  edhoc_oscore_secret_t secret;
  char line[96], s[2 * EDHOC_MAX_CID_LEN + 1], r[2 * EDHOC_MAX_CID_LEN + 1];

  if(edhoc_exporter_oscore(&secret, edhoc_ctx) < 0) {
    LOG_ERR("EDHOC exporter failed\n");
    return -1;
  }
  print_oscore_ctx(&secret);

  /* RFC 9528 A.1: the Initiator's OSCORE Sender ID is C_R, Recipient ID is C_I */
  sender_id_len = edhoc_ctx->state.cid_rx_len;
  memcpy(sender_id, edhoc_ctx->state.cid_rx, sender_id_len);
  recipient_id_len = edhoc_ctx->state.cid_len;
  memcpy(recipient_id, edhoc_ctx->state.cid, recipient_id_len);

  oscore_derive_ctx(&context, secret.master_secret, OSCORE_KEY_SZ,
                    secret.master_salt, OSCORE_SALT_SZ, COSE_ALG_AES_CCM_16_64_128,
                    sender_id, sender_id_len, recipient_id, recipient_id_len,
                    NULL, 0);

  hex(s, sizeof(s), sender_id, sender_id_len);
  hex(r, sizeof(r), recipient_id, recipient_id_len);
  LOG_INFO("OSCORE context from EDHOC: Sender ID %s, Recipient ID %s\n", s, r);
  snprintf(line, sizeof(line), "edhoc OK sid=%s rid=%s", s, r);
  record_result("a", line);

  /* One layer, straight to the server (as NUM_LAYERS == 1 in the OSCORE client) */
  layer.ctx = &context;
  layer.forward_to_uri = NULL;
  path.layers = &layer;
  path.num_layers = 1;
  if(!oscore_ep_path_set(&server_ep, &path)) {
    LOG_ERR("Could not set the OSCORE path\n");
    return -1;
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
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
  printf("response: \n|%.*s\n", len, (char *)chunk);
  snprintf(line, sizeof(line), "result OK %.*s", len, (char *)chunk);
  record_result("a", line);
}
/*---------------------------------------------------------------------------*/
PROCESS(oscore_edhoc_client, "OSCORE over EDHOC client (Stage 1)");
AUTOSTART_PROCESSES(&oscore_edhoc_client);

PROCESS_THREAD(oscore_edhoc_client, ev, data)
{
  static struct etimer timer;
  static coap_message_t request[1];
  static int8_t status;
  static char line[64];

  PROCESS_BEGIN();

  coap_endpoint_parse(EDHOC_CONF_SERVER_EP, strlen(EDHOC_CONF_SERVER_EP), &server_ep);
  snprintf(line, sizeof(line), "start layers=1 chunk=%d method=%d suite=2",
           COAP_MAX_CHUNK_SIZE, EDHOC_METHOD);
  record_result("w", line);

  /* Give the Java server time to start after tun0 / fd00::1 exist */
  printf("Waiting 20 s for the EDHOC server...\n");
  etimer_set(&timer, 20 * CLOCK_SECOND);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));

  /* Credentials: RFC 9529 Trace 2 (our key pair, the server's public key) */
  if(edhoc_create_key_list() != EDHOC_SUCCESS) {
    LOG_ERR("Could not create the EDHOC key list\n");
    PROCESS_EXIT();
  }
  {
    cose_key_t client_key = auth_rfc9529_static_dh_client;
    cose_key_t server_key = auth_rfc9529_static_dh_server;
    if(edhoc_setup_key_pair(&client_key, &server_key, "Client", "Server") != EDHOC_SUCCESS) {
      LOG_ERR("Could not set up the EDHOC credentials\n");
      PROCESS_EXIT();
    }
  }

  /* 1. EDHOC */
  printf("Starting EDHOC with %s\n", EDHOC_CONF_SERVER_EP);
  edhoc_client_run();
  while(1) {
    PROCESS_WAIT_EVENT();
    status = edhoc_client_callback(ev, data);
    if(status != 0) {
      break;            /* > 0 finished, < 0 failed */
    }
  }
  if(status < 0) {
    LOG_ERR("EDHOC failed (%d)\n", status);
    snprintf(line, sizeof(line), "edhoc FAILED %d", status);
    record_result("a", line);
    edhoc_client_close();
    PROCESS_EXIT();
  }
  printf("EDHOC finished\n");

  /* 2. EDHOC -> OSCORE context and path */
  status = edhoc_to_oscore();
  edhoc_client_close();
  if(status < 0) {
    record_result("a", "result FAILED no OSCORE context");
    PROCESS_EXIT();
  }

  /* 3. OSCORE-protected request. CON, so the response reaches the handler
   *    (Contiki drops responses to NON requests); the size is the same. */
  coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
  coap_set_header_uri_path(request, SERVICE_URI);
  request->dest_ep = &server_ep;
  printf("Sending GET /%s with OSCORE\n", SERVICE_URI);
  COAP_BLOCKING_REQUEST(&server_ep, request, response_handler);
  printf("--Done--\n");

  PROCESS_END();
}
