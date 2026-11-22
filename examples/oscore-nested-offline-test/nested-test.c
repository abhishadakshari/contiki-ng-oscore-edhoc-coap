/*
 * Native test for nested OSCORE on the client.
 *
 * Runs in one process with no network: the client wraps a request in N
 * OSCORE layers, the matching peer contexts peel them off one by one, then
 * the peers wrap a response in N layers and the client removes them.
 *
 * Build and run:  make TARGET=native && ./nested-test.native
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "contiki.h"
#include "coap-engine.h"
#include "coap.h"
#include "oscore.h"
#include "oscore-context.h"
#include "oscore-layer.h"
#include "oscore-cose.h"
#include "nanocbor/nanocbor.h"

#define MAX_N 5                       /* largest number of layers tried */

static int checks, failures;
/* The reason a failed send leaves in coap_error_message. */
#define CHECK_REASON(expected)                                       \
  CHECK(strcmp(coap_error_message, (expected)) == 0,                 \
        "reason was \"%s\", expected \"%s\"", coap_error_message, (expected))

#define CHECK(cond, ...) do {                      \
    checks++;                                      \
    if(!(cond)) {                                  \
      failures++;                                  \
      printf("    FAIL: " __VA_ARGS__);            \
      printf("\n");                                \
    }                                              \
  } while(0)

/* Keying material shared by client and peers (test values only). */
static uint8_t master_secret[16] = {
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
static uint8_t master_salt[8] = { 0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40 };

/* Layer k: client Sender ID 0x10+k, Recipient ID 0x20+k. Peers use the
 * same IDs swapped. Distinct IDs per layer matter: the client and peer
 * contexts share one list and lookups return the first match. */
static uint8_t client_sid[MAX_N][1], client_rid[MAX_N][1];
static oscore_ctx_t client_ctx[MAX_N], peer_ctx[MAX_N];

/* Where each layer's hop forwards to (unused for layer 0). */
static const char *hop_uri[MAX_N] = {
  NULL,
  "coap://[fd00::2]:5683",
  "coap://[fd00::3]:5683",
  "coap://[fd00::4]:5683",
  "coap://[fd00::1]:5675",
};

static oscore_layer_t client_layers[MAX_N], peer_layers[MAX_N];
static oscore_path_t client_path, peer_path;
static coap_endpoint_t proxy_ep, client_ep, plain_ep;

static uint8_t wire[COAP_MAX_PACKET_SIZE + 64];
static coap_message_t msg;
static uint16_t next_mid = 1;
static uint8_t next_token = 1;

/*---------------------------------------------------------------------------*/
static void
derive_contexts(void)
{
  for(int k = 0; k < MAX_N; k++) {
    client_sid[k][0] = 0x10 + k;
    client_rid[k][0] = 0x20 + k;
    oscore_derive_ctx(&client_ctx[k], master_secret, sizeof(master_secret),
                      master_salt, sizeof(master_salt), 10,
                      client_sid[k], 1, client_rid[k], 1, NULL, 0);
    oscore_derive_ctx(&peer_ctx[k], master_secret, sizeof(master_secret),
                      master_salt, sizeof(master_salt), 10,
                      client_rid[k], 1, client_sid[k], 1, NULL, 0);
  }
}
/*---------------------------------------------------------------------------*/
static void
set_paths(int n)
{
  for(int k = 0; k < n; k++) {
    client_layers[k].ctx = &client_ctx[k];
    client_layers[k].forward_to_uri = (k == 0) ? NULL : hop_uri[k];
    peer_layers[k].ctx = &peer_ctx[k];
    peer_layers[k].forward_to_uri = NULL;   /* responses carry no routing */
  }
  client_path.layers = client_layers;
  client_path.num_layers = n;
  peer_path.layers = peer_layers;
  peer_path.num_layers = n;
  oscore_ep_path_set(&proxy_ep, &client_path);
  oscore_ep_path_set(&client_ep, &peer_path);
}
/*---------------------------------------------------------------------------*/
/* Client: build GET hello/1 and protect it with the path for proxy_ep. */
static size_t
send_request(coap_message_t *req, uint8_t token)
{
  coap_init_message(req, COAP_TYPE_CON, COAP_GET, next_mid++);
  coap_set_header_uri_path(req, "hello/1");
  uint8_t tok[2] = { 0xA0, token };
  coap_set_token(req, tok, sizeof(tok));
  coap_set_option(req, COAP_OPTION_OSCORE);
  req->dest_ep = &proxy_ep;
  return coap_serialize_message(req, wire);
}
/*---------------------------------------------------------------------------*/
static bool
proxy_uri_is(const coap_message_t *m, const char *uri)
{
  return m->proxy_uri_len == strlen(uri) &&
         memcmp(m->proxy_uri, uri, m->proxy_uri_len) == 0;
}
/*---------------------------------------------------------------------------*/
/* True if the outer (unencrypted) message on the wire has a Proxy-Uri. */
static bool
wire_has_proxy_uri(size_t len)
{
  static uint8_t copy[sizeof(wire)];
  static coap_message_t outer;
  memcpy(copy, wire, len);
  coap_parse_message_no_decrypt(&outer, copy, len);
  return coap_is_option(&outer, COAP_OPTION_PROXY_URI);
}
/*---------------------------------------------------------------------------*/
/* Request and response through n layers. */
static void
test_layers(int n)
{
  static coap_message_t req, resp;
  printf("  %d layer(s)\n", n);
  set_paths(n);

  uint8_t token = next_token++;
  size_t len = send_request(&req, token);
  printf("    request: %u bytes on the wire\n", (unsigned)len);
  CHECK(len > 0 && len <= COAP_MAX_PACKET_SIZE, "request not protected (returned %u)", (unsigned)len);
  if(len == 0 || len > COAP_MAX_PACKET_SIZE) {
    return;
  }
  CHECK(!wire_has_proxy_uri(len), "Proxy-Uri visible outside the outer layer");

  /* Peers peel the request, outermost layer first. */
  coap_status_t s = coap_parse_message(&msg, wire, len);
  CHECK(s == NO_ERROR, "layer 0 not removed (status %u)", s);
  for(int k = 1; k < n && s == NO_ERROR; k++) {
    CHECK(proxy_uri_is(&msg, hop_uri[k]), "layer %d: wrong Proxy-Uri", k - 1);
    s = oscore_decode_message(&msg);
    CHECK(s == NO_ERROR, "layer %d not removed (status %u)", k, s);
  }
  if(s != NO_ERROR) {
    return;
  }
  const char *path;
  size_t path_len = coap_get_header_uri_path(&msg, &path);
  CHECK(msg.code == COAP_GET, "inner code is %u, expected GET", msg.code);
  CHECK(path_len == 7 && memcmp(path, "hello/1", 7) == 0, "inner Uri-Path wrong");

  /* Peers wrap a response in n layers, innermost (server) first. */
  coap_init_message(&resp, COAP_TYPE_ACK, CONTENT_2_05, req.mid);
  uint8_t tok[2] = { 0xA0, token };
  coap_set_token(&resp, tok, sizeof(tok));
  coap_set_payload(&resp, "hi", 2);
  coap_set_option(&resp, COAP_OPTION_OSCORE);
  resp.dest_ep = &client_ep;
  len = coap_serialize_message(&resp, wire);
  printf("    response: %u bytes on the wire\n", (unsigned)len);
  CHECK(len > 0 && len <= COAP_MAX_PACKET_SIZE, "response not protected (returned %u)", (unsigned)len);
  if(len == 0 || len > COAP_MAX_PACKET_SIZE) {
    return;
  }

  /* Client removes the n layers. */
  s = oscore_handle_message(&msg, wire, len, &proxy_ep);
  CHECK(s == NO_ERROR, "response not decrypted (status %u)", s);
  if(s == NO_ERROR) {
    CHECK(msg.code == CONTENT_2_05, "response code %u, expected 2.05", msg.code);
    CHECK(msg.payload_len == 2 && memcmp(msg.payload, "hi", 2) == 0, "response payload wrong");
  }
}
/*---------------------------------------------------------------------------*/
/* A path that ends at a proxy (Onion CoAP paper, Section VI, steps 4-6):
 * reach a hop that shares no context with us yet, as for EDHOC message_1
 * to the next proxy. The message is not protected end to end. */
static const char *edhoc_target = "coap://[fd00::5]:5683";

static void
test_path_to_proxy(int n)
{
  static coap_message_t req, resp;
  printf("  %d layer(s) ending at a proxy\n", n);
  set_paths(n);
  client_path.target_uri = edhoc_target;

  uint8_t token = next_token++;
  uint8_t tok[2] = { 0xA0, token };
  coap_init_message(&req, COAP_TYPE_CON, COAP_POST, next_mid++);
  coap_set_header_uri_path(&req, ".well-known/edhoc");
  coap_set_payload(&req, "msg1", 4);
  coap_set_token(&req, tok, sizeof(tok));
  coap_set_option(&req, COAP_OPTION_OSCORE);
  req.dest_ep = &proxy_ep;
  size_t len = coap_serialize_message(&req, wire);
  printf("    request: %u bytes on the wire\n", (unsigned)len);
  CHECK(len > 0 && len <= COAP_MAX_PACKET_SIZE, "request not protected (returned %u)", (unsigned)len);
  if(len == 0 || len > COAP_MAX_PACKET_SIZE) {
    client_path.target_uri = NULL;
    return;
  }
  CHECK(!wire_has_proxy_uri(len), "Proxy-Uri visible outside the outer layer");

  /* The proxies peel their layers; the last one finds where to forward. */
  coap_status_t s = coap_parse_message(&msg, wire, len);
  CHECK(s == NO_ERROR, "layer 0 not removed (status %u)", s);
  for(int k = 1; k < n && s == NO_ERROR; k++) {
    CHECK(proxy_uri_is(&msg, hop_uri[k]), "layer %d: wrong Proxy-Uri", k - 1);
    s = oscore_decode_message(&msg);
    CHECK(s == NO_ERROR, "layer %d not removed (status %u)", k, s);
  }
  if(s == NO_ERROR) {
    const char *path;
    size_t path_len = coap_get_header_uri_path(&msg, &path);
    CHECK(proxy_uri_is(&msg, edhoc_target), "innermost Proxy-Uri is not the target");
    CHECK(msg.object_security == NULL, "an OSCORE option was left inside the innermost layer");
    CHECK(msg.code == COAP_POST, "inner code is %u, expected POST", msg.code);
    CHECK(path_len == 17 && memcmp(path, ".well-known/edhoc", 17) == 0, "inner Uri-Path wrong");
    CHECK(msg.payload_len == 4 && memcmp(msg.payload, "msg1", 4) == 0, "inner payload wrong");
  }
  client_path.target_uri = NULL;
  if(s != NO_ERROR) {
    return;
  }

  /* The proxies wrap the target's unprotected reply (EDHOC message_2). */
  coap_init_message(&resp, COAP_TYPE_ACK, CHANGED_2_04, req.mid);
  coap_set_token(&resp, tok, sizeof(tok));
  coap_set_payload(&resp, "msg2", 4);
  coap_set_option(&resp, COAP_OPTION_OSCORE);
  resp.dest_ep = &client_ep;
  len = coap_serialize_message(&resp, wire);
  s = oscore_handle_message(&msg, wire, len, &proxy_ep);
  CHECK(s == NO_ERROR, "response not decrypted (status %u)", s);
  if(s == NO_ERROR) {
    CHECK(msg.payload_len == 4 && memcmp(msg.payload, "msg2", 4) == 0, "response payload wrong");
  }
}
/*---------------------------------------------------------------------------*/
/* Proxies draft section 2.1: more layers than OSCORE_MAX_LAYERS is refused. */
static void
test_too_many_layers(void)
{
  static coap_message_t req;
  printf("  %d layers (over OSCORE_MAX_LAYERS)\n", OSCORE_MAX_LAYERS + 1);
  set_paths(OSCORE_MAX_LAYERS);            /* a valid path is registered */
  client_path.num_layers = OSCORE_MAX_LAYERS + 1;   /* then made too long */
  coap_error_message = "";
  size_t len = send_request(&req, next_token++);
  CHECK(len == 0, "request with too many layers was sent (returned %u)", (unsigned)len);
  CHECK_REASON("OSCORE: more layers than OSCORE_MAX_LAYERS");
}
/*---------------------------------------------------------------------------*/
/* Draft section 2.6: an OSCORE option left after removing our layers is an error. */
static void
test_leftover_layer(void)
{
  static coap_message_t req, resp;
  printf("  response with one layer more than the request\n");
  set_paths(3);
  uint8_t token = next_token++;
  size_t len = send_request(&req, token);
  coap_status_t s = coap_parse_message(&msg, wire, len);
  for(int k = 1; k < 3 && s == NO_ERROR; k++) {
    s = oscore_decode_message(&msg);
  }
  CHECK(s == NO_ERROR, "setup failed");

  coap_init_message(&resp, COAP_TYPE_ACK, CONTENT_2_05, req.mid);
  uint8_t tok[2] = { 0xA0, token };
  coap_set_token(&resp, tok, sizeof(tok));
  coap_set_payload(&resp, "hi", 2);
  coap_set_option(&resp, COAP_OPTION_OSCORE);
  resp.dest_ep = &client_ep;
  len = coap_serialize_message(&resp, wire);

  client_path.num_layers = 2;   /* client now expects one layer fewer */
  s = oscore_handle_message(&msg, wire, len, &proxy_ep);
  CHECK(s != NO_ERROR, "accepted a response with an OSCORE option left over");
}
/*---------------------------------------------------------------------------*/
/* Fix 1b: an unprotected response to a protected request. */
static void
test_unprotected_response(uint8_t code, bool expect_accept)
{
  static coap_message_t req, resp;
  printf("  unprotected response, code %u.%02u\n", code >> 5, code & 0x1f);
  set_paths(2);
  uint8_t token = next_token++;
  send_request(&req, token);

  coap_init_message(&resp, COAP_TYPE_ACK, code, req.mid);
  uint8_t tok[2] = { 0xA0, token };
  coap_set_token(&resp, tok, sizeof(tok));
  size_t len = coap_serialize_message(&resp, wire);   /* no OSCORE bit: plain */

  coap_status_t s = oscore_handle_message(&msg, wire, len, &proxy_ep);
  if(expect_accept) {
    CHECK(s == NO_ERROR, "allowed error response rejected (status %u)", s);
  } else {
    CHECK(s == OSCORE_DECRYPTION_ERROR, "unprotected response accepted (status %u)", s);
  }
}
/*---------------------------------------------------------------------------*/
/* Fix 1c: when the token store is full, the oldest entry must go. */
static void
test_eviction(void)
{
  printf("  token store eviction (%u slots)\n", TOKEN_SEQ_NUM);
  oscore_exchange_store_init();
  for(int i = 0; i <= TOKEN_SEQ_NUM; i++) {
    uint8_t tok[2] = { 0xEE, (uint8_t)i };
    oscore_set_exchange(tok, 2, i, &client_ctx[0]);
  }
  uint8_t oldest[2] = { 0xEE, 0 };
  uint8_t prev[2] = { 0xEE, TOKEN_SEQ_NUM - 1 };
  uint8_t newest[2] = { 0xEE, TOKEN_SEQ_NUM };
  CHECK(oscore_get_exchange(oldest, 2) == NULL, "oldest entry was kept");
  CHECK(oscore_get_exchange(prev, 2) != NULL, "second-newest entry was evicted");
  CHECK(oscore_get_exchange(newest, 2) != NULL, "newest entry missing");
  oscore_exchange_store_init();
}
/*---------------------------------------------------------------------------*/
/* Fix 1d: an exhausted sender sequence number must stop sending. */
static void
test_seq_exhausted(void)
{
  static coap_message_t req;
  printf("  sender sequence number exhausted\n");
  set_paths(1);
  uint64_t saved = client_ctx[0].sender_context.seq;
  client_ctx[0].sender_context.seq = OSCORE_SEQ_MAX;
  coap_error_message = "";
  size_t len = send_request(&req, next_token++);
  CHECK(len == 0, "request sent with an exhausted context (returned %u)", (unsigned)len);
  CHECK_REASON("OSCORE: sender sequence number exhausted");
  client_ctx[0].sender_context.seq = saved;
}
/*---------------------------------------------------------------------------*/
/* Proxies draft 2.5: hop k+1 cannot remove its layer and replies with a
 * plain error; only the hops before it add their layers on the way back. */
static void
test_error_from_inner_hop(uint8_t code, bool expect_accept)
{
  static coap_message_t req, resp;
  printf("  plain %u.%02u from hop 2 of 3, wrapped by hop 1 only\n", code >> 5, code & 0x1f);
  set_paths(3);
  uint8_t token = next_token++;
  size_t len = send_request(&req, token);
  /* Hop 1 removes its layer (recording the request for its reply); hop 2
   * then fails to remove the next one. */
  coap_status_t s = coap_parse_message(&msg, wire, len);
  CHECK(s == NO_ERROR, "hop 1 could not remove its layer (status %u)", s);

  coap_init_message(&resp, COAP_TYPE_ACK, code, req.mid);
  uint8_t tok[2] = { 0xA0, token };
  coap_set_token(&resp, tok, sizeof(tok));
  coap_set_payload(&resp, "Security context not found", 26);
  coap_set_option(&resp, COAP_OPTION_OSCORE);
  resp.dest_ep = &client_ep;
  peer_path.num_layers = 1;            /* only hop 1 protects the reply */
  len = coap_serialize_message(&resp, wire);
  CHECK(len > 0, "could not build the wrapped error");

  coap_error_message = "";
  s = oscore_handle_message(&msg, wire, len, &proxy_ep);
  if(expect_accept) {
    CHECK(s == NO_ERROR, "error from inner hop rejected (status %u)", s);
    CHECK(msg.code == code, "code %u, expected %u", msg.code, code);
    CHECK_REASON("Error 4.01 from hop 2 of 3");
  } else {
    CHECK(s == OSCORE_DECRYPTION_ERROR, "unprotected success from inner hop accepted (status %u)", s);
  }
  uint8_t t[2] = { 0xA0, token };
  CHECK(oscore_get_exchange(t, 2) == NULL, "token entries left behind");
}
/*---------------------------------------------------------------------------*/
/* Each way protection can fail must say why in coap_error_message. */
static void
test_failure_reasons(void)
{
  static coap_message_t req;
  static uint8_t big[COAP_MAX_CHUNK_SIZE];   /* payload alone fills the chunk */
  static char long_uri[90];
  size_t len;
  printf("  failure reasons\n");

  /* No context: OSCORE requested, but none attached and no path. */
  coap_init_message(&req, COAP_TYPE_CON, COAP_GET, next_mid++);
  coap_set_option(&req, COAP_OPTION_OSCORE);
  req.dest_ep = &plain_ep;
  coap_error_message = "";
  len = coap_serialize_message(&req, wire);
  CHECK(len == 0, "sent without a context");
  CHECK_REASON("OSCORE: no security context");

  /* Too large: one layer, but a payload that leaves no room for the tag. */
  set_paths(1);
  coap_init_message(&req, COAP_TYPE_CON, COAP_POST, next_mid++);
  memset(big, 'x', sizeof(big));
  coap_set_payload(&req, big, sizeof(big));
  uint8_t tok[2] = { 0xC0, next_token++ };
  coap_set_token(&req, tok, sizeof(tok));
  coap_set_option(&req, COAP_OPTION_OSCORE);
  req.dest_ep = &proxy_ep;
  coap_error_message = "";
  len = coap_serialize_message(&req, wire);
  CHECK(len == 0, "oversized request was sent");
  CHECK_REASON("OSCORE: message too large for COAP_MAX_CHUNK_SIZE");

  /* Options too long: an 80-character Proxy-Uri overflows COAP_MAX_HEADER_SIZE.
   * The serialiser's own reason must survive. */
  memset(long_uri, 'a', sizeof(long_uri) - 1);
  memcpy(long_uri, "coap://", 7);
  long_uri[80] = '\0';
  client_path.target_uri = long_uri;
  coap_error_message = "";
  len = send_request(&req, next_token++);
  CHECK(len == 0, "request with oversized options was sent");
  CHECK_REASON("Serialized header exceeds COAP_MAX_HEADER_SIZE");
  client_path.target_uri = NULL;
}
/*---------------------------------------------------------------------------*/
/* Proxies draft 2.6: a response that carries its own Partial IV.
 * Built here by hand, following RFC 8613 sections 5.2-5.4 directly, so the
 * client's decoding is checked against an independent encoder. */
static size_t
build_response_with_piv(coap_message_t *r, const uint8_t *tok, uint16_t mid,
                        uint8_t req_piv, uint8_t resp_piv)
{
  static uint8_t pt[COAP_MAX_PACKET_SIZE];
  static uint8_t opt[2];
  coap_init_message(r, COAP_TYPE_ACK, CONTENT_2_05, mid);
  coap_set_token(r, tok, 2);
  coap_set_payload(r, "piv", 3);
  size_t pt_len = oscore_serializer(r, pt, ROLE_CONFIDENTIAL);

  /* external_aad = [1, [alg], request_kid, request_piv, h''] */
  uint8_t ext[32], aad[48];
  nanocbor_encoder_t e;
  nanocbor_encoder_init(&e, ext, sizeof(ext));
  nanocbor_fmt_array(&e, 5);
  nanocbor_fmt_uint(&e, 1);
  nanocbor_fmt_array(&e, 1);
  nanocbor_fmt_uint(&e, 10);
  nanocbor_put_bstr(&e, client_sid[0], 1);
  nanocbor_put_bstr(&e, &req_piv, 1);
  nanocbor_put_bstr(&e, NULL, 0);
  size_t ext_len = nanocbor_encoded_len(&e);
  nanocbor_encoder_init(&e, aad, sizeof(aad));
  nanocbor_fmt_array(&e, 3);
  nanocbor_put_tstr(&e, "Encrypt0");
  nanocbor_put_bstr(&e, NULL, 0);
  nanocbor_put_bstr(&e, ext, ext_len);

  /* Nonce from the responder's Sender ID and the response's Partial IV. */
  cose_encrypt0_t c;
  uint8_t nonce[13];
  cose_encrypt0_init(&c);
  cose_encrypt0_set_alg(&c, 10);
  cose_encrypt0_set_key(&c, peer_ctx[0].sender_context.sender_key, 16);
  cose_encrypt0_set_key_id(&c, client_rid[0], 1);
  cose_encrypt0_set_partial_iv(&c, &resp_piv, 1);
  r->security_context = &peer_ctx[0];
  oscore_generate_nonce(&c, r, nonce, sizeof(nonce));
  cose_encrypt0_set_nonce(&c, nonce, sizeof(nonce));
  cose_encrypt0_set_aad(&c, aad, nanocbor_encoded_len(&e));
  cose_encrypt0_set_content(&c, pt, pt_len);
  int ct_len = cose_encrypt0_encrypt(&c);

  /* Outer message: OSCORE option = flag byte (Partial IV length 1) + Partial IV. */
  opt[0] = 0x01;
  opt[1] = resp_piv;
  r->code = CHANGED_2_04;
  coap_set_header_object_security(r, opt, sizeof(opt));
  coap_set_payload(r, pt, ct_len);
  oscore_clear_options(r);
  return oscore_serializer(r, wire, ROLE_COAP);
}

static void
test_response_with_piv(void)
{
  static coap_message_t req, resp;
  printf("  response carrying its own Partial IV\n");
  coap_init_message(&req, COAP_TYPE_CON, COAP_GET, next_mid++);
  coap_set_header_uri_path(&req, "hello/1");
  uint8_t tok[2] = { 0xB0, next_token++ };
  coap_set_token(&req, tok, sizeof(tok));
  uint8_t req_piv = (uint8_t)client_ctx[0].sender_context.seq;
  coap_set_oscore(&req, &client_ctx[0]);
  req.dest_ep = &plain_ep;                 /* no path: plain OSCORE */
  size_t len = coap_serialize_message(&req, wire);
  CHECK(len > 0, "request not protected");

  len = build_response_with_piv(&resp, tok, req.mid, req_piv, 0x07);
  coap_status_t s = oscore_handle_message(&msg, wire, len, &plain_ep);
  CHECK(s == NO_ERROR, "response with Partial IV not decrypted (status %u)", s);
  if(s == NO_ERROR) {
    CHECK(msg.payload_len == 3 && memcmp(msg.payload, "piv", 3) == 0, "payload wrong");
  }
}
/*---------------------------------------------------------------------------*/
PROCESS(nested_test, "Nested OSCORE test");
AUTOSTART_PROCESSES(&nested_test);

PROCESS_THREAD(nested_test, ev, data)
{
  PROCESS_BEGIN();

  coap_endpoint_parse("coap://[fd00::1]:5685", 21, &proxy_ep);
  coap_endpoint_parse("coap://[fd00::302:304:506:708]", 30, &client_ep);
  coap_endpoint_parse("coap://[fd00::9]", 16, &plain_ep);
  derive_contexts();

  printf("Nested OSCORE test, COAP_MAX_CHUNK_SIZE = %u, OSCORE_MAX_LAYERS = %u\n",
         COAP_MAX_CHUNK_SIZE, OSCORE_MAX_LAYERS);
  for(int n = 1; n <= OSCORE_MAX_LAYERS; n++) {
    test_layers(n);
  }
  test_too_many_layers();
  test_path_to_proxy(1);
  test_path_to_proxy(2);
  test_path_to_proxy(3);
  test_leftover_layer();
  test_unprotected_response(CONTENT_2_05, false);
  test_unprotected_response(UNAUTHORIZED_4_01, true);
  test_eviction();
  test_seq_exhausted();
  test_response_with_piv();
  test_failure_reasons();
  test_error_from_inner_hop(UNAUTHORIZED_4_01, true);
  test_error_from_inner_hop(CONTENT_2_05, false);

  printf("%d checks, %d failed\n", checks, failures);
  exit(failures == 0 ? 0 : 1);

  PROCESS_END();
}
