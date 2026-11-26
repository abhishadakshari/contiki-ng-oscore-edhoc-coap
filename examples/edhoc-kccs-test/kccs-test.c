/**
 * \file
 *         Offline checks for credentials by value ('kccs') in the EDHOC
 *         module, using the RFC 9529 Trace 2 credentials. No network needed:
 *         run the .native and it prints the number of checks and failures.
 *
 *         Checks that a received {14: CCS} is parsed and its exact bytes used
 *         as CRED_X, that an untrusted key sent by value is rejected, that
 *         credentials by reference still work, that this node sends
 *         {14: CRED_I}, and that the ID_CRED_X and TH_4 buffers are large
 *         enough for a credential by value.
 * \author
 *         Abhishek Shadakshari
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "contiki.h"
#include "edhoc.h"
#include "edhoc-msgs.h"
#include "edhoc-key-storage.h"
#include "edhoc-cred-rfc9529.h"
#include "lib/cbor.h"

/* Count the checks and print each one that fails */
static int checks, failed;
#define CHECK(c, ...) do { checks++; if(!(c)) { failed++; printf("  FAIL: " __VA_ARGS__); printf("\n"); } } while(0)

/* Convert a hex string into bytes; returns the number of bytes */
static size_t unhex(const char *h, uint8_t *b) { size_t n = 0; while(h[0] && h[1]) { unsigned v; sscanf(h, "%2x", &v); b[n++] = v; h += 2; } return n; }

/* RFC 9529 Trace 2 CRED_R, as the Java server now sends it */
static const char *CRED_R = "A2026B6578616D706C652E65647508A101A501020241322001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072";

PROCESS(t, "kccs test");
AUTOSTART_PROCESSES(&t);
PROCESS_THREAD(t, ev, data)
{
  PROCESS_BEGIN();
  uint8_t cred[200], idc[220], out[220];
  size_t cred_sz = unhex(CRED_R, cred);
  cose_key_t ck = auth_rfc9529_static_dh_client, sk = auth_rfc9529_static_dh_server;
  edhoc_create_key_list();
  edhoc_setup_key_pair(&ck, &sk, "Client", "Server");

  /* 1. {14: CRED_R} is parsed, and CRED_X is the received bytes */
  idc[0] = 0xA1; idc[1] = 0x0E; memcpy(idc + 2, cred, cred_sz);
  {
    cbor_reader_state_t r; cose_key_t key; const uint8_t *cv = NULL; size_t cvs = 0;
    cbor_init_reader(&r, idc, cred_sz + 2);
    int8_t n = edhoc_get_key_id_cred_x(&r, out, sizeof(out), &key, &cv, &cvs);
    CHECK(n == (int8_t)(cred_sz + 2), "kccs: returned size %d, expected %d", n, (int)cred_sz + 2);
    CHECK(cv && cvs == cred_sz && memcmp(cv, cred, cred_sz) == 0, "kccs: CRED_X is not the received CCS");
    CHECK(n > 0 && memcmp(out, idc, cred_sz + 2) == 0, "kccs: ID_CRED_X not copied as received");
    CHECK(key.kid_sz == 1 && key.kid[0] == 0x32, "kccs: wrong kid");
  }
  /* 2. A credential by value with an untrusted key is rejected */
  {
    uint8_t bad[220]; memcpy(bad, idc, cred_sz + 2); bad[2 + 30] ^= 0x01;   /* flip a bit of x */
    cbor_reader_state_t r; cose_key_t key; const uint8_t *cv = NULL; size_t cvs = 0;
    cbor_init_reader(&r, bad, cred_sz + 2);
    int8_t n = edhoc_get_key_id_cred_x(&r, out, sizeof(out), &key, &cv, &cvs);
    CHECK(n < 0, "kccs: key not matching the trusted one was accepted");
  }
  /* 3. By reference still works: {4: h'32'} and compact 0x32, no CRED_X returned */
  {
    uint8_t m[] = { 0xA1, 0x04, 0x41, 0x32 };
    cbor_reader_state_t r; cose_key_t key; const uint8_t *cv = (const uint8_t *)1; size_t cvs = 9;
    cbor_init_reader(&r, m, sizeof(m));
    int8_t n = edhoc_get_key_id_cred_x(&r, out, sizeof(out), &key, &cv, &cvs);
    CHECK(n == 4 && cv == NULL && cvs == 0 && key.kid[0] == 0x32, "kid map: n=%d", n);
    uint8_t c[] = { 0x32 };
    cbor_init_reader(&r, c, sizeof(c));
    n = edhoc_get_key_id_cred_x(&r, out, sizeof(out), &key, &cv, &cvs);
    CHECK(n == 4 && cv == NULL && memcmp(out, m, 4) == 0, "compact kid: n=%d", n);
  }
  /* 4. Sending by value: ID_CRED_I = {14: CRED_I}, and CRED_I is Trace 2's */
  {
    const char *CRED_I = "A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8";
    uint8_t ci[200]; size_t ci_sz = unhex(CRED_I, ci);
    size_t g = edhoc_generate_cred_x(&ck, out, sizeof(out));
    CHECK(g == ci_sz && memcmp(out, ci, ci_sz) == 0, "CRED_I built by Contiki differs from Trace 2");
    size_t gi = edhoc_generate_id_cred_x(&ck, out, sizeof(out));
    CHECK(gi == ci_sz + 2 && out[0] == 0xA1 && out[1] == 0x0E && memcmp(out + 2, ci, ci_sz) == 0,
          "ID_CRED_I is not {14: CRED_I} (%u bytes)", (unsigned)gi);
  }
  /* 5. The context's ID_CRED_X buffer is big enough for a credential by value */
  CHECK(EDHOC_MAX_ID_CRED_LEN >= 109, "EDHOC_MAX_ID_CRED_LEN is %d, too small for {14: CCS}",
        (int)EDHOC_MAX_ID_CRED_LEN);
  /* 6. TH_4 can be computed for a credential by value: TH_3 + a 118-byte
   *    PLAINTEXT_3 + the 107-byte CRED_I = 259 bytes, more than the old 256 */
  {
    static edhoc_context_t c;
    static uint8_t pt[118], cr[107];
    uint8_t before[HASH_LEN];
    memcpy(before, c.state.th, HASH_LEN);
    uint8_t r = edhoc_generate_transcript_hash_4(&c, cr, sizeof(cr), pt, sizeof(pt));
    CHECK(r == 0 && memcmp(before, c.state.th, HASH_LEN) != 0,
          "TH_4 not computed for a 259-byte input (returned %u)", r);
  }
  printf("%d checks, %d failed\n", checks, failed);
  exit(failed ? 1 : 0);
  PROCESS_END();
}
