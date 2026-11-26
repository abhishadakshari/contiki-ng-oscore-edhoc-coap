/**
 * \file
 *         Project configuration for the Stage 2 client (one proxy). Same
 *         EDHOC settings as Stage 1, plus room for the proxy's key.
 * \author
 *         Abhishek Shadakshari
 */

#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* ---- EDHOC: method 3, cipher suite 2, credentials by reference (kid) ---- */
#define EDHOC_CONF_ROLE              EDHOC_INITIATOR
#define EDHOC_CONF_METHOD            EDHOC_METHOD3
#define EDHOC_CONF_AUTHENT_TYPE      EDHOC_CRED_KID
#define EDHOC_CONF_SUPPORTED_SUITE_1 EDHOC_CIPHERSUITE_2
#define EDHOC_AUTH_KID               0x2b      /* own credential (client, Trace 2) */
#define EDHOC_CONF_CID               0x37      /* own connection identifier C_I */
#define EDHOC_CONF_TIMEOUT           100000
/* Default peer; the program sets the peer of each run itself */
#define EDHOC_CONF_SERVER_EP         "coap://[fd00::1]:5685"
#define EDHOC_CONF_TEST              EDHOC_TEST_VECTOR_TRACE_DH

/* Own key + server + proxy (the default of 2 only fits one peer) */
#define EDHOC_CONF_MAX_KEYS          3

/* ---- Logging ---- */
#define LOG_CONF_LEVEL_EDHOC         LOG_LEVEL_INFO
#define LOG_CONF_LEVEL_COAP          LOG_LEVEL_WARN
#define LOG_CONF_WITH_COMPACT_BYTES  0

#endif /* PROJECT_CONF_H_ */
