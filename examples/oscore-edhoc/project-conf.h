#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* ---- EDHOC: method 3, cipher suite 2, CCS by kid (RFC 9529 Trace 2) ---- */
#define EDHOC_CONF_ROLE              EDHOC_INITIATOR
#define EDHOC_CONF_METHOD            EDHOC_METHOD3
#define EDHOC_CONF_AUTHENT_TYPE      EDHOC_CRED_INCLUDE
#define EDHOC_CONF_SUPPORTED_SUITE_1 EDHOC_CIPHERSUITE_2
#define EDHOC_AUTH_KID               0x2b      /* own credential (client) */
#define EDHOC_CONF_CID               0x37      /* own connection identifier C_I */
#define EDHOC_CONF_TIMEOUT           100000
/* Java EdhocServer (examples/java-edhoc) */
#define EDHOC_CONF_SERVER_EP         "coap://[fd00::1]:5686"
/* Use the RFC 9529 Trace 2 ephemeral key, so message_1 can be compared with the RFC */
#define EDHOC_CONF_TEST              EDHOC_TEST_VECTOR_TRACE_DH

/* ---- Logging ---- */
#define LOG_CONF_LEVEL_EDHOC         LOG_LEVEL_INFO
#define LOG_CONF_LEVEL_COAP          LOG_LEVEL_WARN
#define LOG_CONF_WITH_COMPACT_BYTES  0

#define COAP_MAX_CHUNK_SIZE 160

#endif /* PROJECT_CONF_H_ */
