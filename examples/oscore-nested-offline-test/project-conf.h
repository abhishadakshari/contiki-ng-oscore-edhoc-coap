#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* Keep the OSCORE/CoAP debug output quiet so the test results are readable. */
#define LOG_CONF_LEVEL_COAP LOG_LEVEL_WARN
#define LOG_CONF_LEVEL_MAIN LOG_LEVEL_WARN

/* 4 layers need about 131 bytes of ciphertext in the outermost layer, more
 * than the default 128. Override from the command line to try other sizes:
 *   make TARGET=native CHUNK=128   */
#ifdef TEST_CHUNK_SIZE
#define REST_MAX_CHUNK_SIZE TEST_CHUNK_SIZE
#else
#define REST_MAX_CHUNK_SIZE 160
#endif

#endif /* PROJECT_CONF_H_ */
