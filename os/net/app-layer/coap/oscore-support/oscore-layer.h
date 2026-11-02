#pragma once

#include "oscore-context.h"

typedef struct {
  const char *forward_to_uri; /* Proxy-Uri to embed in this layer's plaintext */
  oscore_ctx_t *ctx;          /* OSCORE context for this hop */
} oscore_layer_t;

typedef struct {
  oscore_layer_t *layers;
  uint8_t num_layers;
  const char *target_uri;
} oscore_path_t;

/* Proxies draft section 2.1: the most OSCORE layers this node will apply
 * to a request or remove from a response. */
#ifndef OSCORE_MAX_LAYERS
#define OSCORE_MAX_LAYERS 4
#endif

/* How many destination endpoints can have a path (not layers per path). */
#ifndef OSCORE_MAX_PATHS
#define OSCORE_MAX_PATHS 2
#endif

/* Returns false if the path is empty, too long or the table is full. */
bool oscore_ep_path_set(const coap_endpoint_t *ep, oscore_path_t *path);
oscore_path_t *oscore_ep_path_get(const coap_endpoint_t *ep);
