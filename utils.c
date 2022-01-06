#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdbool.h>
#include "utils.h"
#define DEBUG 0

#define free_then_null(ptr) { if (ptr != NULL) { free(ptr); ptr = NULL; } }
#define free_then_malloc(ptr, size) { free_then_null(ptr); ptr = mmalloc(size); }

// FYI: allocates memory that consumer is responsible for
static inline void* mmalloc(size_t size) {
  void* ptr = malloc(size);
  memset(ptr, 0, size);
  return ptr;
}

static inline void pprintf(const char* fmt, ...) {
  if (DEBUG) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
  }
}

// FYI: allocates memory that consumer is responsible for
static inline char* qstrcopy(char* src) {
  size_t len = slength(src) + 1;
  char* dest = mmalloc(len);
  memset(dest, '\0', len);
  return strcpy(dest, src);
}

static inline void sprint_jti(uint8_t* cti, char* out) {
  sprintf(out, "urn:uuid:%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", 
    *(cti+0),  *(cti+1),  *(cti+2),  *(cti+3),  *(cti+4),  *(cti+5),  *(cti+6),  *(cti+7), 
    *(cti+8),  *(cti+9), *(cti+10), *(cti+11), *(cti+12), *(cti+13), *(cti+14), *(cti+15));
}

static inline size_t next_token_len(const uint8_t *uri, size_t skip_pos) {
  char *skipped_str_copy = (char*) (uri + skip_pos);
  size_t token_len = strcspn(skipped_str_copy, "/");
  return token_len;
}

static inline bool sequals(const char* a, const char* b) {
  if (a == NULL || b == NULL) {
    return false;
  }
  return strcmp(a, b) == 0;
}

static inline bool sstartswith(const char* a, const char* b) {
  if (a == NULL || b == NULL) {
    return false;
  }
  return strncmp(a, b, slength(b)) == 0;
}

static inline int slength(const char* a) {
  if (a == NULL) {
    return 0;
  }
  return strlen(a);
}