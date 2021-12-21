#include <stdbool.h>
#define DEBUG false

void* mmalloc(size_t size) {
  void* ptr = malloc(size);
  memset(ptr, 0, size);
  return ptr;
}

void pprintf(const char* fmt, ...) {
  if (DEBUG) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
  }
}

char* qstrcopy(char* src) {
  char* dest = malloc(strlen(src));
  return strcpy(dest, src);
}

void sprint_jti(uint8_t* cti, char* out) {
  sprintf(out, "urn:uuid:%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", 
    *(cti+0),  *(cti+1),  *(cti+2),  *(cti+3),  *(cti+4),  *(cti+5),  *(cti+6),  *(cti+7), 
    *(cti+8),  *(cti+9), *(cti+10), *(cti+11), *(cti+12), *(cti+13), *(cti+14), *(cti+15));
}

size_t next_token_len(const uint8_t *uri, size_t skip_pos) {
  // TODO: don't need mmalloc
  char *str_copy = mmalloc(strlen((char*) uri) + 1);
  strcpy(str_copy, (char*) uri);
  char *skipped_str_copy = (char*) (str_copy + skip_pos);
  char *token = strtok(skipped_str_copy, "/");
  size_t token_len = strlen(token);
  free(str_copy);
  return token_len;
}
