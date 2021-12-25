#ifndef __UTILS_H_
#define __UTILS_H_

void* mmalloc(size_t size);
void pprintf(const char* fmt, ...);
char* qstrcopy(char* src);
void sprint_jti(uint8_t* cti, char* out);
size_t next_token_len(const uint8_t *uri, size_t skip_pos);

#endif
