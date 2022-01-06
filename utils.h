#ifndef __UTILS_H_
#define __UTILS_H_

static inline void* mmalloc(size_t size);
static inline void pprintf(const char* fmt, ...);
static inline char* qstrcopy(char* src);
static inline void sprint_jti(uint8_t* cti, char* out);
static inline size_t next_token_len(const uint8_t *uri, size_t skip_pos);
static inline bool sequals(const char* a, const char* b);
static inline int slength(const char* a);

#endif
