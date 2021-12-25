#ifndef __UTILS_H_
#define __UTILS_H_

inline void* mmalloc(size_t size);
inline void pprintf(const char* fmt, ...);
inline char* qstrcopy(char* src);
inline void sprint_jti(uint8_t* cti, char* out);
inline size_t next_token_len(const uint8_t *uri, size_t skip_pos);

#endif
