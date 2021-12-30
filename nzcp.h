#ifndef __NZCP_H_
#define __NZCP_H_

#include <stdlib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ERROR_DEF(a, b) static const int NZCP_##a = b;

#include "nzcp_errors.h"

typedef int nzcp_error;

// caller is responsible for free()ing the strings
typedef struct nzcp_verification_result {
  char* jti;
  char* iss;
  int nbf;
  int exp;
  char* given_name;
  char* family_name;
  char* dob;
} nzcp_verification_result;

nzcp_error nzcp_verify_pass_uri(uint8_t* pass_uri, nzcp_verification_result* verification_result, ...);
void nzcp_free_verification_result(struct nzcp_verification_result* verification_result);

#ifdef __cplusplus
}
#endif

#endif
