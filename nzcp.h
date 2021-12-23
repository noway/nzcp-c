#ifndef __NZCP_H_
#define __NZCP_H_

#include <stdlib.h>

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

#endif
