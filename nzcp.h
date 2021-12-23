#ifndef __NZCP_H_
#define __NZCP_H_

#include <stdlib.h>

#define NZCP_E_SUCCESS 0
#define NZCP_E_BAD_URI_PREFIX 1
#define NZCP_E_BAD_VERSION_IDENTIFIER 2
#define NZCP_E_CBOR_ERROR 3
#define NZCP_E_BAD_TAG 4
#define NZCP_E_MALFORMED_CWT 5
#define NZCP_E_MALFORMED_CWT_HEADER 6
#define NZCP_E_WRONG_KID 7
#define NZCP_E_WRONG_ALG 8
#define NZCP_E_MALFORMED_CWT_CLAIMS 9
#define NZCP_E_MALFORMED_CWT_ISSUER 10
#define NZCP_E_MALFORMED_CWT_NBF 11
#define NZCP_E_MALFORMED_CWT_EXP 12
#define NZCP_E_MALFORMED_CWT_CTI 13
#define NZCP_E_MALFORMED_CWT_VC 14
#define NZCP_E_MALFORMED_VC_CONTEXT 15
#define NZCP_E_MALFORMED_VC_VERSION 16
#define NZCP_E_MALFORMED_VC_TYPE 17
#define NZCP_E_MALFORMED_CREDENTIAL_SUBJECT 18
#define NZCP_E_MALFORMED_GIVEN_NAME 19
#define NZCP_E_MALFORMED_FAMILY_NAME 20
#define NZCP_E_MALFORMED_DOB 21
#define NZCP_E_WRONG_TRUSTED_ISSUER 22
#define NZCP_E_BAD_CTI 23
#define NZCP_E_BAD_ISS 24
#define NZCP_E_BAD_NBF 25
#define NZCP_E_BAD_EXP 26
#define NZCP_E_PASS_NOT_ACTIVE 27
#define NZCP_E_PASS_EXPIRED 28
#define NZCP_E_BAD_VC_CONTEXT 29
#define NZCP_E_BAD_VC_TYPE 30
#define NZCP_E_BAD_VC_VERSION 31
#define NZCP_E_BAD_GIVEN_NAME 32
#define NZCP_E_BAD_DOB 33
#define NZCP_E_FAILED_SIGNATURE_VERIFICATION 34

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

#endif
