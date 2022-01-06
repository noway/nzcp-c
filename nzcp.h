#ifndef __NZCP_H_
#define __NZCP_H_

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif


#define ERROR_DEF(a, b, c) static const int NZCP_##a = b;
#include "nzcp_errors.inc"
#undef ERROR_DEF

/**
 * @brief The nzcp_error type.
 *
 * This is the type used to represent NZCP errors.
 * @see nzcp_errors.inc
 */
typedef int nzcp_error;

/**
 * @brief The nzcp_verification_result structure.
 * 
 * A structure used in `nzcp_verify_pass_uri` to return the result of the verification
 * 
 * @see nzcp_verify_pass_uri
 * @see nzcp_free_verification_result
 */
typedef struct nzcp_verification_result {
  char* jti;
  char* iss;
  int nbf;
  int exp;
  char* given_name;
  char* family_name;
  char* dob;
} nzcp_verification_result;

/**
 * @brief Verify New Zealand COVID Pass URI.
 * 
 * @param pass_uri Null-terminted buffer with the URI 
 * @param verification_result Pointer to verification result struct
 * @param is_example Whether the pass_uri is an example
 * @return nzcp_error
 */
nzcp_error nzcp_verify_pass_uri(uint8_t* pass_uri, nzcp_verification_result* verification_result, bool is_example);

/**
 * 
 * @brief Frees nzcp_verification_result struct. Run this after you're done with the result.
 * 
 * @param verification_result 
 */
void nzcp_free_verification_result(struct nzcp_verification_result* verification_result);

/**
 * @brief Returns the error description for the given error code.
 * 
 * @param error 
 * @return const char* 
 */
const char* nzcp_error_string(nzcp_error error);

#ifdef __cplusplus
}
#endif

#endif
