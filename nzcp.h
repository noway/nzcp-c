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
 * A structure used in @ref nzcp_verify_pass_uri to return the result of the verification
 * 
 * @param jti The JWT ID.
 * @param iss The issuer.
 * @param nbf The not before time.
 * @param exp The expiration time.
 * @param given_name The given name.
 * @param family_name The family name.
 * @param dob The date of birth.
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
 * @defgroup NZCPVerifying NZCP Verifying
 * @brief A group of functions for verifying New Zealand COVID Passes
 * @section example_usage Example Usage
 * @code
 * #include <nzcp.h>
 * 
 * // initiate verification result on stack
 * nzcp_verification_result verification_result;
 *
 * // verify pass
 * // last argument determines if it's example or live MOH DID document
 * int error = nzcp_verify_pass_uri(PASS_URI, &verification_result, 1);
 *
 * // check for error
 * if (error == NZCP_E_SUCCESS) {
 *   printf("jti: %s\n", verification_result.jti);
 *   printf("iss: %s\n", verification_result.iss);
 *   printf("nbf: %d\n", verification_result.nbf);
 *   printf("exp: %d\n", verification_result.exp);
 *   printf("given_name: %s\n", verification_result.given_name);
 *   printf("family_name: %s\n", verification_result.family_name);
 *   printf("dob: %s\n", verification_result.dob);
 * }
 * else {
 *   printf("error: %s\n", nzcp_error_string(error));
 * }
 *
 * // free memory of verification result properties
 * nzcp_free_verification_result(&verification_result);
 * @endcode
 */

/**
 * @addtogroup NZCPVerifying
 * @{
 */

/**
 * @brief Verifies New Zealand COVID Pass URI.
 * 
 * @param pass_uri Null-terminted buffer with the URI 
 * @param verification_result Pointer to verification result struct
 * @param is_example Whether the pass_uri uses example or live MOH DID document
 * @return nzcp_error
 */
nzcp_error nzcp_verify_pass_uri(uint8_t* pass_uri, nzcp_verification_result* verification_result, bool is_example);

/**
 * 
 * @brief Frees nzcp_verification_result struct. Run this after you're done with the result.
 * 
 * @param verification_result  Pointer to verification result struct
 */
void nzcp_free_verification_result(nzcp_verification_result* verification_result);

/**
 * @brief Returns the error description for the given error code.
 * 
 * @param error error code
 * @return const char* 
 */
const char* nzcp_error_string(nzcp_error error);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
