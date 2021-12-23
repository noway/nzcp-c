#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <tinycbor/cbor.h>
#include <sb_sw_lib.h>
#include <sb_sw_context.h>

#include "base32.c"
#include "nzcp.h"
#include "consts.h"
#include "utils.c"

#define TO_BE_SIGNED_MAX_LEN 1024 // TODO: dynamic? usually 320 bytes or so depending on family_name and given_name
#define JTI_LEN strlen("urn:uuid:00000000-0000-0000-0000-000000000000")
#define aassert(a, e) if (!(a)) { nzcp_free_state(&state); return e; }

struct nzcp_state {
  uint8_t *padded_base32_cwt;
  uint8_t *cwt;
  uint8_t *headers;
  uint8_t *kid;
  uint8_t *claims;

  uint8_t *cti;
  char* jti;
  char *iss;

  char *context_0;
  char *context_1;
  char *version;
  char *type_0;
  char *type_1;

  char *given_name;
  char *family_name;
  char *dob;

  uint8_t *sign;
  uint8_t *tobe_signed_buf;
  sb_sha256_state_t *sha256_state;
  sb_byte_t *hash;
};


void nzcp_free_state(struct nzcp_state* state) {
  free_then_null(state->padded_base32_cwt);
  free_then_null(state->cwt);
  free_then_null(state->headers);
  free_then_null(state->kid);
  free_then_null(state->claims);

  free_then_null(state->cti);
  free_then_null(state->jti);
  free_then_null(state->iss);

  free_then_null(state->context_0);
  free_then_null(state->context_1);
  free_then_null(state->version);
  free_then_null(state->type_0);
  free_then_null(state->type_1);

  free_then_null(state->given_name);
  free_then_null(state->family_name);
  free_then_null(state->dob);

  free_then_null(state->sign);
  free_then_null(state->tobe_signed_buf);
  free_then_null(state->sha256_state);
  free_then_null(state->hash);
}


void nzcp_free_verification_result(nzcp_verification_result* verification_result) {
  free_then_null(verification_result->jti);
  free_then_null(verification_result->iss);
  free_then_null(verification_result->given_name);
  free_then_null(verification_result->family_name);
  free_then_null(verification_result->dob);
}

nzcp_error nzcp_verify_pass_uri(uint8_t* pass_uri, nzcp_verification_result* verification_result, ...) {

  va_list args;
  va_start(args, verification_result);
  int is_example = va_arg(args, int);
  va_end(args);

  const uint8_t* KID = is_example ? (uint8_t *) MOH_EXAMPLE_KID : (uint8_t *) MOH_LIVE_KID;
  const char* TRUSTED_ISSUER = is_example ? MOH_EXAMPLE_TRUSTED_ISSUER : MOH_LIVE_TRUSTED_ISSUER;
  static const sb_sw_public_t LIVE_PUB_KEY = MOH_LIVE_PUB_KEY;
  static const sb_sw_public_t EXAMPLE_PUB_KEY = MOH_EXAMPLE_PUB_KEY;
  const sb_sw_public_t PUB_KEY = is_example ? EXAMPLE_PUB_KEY : LIVE_PUB_KEY;

  // 
  // memory allocated variables:
  // 
  // TODO: better initialisation?
  struct nzcp_state state = {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL, 
    NULL,
    NULL,
    NULL, 
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
  };

  CborError cbor_error = CborNoError;

  size_t token1_len = next_token_len(pass_uri, 0);
  size_t token2_len = next_token_len(pass_uri, token1_len + 1);
  size_t token3_len = next_token_len(pass_uri, token1_len + 1 + token2_len + 1);

  const uint8_t* uri_prefix = pass_uri;
  const uint8_t* version_identifier = pass_uri + token1_len + 1;
  const uint8_t* base32_cwt = pass_uri + token1_len + 1 + token2_len + 1;

  pprintf("uri_prefix %s %lu\n", uri_prefix, token1_len);
  pprintf("version_identifier %s %lu\n", version_identifier, token2_len);
  pprintf("base32_cwt %s %lu\n", base32_cwt, token3_len);
  aassert(strncmp((char*) uri_prefix, "NZCP:", token1_len) == 0, NZCP_E_BAD_URI_PREFIX);
  aassert(strncmp((char*) version_identifier, "1", token2_len) == 0, NZCP_E_BAD_VERSION_IDENTIFIER);
  
  int padded_len = token3_len % 8 == 0 ? token3_len : ((token3_len / 8) + 1) * 8;
  state.padded_base32_cwt = mmalloc(padded_len + 1);
  memset(state.padded_base32_cwt, '\0', padded_len + 1);
  memset(state.padded_base32_cwt, '=', padded_len);
  memcpy(state.padded_base32_cwt, base32_cwt, token3_len);
  pprintf("state.padded_base32_cwt %s \n", state.padded_base32_cwt);

  size_t cwt_max = strlen((char*) state.padded_base32_cwt) + 1; // TODO: FIX: this is the length of stringified base32, not the binary length
  state.cwt = mmalloc(cwt_max);
  base32_decode(state.padded_base32_cwt, state.cwt);
  size_t cwt_len = strlen((char*) state.cwt);
  pprintf("strlen(cwt) %zu \n", cwt_len);

  CborParser parser;
  CborValue value;
  cbor_error = cbor_parser_init(state.cwt, cwt_len, 0, &parser, &value);
  aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
  bool is_tag = cbor_value_is_tag(&value);
  aassert(is_tag, NZCP_E_BAD_TAG);
  pprintf("is_tag: %d\n",is_tag);

  CborTag tag;
  cbor_error = cbor_value_get_tag(&value, &tag);
  aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR)
  aassert(tag == 18, NZCP_E_BAD_TAG);
  pprintf("tag: %llu\n",tag);

  cbor_error = cbor_value_skip_tag(&value);
  aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
  CborType type1 = cbor_value_get_type(&value); // TODO: rename type1-type3 to something else
  aassert(type1 == CborArrayType, NZCP_E_MALFORMED_CWT);
  pprintf("type1: %d\n",type1);

  size_t array_length;
  cbor_error = cbor_value_get_array_length(&value, &array_length);
  aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
  aassert(array_length == 4, NZCP_E_MALFORMED_CWT);
  pprintf("array_length: %lu\n", array_length);

  CborValue element_value;
  cbor_error = cbor_value_enter_container(&value, &element_value);
  aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
  CborType type2 = cbor_value_get_type(&element_value);
  aassert(type2 == CborByteStringType, NZCP_E_MALFORMED_CWT);
  pprintf("type2: %d\n",type2);

  size_t headers_len;
  cbor_error = cbor_value_calculate_string_length(&element_value, &headers_len);
  aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
  state.headers = mmalloc(headers_len + 1); // tinycbor adds null byte at the end
  cbor_error = cbor_value_copy_byte_string(&element_value, state.headers, &headers_len, &element_value); // TODO: i'd rather advance on my own
  aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
  pprintf("state.headers: %s\n", state.headers);
  pprintf("headers_len: %lu\n", headers_len);

  CborParser headers_parser;
  CborValue headers_value;
  cbor_error = cbor_parser_init(state.headers, headers_len, 0, &headers_parser, &headers_value);
  aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);

  CborType headers_type = cbor_value_get_type(&headers_value);
  aassert(headers_type == CborMapType, NZCP_E_MALFORMED_CWT_HEADER);
  pprintf("headers_type: %d\n",headers_type);

  CborValue headers_element_value;
  cbor_error = cbor_value_enter_container(&headers_value, &headers_element_value);
  aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);

  size_t kid_len = 0;
  state.kid = NULL;
  int alg = 0;

  CborType header_type;
  int header_key;

  do {
    header_type = cbor_value_get_type(&headers_element_value);
    aassert(header_type == CborIntegerType, NZCP_E_MALFORMED_CWT_HEADER);
    pprintf("header_type: %d\n",header_type);

    cbor_error = cbor_value_get_int_checked(&headers_element_value, &header_key);
    aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
    pprintf("header_key: %d\n",header_key);

    if (header_key == 4) {
      pprintf("cwt_header_kid\n");
      cbor_error = cbor_value_advance(&headers_element_value);
      aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);

      CborType header_value_type = cbor_value_get_type(&headers_element_value);
      pprintf("header_value_type: %d\n",header_value_type);
      aassert(header_value_type == CborByteStringType, NZCP_E_MALFORMED_CWT_HEADER);

      cbor_error = cbor_value_calculate_string_length(&headers_element_value, &kid_len);
      aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);

      free_then_malloc(state.kid, kid_len + 1); // tinycbor adds null byte at the end
      cbor_error = cbor_value_copy_byte_string(&headers_element_value, state.kid, &kid_len, NULL);
      aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
    }
    else if (header_key == 1) {
      pprintf("cwt_header_alg\n");
      cbor_error = cbor_value_advance(&headers_element_value);
      aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);

      CborType header_value_type = cbor_value_get_type(&headers_element_value);
      aassert(header_value_type == CborIntegerType, NZCP_E_MALFORMED_CWT_HEADER);
      pprintf("header_value_type: %d\n",header_value_type);

      cbor_error = cbor_value_get_int_checked(&headers_element_value, &alg);
      aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
    }
    else {
      cbor_error = cbor_value_advance(&headers_element_value);
      aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
    }
    cbor_error = cbor_value_advance(&headers_element_value);
    aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
  } while (!cbor_value_at_end(&headers_element_value));

  pprintf("state.kid: %s\n", state.kid);
  pprintf("alg: %d\n", alg);

  aassert(memcmp(KID, state.kid, kid_len) == 0, NZCP_E_WRONG_KID);
  aassert(alg == -7, NZCP_E_WRONG_ALG);

  CborType type3 = cbor_value_get_type(&element_value);
  aassert(type3 == CborMapType, NZCP_E_MALFORMED_CWT); // empty map
  pprintf("type3: %d\n",type3);

  cbor_error = cbor_value_advance(&element_value);
  aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
  CborType type4 = cbor_value_get_type(&element_value);
  aassert(type4 == CborByteStringType, NZCP_E_MALFORMED_CWT); // cwt state.claims
  pprintf("type4: %d\n",type4);

  size_t claims_len;
  cbor_error = cbor_value_calculate_string_length(&element_value, &claims_len);
  aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
  state.claims = mmalloc(claims_len + 1); // tinycbor adds null byte at the end
  cbor_error = cbor_value_copy_byte_string(&element_value, state.claims, &claims_len, &element_value); // TODO: i'd rather advance on my own
  aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
  pprintf("claims_len: %lu\n", claims_len);

  CborParser claims_parser;
  CborValue claims_value;
  cbor_error = cbor_parser_init(state.claims, claims_len, 0, &claims_parser, &claims_value);
  aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
  CborType claims_type = cbor_value_get_type(&claims_value);
  aassert(claims_type == CborMapType, NZCP_E_MALFORMED_CWT_CLAIMS);
  pprintf("claims_type: %d\n",claims_type);

  
  int nbf = 0;
  int exp = 0;

  CborValue cwt_claim_element_value;
  cbor_error = cbor_value_enter_container(&claims_value, &cwt_claim_element_value);
  aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
  do {
    CborType cwt_claim_element_type = cbor_value_get_type(&cwt_claim_element_value);
    aassert(cwt_claim_element_type == CborIntegerType || cwt_claim_element_type == CborTextStringType, NZCP_E_MALFORMED_CWT_CLAIMS);
    pprintf("cwt_claim_element_type: %d\n",cwt_claim_element_type);

    if (cwt_claim_element_type == CborIntegerType) {
      int cwt_claim_key;
      cbor_error = cbor_value_get_int_checked(&cwt_claim_element_value, &cwt_claim_key);
      aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
      pprintf("cwt_claim_key: %d\n",cwt_claim_key);

      if (cwt_claim_key == 1) {
        cbor_error = cbor_value_advance(&cwt_claim_element_value);
        aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
        cwt_claim_element_type = cbor_value_get_type(&cwt_claim_element_value);
        aassert(cwt_claim_element_type == CborTextStringType, NZCP_E_MALFORMED_CWT_ISSUER);
        pprintf("cwt_claim_element_type: %d\n",cwt_claim_element_type);

        size_t iss_len;
        cbor_error = cbor_value_calculate_string_length(&cwt_claim_element_value, &iss_len);
        aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);

        free_then_malloc(state.iss, iss_len + 1); // tinycbor adds null byte at the end
        cbor_error = cbor_value_copy_text_string(&cwt_claim_element_value, state.iss, &iss_len, NULL);
        aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
      }
      else if (cwt_claim_key == 5) {
        cbor_error = cbor_value_advance(&cwt_claim_element_value);
        aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
        cwt_claim_element_type = cbor_value_get_type(&cwt_claim_element_value);
        aassert(cwt_claim_element_type == CborIntegerType, NZCP_E_MALFORMED_CWT_NBF);
        pprintf("cwt_claim_element_type: %d\n",cwt_claim_element_type);

        cbor_error = cbor_value_get_int_checked(&cwt_claim_element_value, &nbf);
        aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
        pprintf("nbf: %d\n",nbf);
      }
      else if (cwt_claim_key == 4) {
        cbor_error = cbor_value_advance(&cwt_claim_element_value);
        aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
        cwt_claim_element_type = cbor_value_get_type(&cwt_claim_element_value);
        aassert(cwt_claim_element_type == CborIntegerType, NZCP_E_MALFORMED_CWT_EXP);
        pprintf("cwt_claim_element_type: %d\n",cwt_claim_element_type);

        cbor_error = cbor_value_get_int_checked(&cwt_claim_element_value, &exp);
        aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
        pprintf("exp: %d\n",exp);
      }
      else if (cwt_claim_key == 7) {
        cbor_error = cbor_value_advance(&cwt_claim_element_value);
        aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
        cwt_claim_element_type = cbor_value_get_type(&cwt_claim_element_value);
        aassert(cwt_claim_element_type == CborByteStringType, NZCP_E_MALFORMED_CWT_CTI);
        pprintf("cwt_claim_element_type: %d\n",cwt_claim_element_type);

        size_t cti_len;
        cbor_error = cbor_value_calculate_string_length(&cwt_claim_element_value, &cti_len);
        aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
        free_then_malloc(state.cti, cti_len + 1); // tinycbor adds null byte at the end
        cbor_error = cbor_value_copy_byte_string(&cwt_claim_element_value, state.cti, &cti_len, NULL);
        aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
        free_then_malloc(state.jti, JTI_LEN + 1);
        sprint_jti(state.cti, state.jti);

        pprintf("state.cti: %s\n",state.cti);
      }
      else {
        cbor_error = cbor_value_advance(&cwt_claim_element_value);
        aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
      }
    }
    else if (cwt_claim_element_type == CborTextStringType) {
      bool is_vc;
      cbor_error = cbor_value_text_string_equals(&cwt_claim_element_value, "vc", &is_vc); // TODO: dynamic
      aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);

      if (is_vc) {
        pprintf("is_vc: %d\n",is_vc);
        cbor_error = cbor_value_advance(&cwt_claim_element_value);
        aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
        cwt_claim_element_type = cbor_value_get_type(&cwt_claim_element_value);
        aassert(cwt_claim_element_type == CborMapType, NZCP_E_MALFORMED_CWT_VC);
        pprintf("cwt_claim_element_type: %d\n",cwt_claim_element_type);

        CborValue vc_element_value;
        cbor_error = cbor_value_enter_container(&cwt_claim_element_value, &vc_element_value);
        aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);

        do {
          CborType vc_element_type = cbor_value_get_type(&vc_element_value);
          pprintf("vc_element_type: %d\n",vc_element_type);
          aassert(vc_element_type == CborTextStringType, NZCP_E_MALFORMED_CWT_VC);
          
          size_t vc_element_key_len;
          cbor_error = cbor_value_calculate_string_length(&vc_element_value, &vc_element_key_len);
          aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
          char *vc_element_key = mmalloc(vc_element_key_len + 1); // tinycbor adds null byte at the end
          cbor_error = cbor_value_copy_text_string(&vc_element_value, vc_element_key, &vc_element_key_len, NULL);
          aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
          pprintf("vc_element_key: %s\n", vc_element_key);
          pprintf("vc_element_key_len: %lu\n", vc_element_key_len);

          if (strcmp(vc_element_key, "@context") == 0) {
            cbor_error = cbor_value_advance(&vc_element_value);
            aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);

            vc_element_type = cbor_value_get_type(&vc_element_value);
            pprintf("vc_element_type: %d\n",vc_element_type);
            aassert(vc_element_type == CborArrayType, NZCP_E_MALFORMED_VC_CONTEXT);
            
            size_t context_array_len;
            cbor_error = cbor_value_get_array_length(&vc_element_value, &context_array_len);
            aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
            aassert(context_array_len == 2, NZCP_E_MALFORMED_VC_CONTEXT);
            pprintf("context_array_len: %lu\n", context_array_len);

            CborValue context_value;
            cbor_error = cbor_value_enter_container(&vc_element_value, &context_value);
            aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);

            // get state.context_0
            CborType context_0_element_type = cbor_value_get_type(&context_value);
            aassert(context_0_element_type == CborTextStringType, NZCP_E_MALFORMED_VC_CONTEXT);
            size_t context_0_element_len;
            cbor_error = cbor_value_calculate_string_length(&context_value, &context_0_element_len);
            aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
            free_then_malloc(state.context_0, context_0_element_len + 1); // tinycbor adds null byte at the end
            cbor_error = cbor_value_copy_text_string(&context_value, state.context_0, &context_0_element_len, NULL);
            aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);

            cbor_error = cbor_value_advance(&context_value);
            aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);

            // get state.context_1
            CborType context_1_element_type = cbor_value_get_type(&context_value);
            aassert(context_1_element_type == CborTextStringType, NZCP_E_MALFORMED_VC_CONTEXT);
            size_t context_1_element_len;
            cbor_error = cbor_value_calculate_string_length(&context_value, &context_1_element_len);
            aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
            free_then_malloc(state.context_1, context_1_element_len + 1); // tinycbor adds null byte at the end
            cbor_error = cbor_value_copy_text_string(&context_value, state.context_1, &context_1_element_len, NULL);
            aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);

          }
          else if (strcmp(vc_element_key, "version") == 0) {
            cbor_error = cbor_value_advance(&vc_element_value);
            aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);

            vc_element_type = cbor_value_get_type(&vc_element_value);
            pprintf("vc_element_type: %d\n",vc_element_type);
            aassert(vc_element_type == CborTextStringType,  NZCP_E_MALFORMED_VC_VERSION);

            size_t version_len;
            cbor_error = cbor_value_calculate_string_length(&vc_element_value, &version_len);
            aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);

            free_then_malloc(state.version, version_len + 1); // tinycbor adds null byte at the end
            cbor_error = cbor_value_copy_text_string(&vc_element_value, state.version, &version_len, NULL);
            aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);

          }
          else if (strcmp(vc_element_key, "type") == 0) {
            cbor_error = cbor_value_advance(&vc_element_value);
            aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);

            vc_element_type = cbor_value_get_type(&vc_element_value);
            pprintf("vc_element_type: %d\n",vc_element_type);
            aassert(vc_element_type == CborArrayType, NZCP_E_MALFORMED_VC_TYPE);
            
            size_t type_array_len;
            cbor_error = cbor_value_get_array_length(&vc_element_value, &type_array_len);
            aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
            aassert(type_array_len == 2, NZCP_E_MALFORMED_VC_TYPE);
            pprintf("type_array_len: %lu\n", type_array_len);

            CborValue type_value;
            cbor_error = cbor_value_enter_container(&vc_element_value, &type_value);
            aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);

            // get state.type_0
            CborType type_0_element_type = cbor_value_get_type(&type_value);
            aassert(type_0_element_type == CborTextStringType, NZCP_E_MALFORMED_VC_TYPE);
            size_t type_0_element_len;
            cbor_error = cbor_value_calculate_string_length(&type_value, &type_0_element_len);
            aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
            free_then_malloc(state.type_0, type_0_element_len + 1); // tinycbor adds null byte at the end
            cbor_error = cbor_value_copy_text_string(&type_value, state.type_0, &type_0_element_len, NULL);
            aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);

            cbor_error = cbor_value_advance(&type_value);
            aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);

            // get state.type_1
            CborType type_1_element_type = cbor_value_get_type(&type_value);
            aassert(type_1_element_type == CborTextStringType, NZCP_E_MALFORMED_VC_TYPE);
            size_t type_1_element_len;
            cbor_error = cbor_value_calculate_string_length(&type_value, &type_1_element_len);
            aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
            free_then_malloc(state.type_1, type_1_element_len + 1); // tinycbor adds null byte at the end
            cbor_error = cbor_value_copy_text_string(&type_value, state.type_1, &type_1_element_len, NULL);
            aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
          }
          else if (strcmp(vc_element_key, "credentialSubject") == 0) {

            cbor_error = cbor_value_advance(&vc_element_value);
            aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
            vc_element_type = cbor_value_get_type(&vc_element_value);
            aassert(vc_element_type == CborMapType, NZCP_E_MALFORMED_CREDENTIAL_SUBJECT);
            pprintf("vc_element_type: %d\n",vc_element_type);

            CborValue credential_subject_element_value;
            cbor_error = cbor_value_enter_container(&vc_element_value, &credential_subject_element_value);
            aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);

            do {
              CborType credential_subject_element_type = cbor_value_get_type(&credential_subject_element_value);
              pprintf("credential_subject_element_type: %d\n",credential_subject_element_type);
              aassert(credential_subject_element_type == CborTextStringType, NZCP_E_MALFORMED_CREDENTIAL_SUBJECT);

              size_t credential_subject_element_key_len;
              cbor_error = cbor_value_calculate_string_length(&credential_subject_element_value, &credential_subject_element_key_len);
              aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
              char *credential_subject_element_key = mmalloc(credential_subject_element_key_len + 1); // tinycbor adds null byte at the end
              cbor_error = cbor_value_copy_text_string(&credential_subject_element_value, credential_subject_element_key, &credential_subject_element_key_len, NULL);
              aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
              pprintf("credential_subject_element_key: %s\n", credential_subject_element_key);
              pprintf("credential_subject_element_key_len: %lu\n", credential_subject_element_key_len);

              if (strcmp(credential_subject_element_key, "givenName") == 0) {
                cbor_error = cbor_value_advance(&credential_subject_element_value);
                aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
                CborType credential_subject_element_type = cbor_value_get_type(&credential_subject_element_value);
                pprintf("credential_subject_element_type: %d\n",credential_subject_element_type);
                aassert(credential_subject_element_type == CborTextStringType, NZCP_E_MALFORMED_GIVEN_NAME);

                size_t credential_subject_field_len;
                cbor_error = cbor_value_calculate_string_length(&credential_subject_element_value, &credential_subject_field_len);
                aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
                free_then_malloc(state.given_name, credential_subject_field_len + 1); // tinycbor adds null byte at the end
                cbor_error = cbor_value_copy_text_string(&credential_subject_element_value, state.given_name, &credential_subject_field_len, NULL);
                aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
              }
              else if (strcmp(credential_subject_element_key, "familyName") == 0) {
                cbor_error = cbor_value_advance(&credential_subject_element_value);
                aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
                CborType credential_subject_element_type = cbor_value_get_type(&credential_subject_element_value);
                pprintf("credential_subject_element_type: %d\n",credential_subject_element_type);
                aassert(credential_subject_element_type == CborTextStringType, NZCP_E_MALFORMED_FAMILY_NAME);

                size_t credential_subject_field_len;
                cbor_error = cbor_value_calculate_string_length(&credential_subject_element_value, &credential_subject_field_len);
                aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
                free_then_malloc(state.family_name, credential_subject_field_len + 1); // tinycbor adds null byte at the end
                cbor_error = cbor_value_copy_text_string(&credential_subject_element_value, state.family_name, &credential_subject_field_len, NULL);
                aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
              }
              else if (strcmp(credential_subject_element_key, "dob") == 0) {
                cbor_error = cbor_value_advance(&credential_subject_element_value);
                aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
                CborType credential_subject_element_type = cbor_value_get_type(&credential_subject_element_value);
                pprintf("credential_subject_element_type: %d\n",credential_subject_element_type);
                aassert(credential_subject_element_type == CborTextStringType, NZCP_E_MALFORMED_DOB);

                size_t credential_subject_field_len;
                cbor_error = cbor_value_calculate_string_length(&credential_subject_element_value, &credential_subject_field_len);
                aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
                free_then_malloc(state.dob, credential_subject_field_len + 1); // tinycbor adds null byte at the end
                cbor_error = cbor_value_copy_text_string(&credential_subject_element_value, state.dob, &credential_subject_field_len, NULL);
                aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
              }
              else {
                cbor_error = cbor_value_advance(&credential_subject_element_value);
                aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
              }

              free(credential_subject_element_key);
              cbor_error = cbor_value_advance(&credential_subject_element_value);
              aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
            } while(!cbor_value_at_end(&credential_subject_element_value));

          }
          else {
            cbor_error = cbor_value_advance(&vc_element_value);
            aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
          }

          free(vc_element_key);
          cbor_error = cbor_value_advance(&vc_element_value);
          aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
        } while (!cbor_value_at_end(&vc_element_value));
      }

    }
    cbor_error = cbor_value_advance(&cwt_claim_element_value);
    aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
  } while(!cbor_value_at_end(&cwt_claim_element_value));

  // Validate state.iss is correct before checking signature.
  aassert(strcmp(state.iss, TRUSTED_ISSUER) == 0, NZCP_E_WRONG_TRUSTED_ISSUER);

  // Get signature
  size_t sign_len;
  cbor_error = cbor_value_calculate_string_length(&element_value, &sign_len);
  aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
  state.sign = mmalloc(sign_len + 1); // tinycbor adds null byte at the end
  cbor_error = cbor_value_copy_byte_string(&element_value, state.sign, &sign_len, &element_value); // TODO: i'd rather advance on my own
  aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
  pprintf("sign_len: %lu\n", sign_len);

  pprintf("time(NULL): %ld\n", time(NULL));
  pprintf("state.version: %s\n", state.version);
  pprintf("state.type_0: %s\n", state.type_0);
  pprintf("state.type_1: %s\n", state.type_1);
  pprintf("state.context_0: %s\n", state.context_0);
  pprintf("state.context_1: %s\n", state.context_1);

  
  CborEncoder encoder;
  CborEncoder array_encoder;
  state.tobe_signed_buf = mmalloc(TO_BE_SIGNED_MAX_LEN); 
  cbor_encoder_init(&encoder, state.tobe_signed_buf, TO_BE_SIGNED_MAX_LEN, 0);
  cbor_error = cbor_encoder_create_array(&encoder, &array_encoder, 4);
  aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
  uint8_t* buffer0 = (uint8_t*) "\0";
  cbor_error = cbor_encode_text_stringz(&array_encoder, "Signature1");
  aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
  cbor_error = cbor_encode_byte_string(&array_encoder, state.headers, headers_len);
  aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
  cbor_error = cbor_encode_byte_string(&array_encoder, buffer0, 0);
  aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
  cbor_error = cbor_encode_byte_string(&array_encoder, state.claims, claims_len);
  aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);
  cbor_error = cbor_encoder_close_container_checked(&encoder, &array_encoder);
  aassert(cbor_error == CborNoError, NZCP_E_CBOR_ERROR);

  size_t tobe_signed_buflen_actual = cbor_encoder_get_buffer_size(&encoder, state.tobe_signed_buf);
  pprintf("tobe_signed_buflen_actual: %zu\n", tobe_signed_buflen_actual);

  state.sha256_state = mmalloc(sizeof(struct sb_sha256_state_t));
  size_t hash_len = 32;
  state.hash = mmalloc(hash_len);

  sb_sha256_message(state.sha256_state, state.hash, state.tobe_signed_buf, tobe_signed_buflen_actual);

  pprintf("hash_len: %zu\n", hash_len);

  sb_sw_context_t sw_context;

  sb_sw_signature_t sw_signature = { {
    *(state.sign+0),  *(state.sign+1),  *(state.sign+2),  *(state.sign+3),  *(state.sign+4),  *(state.sign+5),  *(state.sign+6),  *(state.sign+7), 
    *(state.sign+8),  *(state.sign+9),  *(state.sign+10), *(state.sign+11), *(state.sign+12), *(state.sign+13), *(state.sign+14), *(state.sign+15), 
    *(state.sign+16), *(state.sign+17), *(state.sign+18), *(state.sign+19), *(state.sign+20), *(state.sign+21), *(state.sign+22), *(state.sign+23), 
    *(state.sign+24), *(state.sign+25), *(state.sign+26), *(state.sign+27), *(state.sign+28), *(state.sign+29), *(state.sign+30), *(state.sign+31),
    *(state.sign+32), *(state.sign+33), *(state.sign+34), *(state.sign+35), *(state.sign+36), *(state.sign+37), *(state.sign+38), *(state.sign+39), 
    *(state.sign+40), *(state.sign+41), *(state.sign+42), *(state.sign+43), *(state.sign+44), *(state.sign+45), *(state.sign+46), *(state.sign+47), 
    *(state.sign+48), *(state.sign+49), *(state.sign+50), *(state.sign+51), *(state.sign+52), *(state.sign+53), *(state.sign+54), *(state.sign+55), 
    *(state.sign+56), *(state.sign+57), *(state.sign+58), *(state.sign+59), *(state.sign+60), *(state.sign+61), *(state.sign+62), *(state.sign+63)
  } };

  sb_sw_message_digest_t sw_message = { {
    *(state.hash+0),  *(state.hash+1),  *(state.hash+2),  *(state.hash+3),  *(state.hash+4),  *(state.hash+5),  *(state.hash+6),  *(state.hash+7), 
    *(state.hash+8),  *(state.hash+9),  *(state.hash+10), *(state.hash+11), *(state.hash+12), *(state.hash+13), *(state.hash+14), *(state.hash+15), 
    *(state.hash+16), *(state.hash+17), *(state.hash+18), *(state.hash+19), *(state.hash+20), *(state.hash+21), *(state.hash+22), *(state.hash+23), 
    *(state.hash+24), *(state.hash+25), *(state.hash+26), *(state.hash+27), *(state.hash+28), *(state.hash+29), *(state.hash+30), *(state.hash+31)
  } };

  sb_error_t sign_error = sb_sw_verify_signature(&sw_context, &sw_signature, &PUB_KEY, &sw_message,
                                            NULL, SB_SW_CURVE_P256, 
                                            SB_DATA_ENDIAN_BIG);

  aassert(sign_error == 0, NZCP_E_FAILED_SIGNATURE_VERIFICATION);

  // Validating CWT state.claims
  aassert(state.cti != NULL, NZCP_E_BAD_CTI);
  aassert(state.iss != NULL && strlen(state.iss) > 0, NZCP_E_BAD_ISS);
  aassert(nbf != 0, NZCP_E_BAD_NBF);
  aassert(exp != 0, NZCP_E_BAD_EXP);
  aassert(time(NULL) >= nbf, NZCP_E_PASS_NOT_ACTIVE);
  aassert(time(NULL) < exp, NZCP_E_PASS_EXPIRED);
  aassert(state.context_0 != NULL && strcmp(state.context_0, "https://www.w3.org/2018/credentials/v1") == 0, NZCP_E_BAD_VC_CONTEXT);
  aassert(state.context_1 != NULL && strcmp(state.context_1, "https://nzcp.covid19.health.nz/contexts/v1") == 0, NZCP_E_BAD_VC_CONTEXT);
  aassert(state.type_0 != NULL && strcmp(state.type_0, "VerifiableCredential") == 0, NZCP_E_BAD_VC_TYPE);
  aassert(state.type_1 != NULL && strcmp(state.type_1, "PublicCovidPass") == 0, NZCP_E_BAD_VC_TYPE);
  aassert(state.version != NULL && strcmp(state.version, "1.0.0") == 0, NZCP_E_BAD_VC_VERSION);
  aassert(state.given_name != NULL && strlen(state.given_name) > 0, NZCP_E_BAD_GIVEN_NAME);
  aassert(state.dob != NULL && strlen(state.dob) > 0, NZCP_E_BAD_DOB);

  verification_result->jti = qstrcopy(state.jti);
  verification_result->iss = qstrcopy(state.iss);
  verification_result->nbf = nbf;
  verification_result->exp = exp;
  verification_result->given_name = qstrcopy(state.given_name);
  verification_result->family_name = qstrcopy(state.family_name);
  verification_result->dob = qstrcopy(state.dob);

  nzcp_free_state(&state);

  return NZCP_E_SUCCESS;
}
