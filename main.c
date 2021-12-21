#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include "base32.h"
#include <tinycbor/cbor.h>
#include <sb_sw_lib.h>
#include <sb_sw_context.h>

#define DEBUG false
#define IS_LIVE false
#define TO_BE_SIGNED_MAX_LEN 1024 // TODO: dynamic? usually 320 bytes or so depending on family_name and given_name
#define JTI_LEN strlen("urn:uuid:00000000-0000-0000-0000-000000000000")

#if IS_LIVE

static const uint8_t* KID = (uint8_t *) "z12Kf7UQ";
static const char* TRUSTED_ISSUER = "did:web:nzcp.identity.health.nz";
static const sb_sw_public_t PUB_KEY = {
  {
    0x0D, 0x00, 0x8A, 0x26, 0xEB, 0x2A, 0x32, 0xC4,
    0xF4, 0xBB, 0xB0, 0xA3, 0xA6, 0x68, 0x63, 0x54,
    0x69, 0x07, 0x96, 0x7D, 0xC0, 0xDD, 0xF4, 0xBE,
    0x6B, 0x27, 0x87, 0xE0, 0xDB, 0xB9, 0xDA, 0xD7,

    0x97, 0x18, 0x16, 0xCE, 0xC2, 0xED, 0x54, 0x8F,
    0x1F, 0xA9, 0x99, 0x93, 0x3C, 0xFA, 0x3D, 0x9D,
    0x9F, 0xA4, 0xCC, 0x6B, 0x3B, 0xC3, 0xB5, 0xCE,
    0xF3, 0xEA, 0xD4, 0x53, 0xAF, 0x0E, 0xC6, 0x62,
  }
};

#else

static const uint8_t* KID = (uint8_t *) "key-1";
static const char* TRUSTED_ISSUER = "did:web:nzcp.covid19.health.nz";
static const sb_sw_public_t PUB_KEY = {
  {
    0xCD, 0x14, 0x7E, 0x5C, 0x6B, 0x02, 0xA7, 0x5D,
    0x95, 0xBD, 0xB8, 0x2E, 0x8B, 0x80, 0xC3, 0xE8,
    0xEE, 0x9C, 0xAA, 0x68, 0x5F, 0x3E, 0xE5, 0xCC,
    0x86, 0x2D, 0x4E, 0xC4, 0xF9, 0x7C, 0xEF, 0xAD,

    0x22, 0xFE, 0x52, 0x53, 0xA1, 0x6E, 0x5B, 0xE4,
    0xD1, 0x62, 0x1E, 0x7F, 0x18, 0xEA, 0xC9, 0x95,
    0xC5, 0x7F, 0x82, 0x91, 0x7F, 0x1A, 0x91, 0x50,
    0x84, 0x23, 0x83, 0xF0, 0xB4, 0xA4, 0xDD, 0x3D,
  }
};

#endif

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

#define nzcp_error int

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

struct nzcp_state {
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

nzcp_error nzcp_verify_pass_uri(uint8_t* pass_uri, nzcp_verification_result* verification_result) {
  // TODO: check for every CborError and return error code

  // 
  // memory allocated variables:
  // 
  struct nzcp_state state = {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL, NULL,
    NULL,
    NULL, NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
  };

  size_t token1_len = next_token_len(pass_uri, 0);
  size_t token2_len = next_token_len(pass_uri, token1_len + 1);
  size_t token3_len = next_token_len(pass_uri, token1_len + 1 + token2_len + 1);

  const uint8_t* claims_prefix = pass_uri;
  const uint8_t* version_identifier = pass_uri + token1_len + 1;
  const uint8_t* base32_encoded_cwt = pass_uri + token1_len + 1 + token2_len + 1;

  // TODO: check state.claims prefix and state.version identifier
  pprintf("claims_prefix %s %lu\n", claims_prefix, token1_len);
  pprintf("version_identifier %s %lu\n", version_identifier, token2_len);
  pprintf("base32_encoded_cwt %s %lu\n", base32_encoded_cwt, token3_len);
  
  // TODO: add base32 padding
  size_t cwt_max = strlen((char*) base32_encoded_cwt) + 1; // TODO: FIX: this is the length of stringified base32, not the binary length
  state.cwt = mmalloc(cwt_max);
  base32_decode(base32_encoded_cwt, state.cwt);
  size_t cwt_len = strlen((char*) state.cwt);
  pprintf("strlen(cwt) %zu \n", cwt_len);

  CborParser parser;
  CborValue value;
  cbor_parser_init(state.cwt, cwt_len, 0, &parser, &value);
  bool is_tag = cbor_value_is_tag(&value);
  assert(is_tag);
  pprintf("is_tag: %d\n",is_tag);

  CborTag tag;
  cbor_value_get_tag(&value, &tag);
  assert(tag == 18);
  pprintf("tag: %llu\n",tag);

  cbor_value_skip_tag(&value);
  CborType type1 = cbor_value_get_type(&value); // TODO: rename type1-type3 to something else
  assert(type1 == CborArrayType);
  pprintf("type1: %d\n",type1);

  size_t array_length;
  cbor_value_get_array_length(&value, &array_length);
  assert(array_length == 4);
  pprintf("array_length: %lu\n", array_length);

  CborValue element_value;
  cbor_value_enter_container(&value, &element_value);
  CborType type2 = cbor_value_get_type(&element_value);
  assert(type2 == CborByteStringType);
  pprintf("type2: %d\n",type2);

  size_t headers_len;
  cbor_value_calculate_string_length(&element_value, &headers_len);
  state.headers = mmalloc(headers_len + 1); // tinycbor adds null byte at the end
  cbor_value_copy_byte_string(&element_value, state.headers, &headers_len, &element_value); // TODO: i'd rather advance on my own
  pprintf("state.headers: %s\n", state.headers);
  pprintf("headers_len: %lu\n", headers_len);

  CborParser headers_parser;
  CborValue headers_value;
  cbor_parser_init(state.headers, headers_len, 0, &headers_parser, &headers_value);
  CborType headers_type = cbor_value_get_type(&headers_value);
  assert(headers_type == CborMapType);
  pprintf("headers_type: %d\n",headers_type);

  CborValue headers_element_value;
  cbor_value_enter_container(&headers_value, &headers_element_value);

  size_t kid_len = 0;
  state.kid = NULL;
  int alg = 0;

  CborType header_type;
  int header_key;

  do {
    header_type = cbor_value_get_type(&headers_element_value);
    assert(header_type == CborIntegerType);
    pprintf("header_type: %d\n",header_type);

    cbor_value_get_int_checked(&headers_element_value, &header_key);
    pprintf("header_key: %d\n",header_key);

    if (header_key == 4) {
      pprintf("cwt_header_kid\n");
      cbor_value_advance(&headers_element_value);

      CborType header_value_type = cbor_value_get_type(&headers_element_value);
      pprintf("header_value_type: %d\n",header_value_type);
      assert(header_value_type == CborByteStringType);

      cbor_value_calculate_string_length(&headers_element_value, &kid_len);

      if (state.kid != NULL) {
        free(state.kid);
      }
      state.kid = mmalloc(kid_len + 1); // tinycbor adds null byte at the end
      cbor_value_copy_byte_string(&headers_element_value, state.kid, &kid_len, NULL);
    }
    else if (header_key == 1) {
      pprintf("cwt_header_alg\n");
      cbor_value_advance(&headers_element_value);

      CborType header_value_type = cbor_value_get_type(&headers_element_value);
      assert(header_value_type == CborIntegerType);
      pprintf("header_value_type: %d\n",header_value_type);

      cbor_value_get_int_checked(&headers_element_value, &alg);
    }
    else {
      cbor_value_advance(&headers_element_value);
    }
    cbor_value_advance(&headers_element_value);
  } while (!cbor_value_at_end(&headers_element_value));

  pprintf("state.kid: %s\n", state.kid);
  pprintf("alg: %d\n", alg);

  assert(memcmp(KID, state.kid, kid_len) == 0);
  assert(alg == -7);

  CborType type3 = cbor_value_get_type(&element_value);
  assert(type3 == CborMapType); // empty map
  pprintf("type3: %d\n",type3);

  cbor_value_advance(&element_value);
  CborType type4 = cbor_value_get_type(&element_value);
  assert(type4 == CborByteStringType); // cwt state.claims
  pprintf("type4: %d\n",type4);

  size_t claims_len;
  cbor_value_calculate_string_length(&element_value, &claims_len);
  state.claims = mmalloc(claims_len + 1); // tinycbor adds null byte at the end
  cbor_value_copy_byte_string(&element_value, state.claims, &claims_len, &element_value); // TODO: i'd rather advance on my own
  pprintf("claims_len: %lu\n", claims_len);

  CborParser claims_parser;
  CborValue claims_value;
  cbor_parser_init(state.claims, claims_len, 0, &claims_parser, &claims_value);
  CborType claims_type = cbor_value_get_type(&claims_value);
  assert(claims_type == CborMapType);
  pprintf("claims_type: %d\n",claims_type);

  
  int nbf = 0;
  int exp = 0;

  CborValue cwt_claim_element_value;
  cbor_value_enter_container(&claims_value, &cwt_claim_element_value);
  do {
    CborType cwt_claim_element_type = cbor_value_get_type(&cwt_claim_element_value);
    assert(cwt_claim_element_type == CborIntegerType || cwt_claim_element_type == CborTextStringType);
    pprintf("cwt_claim_element_type: %d\n",cwt_claim_element_type);

    if (cwt_claim_element_type == CborIntegerType) {
      int cwt_claim_key;
      cbor_value_get_int_checked(&cwt_claim_element_value, &cwt_claim_key);
      pprintf("cwt_claim_key: %d\n",cwt_claim_key);

      if (cwt_claim_key == 1) {
        cbor_value_advance(&cwt_claim_element_value);
        cwt_claim_element_type = cbor_value_get_type(&cwt_claim_element_value);
        assert(cwt_claim_element_type == CborTextStringType);
        pprintf("cwt_claim_element_type: %d\n",cwt_claim_element_type);

        size_t iss_len;
        cbor_value_calculate_string_length(&cwt_claim_element_value, &iss_len);

        if (state.iss != NULL) {
          free(state.iss);
        }
        state.iss = mmalloc(iss_len + 1); // tinycbor adds null byte at the end
        cbor_value_copy_text_string(&cwt_claim_element_value, state.iss, &iss_len, NULL);
      }
      else if (cwt_claim_key == 5) {
        cbor_value_advance(&cwt_claim_element_value);
        cwt_claim_element_type = cbor_value_get_type(&cwt_claim_element_value);
        assert(cwt_claim_element_type == CborIntegerType);
        pprintf("cwt_claim_element_type: %d\n",cwt_claim_element_type);

        cbor_value_get_int_checked(&cwt_claim_element_value, &nbf);
        pprintf("nbf: %d\n",nbf);
      }
      else if (cwt_claim_key == 4) {
        cbor_value_advance(&cwt_claim_element_value);
        cwt_claim_element_type = cbor_value_get_type(&cwt_claim_element_value);
        assert(cwt_claim_element_type == CborIntegerType);
        pprintf("cwt_claim_element_type: %d\n",cwt_claim_element_type);

        cbor_value_get_int_checked(&cwt_claim_element_value, &exp);
        pprintf("exp: %d\n",exp);
      }
      else if (cwt_claim_key == 7) {
        cbor_value_advance(&cwt_claim_element_value);
        cwt_claim_element_type = cbor_value_get_type(&cwt_claim_element_value);
        assert(cwt_claim_element_type == CborByteStringType);
        pprintf("cwt_claim_element_type: %d\n",cwt_claim_element_type);

        size_t cti_len;
        cbor_value_calculate_string_length(&cwt_claim_element_value, &cti_len);
        if (state.cti != NULL) {
          free(state.cti);
        }
        state.cti = mmalloc(cti_len + 1); // tinycbor adds null byte at the end
        cbor_value_copy_byte_string(&cwt_claim_element_value, state.cti, &cti_len, NULL);
        state.jti = malloc(JTI_LEN + 1);
        sprint_jti(state.cti, state.jti);

        pprintf("state.cti: %s\n",state.cti);
      }
      else {
        // TODO: in every map, put an else and advance the value further. like here.
        cbor_value_advance(&cwt_claim_element_value);
      }
    }
    else if (cwt_claim_element_type == CborTextStringType) {
      bool is_vc;
      cbor_value_text_string_equals(&cwt_claim_element_value, "vc", &is_vc); // TODO: dynamic

      if (is_vc) {
        pprintf("is_vc: %d\n",is_vc);
        cbor_value_advance(&cwt_claim_element_value);
        cwt_claim_element_type = cbor_value_get_type(&cwt_claim_element_value);
        assert(cwt_claim_element_type == CborMapType);
        pprintf("cwt_claim_element_type: %d\n",cwt_claim_element_type);

        CborValue vc_element_value;
        cbor_value_enter_container(&cwt_claim_element_value, &vc_element_value);

        do {
          CborType vc_element_type = cbor_value_get_type(&vc_element_value);
          pprintf("vc_element_type: %d\n",vc_element_type);
          assert(vc_element_type == CborTextStringType);
          
          size_t vc_element_key_len;
          cbor_value_calculate_string_length(&vc_element_value, &vc_element_key_len);
          char *vc_element_key = mmalloc(vc_element_key_len + 1); // tinycbor adds null byte at the end
          cbor_value_copy_text_string(&vc_element_value, vc_element_key, &vc_element_key_len, NULL);
          pprintf("vc_element_key: %s\n", vc_element_key);
          pprintf("vc_element_key_len: %lu\n", vc_element_key_len);

          if (strcmp(vc_element_key, "@context") == 0) {
            cbor_value_advance(&vc_element_value);

            vc_element_type = cbor_value_get_type(&vc_element_value);
            pprintf("vc_element_type: %d\n",vc_element_type);
            assert(vc_element_type == CborArrayType);

            CborValue context_value;
            cbor_value_enter_container(&vc_element_value, &context_value);

            // get state.context_0
            CborType context_0_element_type = cbor_value_get_type(&context_value);
            assert(context_0_element_type == CborTextStringType);
            size_t context_0_element_len;
            cbor_value_calculate_string_length(&context_value, &context_0_element_len);
            if (state.context_0 != NULL) {
              free(state.context_0);
            }
            state.context_0 = mmalloc(context_0_element_len + 1); // tinycbor adds null byte at the end
            cbor_value_copy_text_string(&context_value, state.context_0, &context_0_element_len, NULL);

            cbor_value_advance(&context_value);

            // get state.context_1
            CborType context_1_element_type = cbor_value_get_type(&context_value);
            assert(context_1_element_type == CborTextStringType);
            size_t context_1_element_len;
            cbor_value_calculate_string_length(&context_value, &context_1_element_len);
            if (state.context_1 != NULL) {
              free(state.context_1);
            }
            state.context_1 = mmalloc(context_1_element_len + 1); // tinycbor adds null byte at the end
            cbor_value_copy_text_string(&context_value, state.context_1, &context_1_element_len, NULL);

          }
          else if (strcmp(vc_element_key, "version") == 0) {
            cbor_value_advance(&vc_element_value);

            vc_element_type = cbor_value_get_type(&vc_element_value);
            pprintf("vc_element_type: %d\n",vc_element_type);
            assert(vc_element_type == CborTextStringType);

            size_t version_len;
            cbor_value_calculate_string_length(&vc_element_value, &version_len);

            if (state.version != NULL) {
              free(state.version);
            }
            state.version = mmalloc(version_len + 1); // tinycbor adds null byte at the end
            cbor_value_copy_text_string(&vc_element_value, state.version, &version_len, NULL);

          }
          else if (strcmp(vc_element_key, "type") == 0) {
            cbor_value_advance(&vc_element_value);

            vc_element_type = cbor_value_get_type(&vc_element_value);
            pprintf("vc_element_type: %d\n",vc_element_type);
            assert(vc_element_type == CborArrayType);

            CborValue type_value;
            cbor_value_enter_container(&vc_element_value, &type_value);

            // get state.type_0
            CborType type_0_element_type = cbor_value_get_type(&type_value);
            assert(type_0_element_type == CborTextStringType);
            size_t type_0_element_len;
            cbor_value_calculate_string_length(&type_value, &type_0_element_len);
            if (state.type_0 != NULL) {
              free(state.type_0);
            }
            state.type_0 = mmalloc(type_0_element_len + 1); // tinycbor adds null byte at the end
            cbor_value_copy_text_string(&type_value, state.type_0, &type_0_element_len, NULL);

            cbor_value_advance(&type_value);

            // get state.type_1
            CborType type_1_element_type = cbor_value_get_type(&type_value);
            assert(type_1_element_type == CborTextStringType);
            size_t type_1_element_len;
            cbor_value_calculate_string_length(&type_value, &type_1_element_len);
            if (state.type_1 != NULL) {
              free(state.type_1);
            }
            state.type_1 = mmalloc(type_1_element_len + 1); // tinycbor adds null byte at the end
            cbor_value_copy_text_string(&type_value, state.type_1, &type_1_element_len, NULL);
          }
          else if (strcmp(vc_element_key, "credentialSubject") == 0) {

            cbor_value_advance(&vc_element_value);
            vc_element_type = cbor_value_get_type(&vc_element_value);
            assert(vc_element_type == CborMapType);
            pprintf("vc_element_type: %d\n",vc_element_type);

            CborValue credential_subject_element_value;
            cbor_value_enter_container(&vc_element_value, &credential_subject_element_value);

            do {
              CborType credential_subject_element_type = cbor_value_get_type(&credential_subject_element_value);
              pprintf("credential_subject_element_type: %d\n",credential_subject_element_type);
              assert(credential_subject_element_type == CborTextStringType);

              size_t credential_subject_element_key_len;
              cbor_value_calculate_string_length(&credential_subject_element_value, &credential_subject_element_key_len);
              char *credential_subject_element_key = mmalloc(credential_subject_element_key_len + 1); // tinycbor adds null byte at the end
              cbor_value_copy_text_string(&credential_subject_element_value, credential_subject_element_key, &credential_subject_element_key_len, NULL);
              pprintf("credential_subject_element_key: %s\n", credential_subject_element_key);
              pprintf("credential_subject_element_key_len: %lu\n", credential_subject_element_key_len);
              cbor_value_advance(&credential_subject_element_value);

              if (strcmp(credential_subject_element_key, "givenName") == 0) {
                if (state.given_name != NULL) {
                  free(state.given_name);
                }
                CborType credential_subject_element_type = cbor_value_get_type(&credential_subject_element_value);
                pprintf("credential_subject_element_type: %d\n",credential_subject_element_type);
                assert(credential_subject_element_type == CborTextStringType);

                size_t subject_credential_element_value_len;
                cbor_value_calculate_string_length(&credential_subject_element_value, &subject_credential_element_value_len);
                char *subject_credential_element_value = mmalloc(subject_credential_element_value_len + 1); // tinycbor adds null byte at the end
                cbor_value_copy_text_string(&credential_subject_element_value, subject_credential_element_value, &subject_credential_element_value_len, NULL);
                state.given_name = subject_credential_element_value;
              }
              if (strcmp(credential_subject_element_key, "familyName") == 0) {
                if (state.family_name != NULL) {
                  free(state.family_name);
                }
                CborType credential_subject_element_type = cbor_value_get_type(&credential_subject_element_value);
                pprintf("credential_subject_element_type: %d\n",credential_subject_element_type);
                assert(credential_subject_element_type == CborTextStringType);

                size_t subject_credential_element_value_len; // TODO: rename subject_credential to credential_subject
                cbor_value_calculate_string_length(&credential_subject_element_value, &subject_credential_element_value_len);
                char *subject_credential_element_value = mmalloc(subject_credential_element_value_len + 1); // tinycbor adds null byte at the end
                cbor_value_copy_text_string(&credential_subject_element_value, subject_credential_element_value, &subject_credential_element_value_len, NULL);
                state.family_name = subject_credential_element_value;
              }
              if (strcmp(credential_subject_element_key, "dob") == 0) {
                if (state.dob != NULL) {
                  free(state.dob);
                }
                CborType credential_subject_element_type = cbor_value_get_type(&credential_subject_element_value);
                pprintf("credential_subject_element_type: %d\n",credential_subject_element_type);
                assert(credential_subject_element_type == CborTextStringType);

                size_t subject_credential_element_value_len;
                cbor_value_calculate_string_length(&credential_subject_element_value, &subject_credential_element_value_len);
                char *subject_credential_element_value = mmalloc(subject_credential_element_value_len + 1); // tinycbor adds null byte at the end
                cbor_value_copy_text_string(&credential_subject_element_value, subject_credential_element_value, &subject_credential_element_value_len, NULL);
                state.dob = subject_credential_element_value;
              }

              free(credential_subject_element_key);
              cbor_value_advance(&credential_subject_element_value);
            } while(!cbor_value_at_end(&credential_subject_element_value));

          }

          free(vc_element_key);
          cbor_value_advance(&vc_element_value);
        } while (!cbor_value_at_end(&vc_element_value));
      }

    }
    cbor_value_advance(&cwt_claim_element_value);
  } while(!cbor_value_at_end(&cwt_claim_element_value));

  // Validate state.iss is correct before checking signature.
  assert(strcmp(state.iss, TRUSTED_ISSUER) == 0);

  // Get signature
  size_t sign_len;
  cbor_value_calculate_string_length(&element_value, &sign_len);
  state.sign = mmalloc(sign_len + 1); // tinycbor adds null byte at the end
  cbor_value_copy_byte_string(&element_value, state.sign, &sign_len, &element_value); // TODO: i'd rather advance on my own
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
  cbor_encoder_create_array(&encoder, &array_encoder, 4);
  uint8_t* buffer0 = (uint8_t*) "\0";
  cbor_encode_text_stringz(&array_encoder, "Signature1");
  cbor_encode_byte_string(&array_encoder, state.headers, headers_len);
  cbor_encode_byte_string(&array_encoder, buffer0, 0);
  cbor_encode_byte_string(&array_encoder, state.claims, claims_len);
  cbor_encoder_close_container_checked(&encoder, &array_encoder);

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

  sb_error_t error = sb_sw_verify_signature(&sw_context, &sw_signature, &PUB_KEY, &sw_message,
                                            NULL, SB_SW_CURVE_P256, 
                                            SB_DATA_ENDIAN_BIG);

  /*
  if (error == SB_SUCCESS) { printf("error: SB_SUCCESS\n"); }
  else if (error == SB_ERROR_INSUFFICIENT_ENTROPY) { printf("error: SB_ERROR_INSUFFICIENT_ENTROPY\n"); }
  else if (error == SB_ERROR_INPUT_TOO_LARGE) { printf("error: SB_ERROR_INPUT_TOO_LARGE\n"); }
  else if (error == SB_ERROR_REQUEST_TOO_LARGE) { printf("error: SB_ERROR_REQUEST_TOO_LARGE\n"); }
  else if (error == SB_ERROR_RESEED_REQUIRED) { printf("error: SB_ERROR_RESEED_REQUIRED\n"); }
  else if (error == SB_ERROR_DRBG_FAILURE) { printf("error: SB_ERROR_DRBG_FAILURE\n"); }
  else if (error == SB_ERROR_CURVE_INVALID) { printf("error: SB_ERROR_CURVE_INVALID\n"); }
  else if (error == SB_ERROR_PRIVATE_KEY_INVALID) { printf("error: SB_ERROR_PRIVATE_KEY_INVALID\n"); }
  else if (error == SB_ERROR_PUBLIC_KEY_INVALID) { printf("error: SB_ERROR_PUBLIC_KEY_INVALID\n"); }
  else if (error == SB_ERROR_SIGNATURE_INVALID) { printf("error: SB_ERROR_SIGNATURE_INVALID\n"); }
  else if (error == SB_ERROR_DRBG_UNINITIALIZED) { printf("error: SB_ERROR_DRBG_UNINITIALIZED\n"); }
  else if (error == SB_ERROR_INCORRECT_OPERATION) { printf("error: SB_ERROR_INCORRECT_OPERATION\n"); }
  else if (error == SB_ERROR_NOT_FINISHED) { printf("error: SB_ERROR_NOT_FINISHED\n"); }
  else if (error == SB_ERROR_ADDITIONAL_INPUT_REQUIRED) { printf("error: SB_ERROR_ADDITIONAL_INPUT_REQUIRED\n"); }
  else { printf("error: %d\n", error); }

  printf("state.jti: ");
  print_jti(state.cti);
  printf("\n");
  printf("state.iss: %s\n", state.iss);
  printf("nbf: %d\n", nbf);
  printf("exp: %d\n", exp);
  printf("state.given_name: %s\n", state.given_name);
  printf("state.family_name: %s\n", state.family_name);
  printf("state.dob: %s\n", state.dob);
  */

  // Validate CWT state.claims
  assert(state.cti != NULL);
  assert(state.iss != NULL && strlen(state.iss) > 0);
  assert(nbf != 0);
  assert(exp != 0);
  assert(time(NULL) >= nbf);
  assert(time(NULL) < exp);
  assert(state.context_0 != NULL && strcmp(state.context_0, "https://www.w3.org/2018/credentials/v1") == 0);
  assert(state.context_1 != NULL && strcmp(state.context_1, "https://nzcp.covid19.health.nz/contexts/v1") == 0);
  assert(state.type_0 != NULL && strcmp(state.type_0, "VerifiableCredential") == 0);
  assert(state.type_1 != NULL && strcmp(state.type_1, "PublicCovidPass") == 0);
  assert(state.version != NULL && strcmp(state.version, "1.0.0") == 0);
  assert(state.given_name != NULL && strlen(state.given_name) > 0);
  assert(state.dob != NULL && strlen(state.dob) > 0);

  /*
  free(state.cwt);
  free(state.headers);
  free(state.kid);
  free(state.claims);
  // free(state.jti);
  // free(state.iss);
  free(state.cti);
  free(state.context_0);
  free(state.context_1);
  free(state.version);
  free(state.type_0);
  free(state.type_1);
  // free(state.given_name);
  // free(state.family_name);
  // free(state.dob);
  free(state.sign);
  free(state.tobe_signed_buf);
  free(state.sha256_state);
  free(state.hash);
  */

  verification_result->jti = state.jti;
  verification_result->iss = state.iss;
  verification_result->nbf = nbf;
  verification_result->exp = exp;
  verification_result->given_name = state.given_name;
  verification_result->family_name = state.family_name;
  verification_result->dob = state.dob;
  return error;
}

int main(void) {
  static uint8_t *PASS_URI =
    (uint8_t *) "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAYFE6VGU4MCDGK7DHLLYWHVPUS2YIDJOA6Y524TD3AZRM263WTY2BE4DPKIF27WKF3UDNNVSVWRDYIYVJ65IRJJJ6Z25M2DO4YZLBHWFQGVQR5ZLIWEQJOZTS3IQ7JTNCFDX";

  nzcp_verification_result verification_result;
  int error = nzcp_verify_pass_uri(PASS_URI, &verification_result);
  printf("error: %d\n", error);
  printf("jti: %s\n", verification_result.jti);
  printf("iss: %s\n", verification_result.iss);
  printf("nbf: %d\n", verification_result.nbf);
  printf("exp: %d\n", verification_result.exp);
  printf("given_name: %s\n", verification_result.given_name);
  printf("family_name: %s\n", verification_result.family_name);
  printf("dob: %s\n", verification_result.dob);
  return 0;
}