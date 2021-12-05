#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include "base32.h"
#include <tinycbor/cbor.h>
#include <sb_sw_lib.h>
#include <sb_sw_context.h>

#define DEBUG false
#define TO_BE_SIGNED_MAX_LEN 1024 // TODO: dynamic? usually 320 bytes or so depending on familyName and givenName

static const uint8_t *EXAMPLE_PASS =
  (uint8_t *) "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAYFE6VGU4MCDGK7DHLLYWHVPUS2YIDJOA6Y524TD3AZRM263WTY2BE4DPKIF27WKF3UDNNVSVWRDYIYVJ65IRJJJ6Z25M2DO4YZLBHWFQGVQR5ZLIWEQJOZTS3IQ7JTNCFDX";

static const char* TRUSTED_ISSUER = "did:web:nzcp.covid19.health.nz";

static const sb_sw_public_t MOH_EXAMPLE_PUB_KEY = {
  {
    0xCD, 0x14, 0x7E, 0x5C,
    0x6B, 0x02, 0xA7, 0x5D,
    0x95, 0xBD, 0xB8, 0x2E,
    0x8B, 0x80, 0xC3, 0xE8,
    0xEE, 0x9C, 0xAA, 0x68,
    0x5F, 0x3E, 0xE5, 0xCC,
    0x86, 0x2D, 0x4E, 0xC4,
    0xF9, 0x7C, 0xEF, 0xAD,

    0x22, 0xFE, 0x52, 0x53,
    0xA1, 0x6E, 0x5B, 0xE4,
    0xD1, 0x62, 0x1E, 0x7F,
    0x18, 0xEA, 0xC9, 0x95,
    0xC5, 0x7F, 0x82, 0x91,
    0x7F, 0x1A, 0x91, 0x50,
    0x84, 0x23, 0x83, 0xF0,
    0xB4, 0xA4, 0xDD, 0x3D,
  }
};

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

void print_cti(uint8_t* jti) {
  printf("urn:uuid:%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", 
    *(jti+0),  *(jti+1),  *(jti+2),  *(jti+3),  *(jti+4),  *(jti+5),  *(jti+6),  *(jti+7), 
    *(jti+8),  *(jti+9), *(jti+10), *(jti+11), *(jti+12), *(jti+13), *(jti+14), *(jti+15));
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

int main(void) {
  // TODO: check for every CborError and return error code

  size_t token1_len = next_token_len(EXAMPLE_PASS, 0);
  size_t token2_len = next_token_len(EXAMPLE_PASS, token1_len + 1);
  size_t token3_len = next_token_len(EXAMPLE_PASS, token1_len + 1 + token2_len + 1);

  const uint8_t* payload_prefix = EXAMPLE_PASS;
  const uint8_t* version_identifier = EXAMPLE_PASS + token1_len + 1;
  const uint8_t* base32_encoded_cwt = EXAMPLE_PASS + token1_len + 1 + token2_len + 1;

  // TODO: check payload prefix and version identifier
  pprintf("payload_prefix %s %lu\n", payload_prefix, token1_len);
  pprintf("version_identifier %s %lu\n", version_identifier, token2_len);
  pprintf("base32_encoded_cwt %s %lu\n", base32_encoded_cwt, token3_len);
  
  // TODO: add base32 padding
  size_t binary_cwt_max = strlen((char*) base32_encoded_cwt) + 1; // TODO: FIX: this is the length of stringified base32, not the binary length
  uint8_t *binary_cwt = mmalloc(binary_cwt_max);
  base32_decode(base32_encoded_cwt, binary_cwt);
  size_t binary_cwt_len = strlen((char*) binary_cwt);
  pprintf("strlen(binary_cwt) %zu \n", binary_cwt_len);

  CborParser parser;
  CborValue value;
  int result;
  cbor_parser_init(binary_cwt, binary_cwt_len, 0, &parser, &value);
  bool is_tag = cbor_value_is_tag(&value);
  assert(is_tag);
  pprintf("is_tag: %d\n",is_tag);

  CborTag tag;
  cbor_value_get_tag(&value, &tag);
  assert(tag == 18);
  pprintf("tag: %llu\n",tag);

  cbor_value_skip_tag(&value);
  CborType type1 = cbor_value_get_type(&value);
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

  size_t protected_len;
  cbor_value_calculate_string_length(&element_value, &protected_len);
  uint8_t *protected = mmalloc(protected_len + 1); // tinycbor adds null byte at the end
  cbor_value_copy_byte_string(&element_value, protected, &protected_len, &element_value); // TODO: i'd rather advance on my own
  pprintf("protected: %s\n", protected);
  pprintf("protected_len: %lu\n", protected_len);
  // TODO: check kid and alg

  CborType type3 = cbor_value_get_type(&element_value);
  assert(type3 == CborMapType); // empty map
  pprintf("type3: %d\n",type3);

  cbor_value_advance(&element_value);
  CborType type4 = cbor_value_get_type(&element_value);
  assert(type4 == CborByteStringType);
  pprintf("type4: %d\n",type4);

  size_t payload_len;
  cbor_value_calculate_string_length(&element_value, &payload_len);
  uint8_t *payload = mmalloc(payload_len + 1); // tinycbor adds null byte at the end
  cbor_value_copy_byte_string(&element_value, payload, &payload_len, &element_value); // TODO: i'd rather advance on my own
  pprintf("payload_len: %lu\n", payload_len);

  CborParser payload_parser;
  CborValue payload_value;
  cbor_parser_init(payload, payload_len, 0, &payload_parser, &payload_value);
  CborType payload_type = cbor_value_get_type(&payload_value);
  assert(payload_type == CborMapType);
  pprintf("payload_type: %d\n",payload_type);


  int valid_from = 0;
  int expires_at = 0;
  uint8_t *jti = NULL;
  char *givenName = NULL;
  char *familyName = NULL;
  char *dob = NULL;

  CborValue cwt_claim_element_value;
  cbor_value_enter_container(&payload_value, &cwt_claim_element_value);
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

        bool is_iss_valid;
        cbor_value_text_string_equals(&cwt_claim_element_value, TRUSTED_ISSUER, &is_iss_valid); // TODO: dynamic
        assert(is_iss_valid == true);
      }
      else if (cwt_claim_key == 5) {
        cbor_value_advance(&cwt_claim_element_value);
        cwt_claim_element_type = cbor_value_get_type(&cwt_claim_element_value);
        assert(cwt_claim_element_type == CborIntegerType);
        pprintf("cwt_claim_element_type: %d\n",cwt_claim_element_type);

        cbor_value_get_int_checked(&cwt_claim_element_value, &valid_from);
        pprintf("valid_from: %d\n",valid_from);
      }
      else if (cwt_claim_key == 4) {
        cbor_value_advance(&cwt_claim_element_value);
        cwt_claim_element_type = cbor_value_get_type(&cwt_claim_element_value);
        assert(cwt_claim_element_type == CborIntegerType);
        pprintf("cwt_claim_element_type: %d\n",cwt_claim_element_type);

        cbor_value_get_int_checked(&cwt_claim_element_value, &expires_at);
        pprintf("expires_at: %d\n",expires_at);
      }
      else if (cwt_claim_key == 7) {
        cbor_value_advance(&cwt_claim_element_value);
        cwt_claim_element_type = cbor_value_get_type(&cwt_claim_element_value);
        assert(cwt_claim_element_type == CborByteStringType);
        pprintf("cwt_claim_element_type: %d\n",cwt_claim_element_type);

        size_t jti_len;
        cbor_value_calculate_string_length(&cwt_claim_element_value, &jti_len);
        if (jti != NULL) {
          free(jti);
        }
        jti = mmalloc(jti_len + 1); // tinycbor adds null byte at the end
        cbor_value_copy_byte_string(&cwt_claim_element_value, jti, &jti_len, NULL);

        pprintf("jti: %s\n",jti);
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
            // TODO: save & verify
            cbor_value_advance(&vc_element_value);
          }
          else if (strcmp(vc_element_key, "version") == 0) {
            // TODO: save & verify
            cbor_value_advance(&vc_element_value);
          }
          else if (strcmp(vc_element_key, "type") == 0) {
            // TODO: save & verify
            cbor_value_advance(&vc_element_value);
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
                if (givenName != NULL) {
                  free(givenName);
                }
                CborType credential_subject_element_type = cbor_value_get_type(&credential_subject_element_value);
                pprintf("credential_subject_element_type: %d\n",credential_subject_element_type);
                assert(credential_subject_element_type == CborTextStringType);

                size_t subject_credential_element_value_len;
                cbor_value_calculate_string_length(&credential_subject_element_value, &subject_credential_element_value_len);
                char *subject_credential_element_value = mmalloc(subject_credential_element_value_len + 1); // tinycbor adds null byte at the end
                cbor_value_copy_text_string(&credential_subject_element_value, subject_credential_element_value, &subject_credential_element_value_len, NULL);
                givenName = subject_credential_element_value;
              }
              if (strcmp(credential_subject_element_key, "familyName") == 0) {
                if (familyName != NULL) {
                  free(familyName);
                }
                CborType credential_subject_element_type = cbor_value_get_type(&credential_subject_element_value);
                pprintf("credential_subject_element_type: %d\n",credential_subject_element_type);
                assert(credential_subject_element_type == CborTextStringType);

                size_t subject_credential_element_value_len;
                cbor_value_calculate_string_length(&credential_subject_element_value, &subject_credential_element_value_len);
                char *subject_credential_element_value = mmalloc(subject_credential_element_value_len + 1); // tinycbor adds null byte at the end
                cbor_value_copy_text_string(&credential_subject_element_value, subject_credential_element_value, &subject_credential_element_value_len, NULL);
                familyName = subject_credential_element_value;
              }
              if (strcmp(credential_subject_element_key, "dob") == 0) {
                if (dob != NULL) {
                  free(dob);
                }
                CborType credential_subject_element_type = cbor_value_get_type(&credential_subject_element_value);
                pprintf("credential_subject_element_type: %d\n",credential_subject_element_type);
                assert(credential_subject_element_type == CborTextStringType);

                size_t subject_credential_element_value_len;
                cbor_value_calculate_string_length(&credential_subject_element_value, &subject_credential_element_value_len);
                char *subject_credential_element_value = mmalloc(subject_credential_element_value_len + 1); // tinycbor adds null byte at the end
                cbor_value_copy_text_string(&credential_subject_element_value, subject_credential_element_value, &subject_credential_element_value_len, NULL);
                dob = subject_credential_element_value;
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

  size_t sign_len;
  cbor_value_calculate_string_length(&element_value, &sign_len);
  uint8_t *sign = mmalloc(sign_len + 1); // tinycbor adds null byte at the end
  cbor_value_copy_byte_string(&element_value, sign, &sign_len, &element_value); // TODO: i'd rather advance on my own
  pprintf("sign_len: %lu\n", sign_len);

  printf("valid_from: %d\n", valid_from);
  printf("expires_at: %d\n", expires_at);
  printf("cti: ");
  print_cti(jti);
  printf("\n");
  printf("givenName: %s\n", givenName);
  printf("familyName: %s\n", familyName);
  printf("dob: %s\n", dob);
  
  CborEncoder encoder;
  CborEncoder array_encoder;
  size_t tobe_signed_buflen = TO_BE_SIGNED_MAX_LEN;
  uint8_t *tobe_signed_buf = mmalloc(tobe_signed_buflen); 
  cbor_encoder_init(&encoder, tobe_signed_buf, tobe_signed_buflen, 0);
  cbor_encoder_create_array(&encoder, &array_encoder, 4);
  uint8_t* buffer0 = (uint8_t*) "\0";
  cbor_encode_text_stringz(&array_encoder, "Signature1");
  cbor_encode_byte_string(&array_encoder, protected, protected_len);
  cbor_encode_byte_string(&array_encoder, buffer0, 0);
  cbor_encode_byte_string(&array_encoder, payload, payload_len);
  cbor_encoder_close_container_checked(&encoder, &array_encoder);

  size_t tobe_signed_buflen_actual = cbor_encoder_get_buffer_size(&encoder, tobe_signed_buf);
  pprintf("tobe_signed_buflen_actual: %zu\n", tobe_signed_buflen_actual);

  sb_sha256_state_t *sha256_state = mmalloc(sizeof(struct sb_sha256_state_t)); // TODO: put on stack?
  size_t hash_len = 32;
  sb_byte_t *hash = mmalloc(hash_len); // TODO: put on stack?

  sb_sha256_message(sha256_state, hash, tobe_signed_buf, tobe_signed_buflen_actual);

  pprintf("hash_len: %zu\n", hash_len);

  sb_sw_context_t sw_context;

  sb_sw_signature_t sw_signature = { {
    *(sign+0),  *(sign+1),  *(sign+2),  *(sign+3),  *(sign+4),  *(sign+5),  *(sign+6),  *(sign+7), 
    *(sign+8),  *(sign+9),  *(sign+10), *(sign+11), *(sign+12), *(sign+13), *(sign+14), *(sign+15), 
    *(sign+16), *(sign+17), *(sign+18), *(sign+19), *(sign+20), *(sign+21), *(sign+22), *(sign+23), 
    *(sign+24), *(sign+25), *(sign+26), *(sign+27), *(sign+28), *(sign+29), *(sign+30), *(sign+31),
    *(sign+32), *(sign+33), *(sign+34), *(sign+35), *(sign+36), *(sign+37), *(sign+38), *(sign+39), 
    *(sign+40), *(sign+41), *(sign+42), *(sign+43), *(sign+44), *(sign+45), *(sign+46), *(sign+47), 
    *(sign+48), *(sign+49), *(sign+50), *(sign+51), *(sign+52), *(sign+53), *(sign+54), *(sign+55), 
    *(sign+56), *(sign+57), *(sign+58), *(sign+59), *(sign+60), *(sign+61), *(sign+62), *(sign+63)
  } };

  sb_sw_message_digest_t sw_message = { {
    *(hash+0),  *(hash+1),  *(hash+2),  *(hash+3),  *(hash+4),  *(hash+5),  *(hash+6),  *(hash+7), 
    *(hash+8),  *(hash+9),  *(hash+10), *(hash+11), *(hash+12), *(hash+13), *(hash+14), *(hash+15), 
    *(hash+16), *(hash+17), *(hash+18), *(hash+19), *(hash+20), *(hash+21), *(hash+22), *(hash+23), 
    *(hash+24), *(hash+25), *(hash+26), *(hash+27), *(hash+28), *(hash+29), *(hash+30), *(hash+31)
  } };

  sb_error_t error = sb_sw_verify_signature(&sw_context, &sw_signature, &MOH_EXAMPLE_PUB_KEY, &sw_message, 
                                            NULL, SB_SW_CURVE_P256, 
                                            SB_DATA_ENDIAN_BIG);

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

  // TODO: validate cwt claims

  free(binary_cwt);
  free(protected);
  free(payload);
  free(jti);
  free(givenName);
  free(familyName);
  free(dob);
  free(sign);
  free(tobe_signed_buf);
  free(sha256_state);
  free(hash);
  return 0;
}
