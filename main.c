#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "base32.h"
#include <tinycbor/cbor.h>
#include <sb_sw_lib.h>
#include <sb_sw_context.h>

const uint8_t *EXAMPLE_PASS =
  (uint8_t *) "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAYFE6VGU4MCDGK7DHLLYWHVPUS2YIDJOA6Y524TD3AZRM263WTY2BE4DPKIF27WKF3UDNNVSVWRDYIYVJ65IRJJJ6Z25M2DO4YZLBHWFQGVQR5ZLIWEQJOZTS3IQ7JTNCFDX";

char* PUBLIC_KEY_X = "zRR-XGsCp12Vvbgui4DD6O6cqmhfPuXMhi1OxPl8760";
char* PUBLIC_KEY_Y = "Iv5SU6FuW-TRYh5_GOrJlcV_gpF_GpFQhCOD8LSk3T0";
char* TRUSTED_ISSUER = "did:web:nzcp.covid19.health.nz";



static const sb_sw_public_t TEST_PUB_2 = {
    {
        0x60, 0xFE, 0xD4, 0xBA, 0x25, 0x5A, 0x9D, 0x31,
        0xC9, 0x61, 0xEB, 0x74, 0xC6, 0x35, 0x6D, 0x68,
        0xC0, 0x49, 0xB8, 0x92, 0x3B, 0x61, 0xFA, 0x6C,
        0xE6, 0x69, 0x62, 0x2E, 0x60, 0xF2, 0x9F, 0xB6,
        0x79, 0x03, 0xFE, 0x10, 0x08, 0xB8, 0xBC, 0x99,
        0xA4, 0x1A, 0xE9, 0xE9, 0x56, 0x28, 0xBC, 0x64,
        0xF2, 0xF1, 0xB2, 0x0C, 0x2D, 0x7E, 0x9F, 0x51,
        0x77, 0xA3, 0xC2, 0x94, 0xD4, 0x46, 0x22, 0x99
    }
};

void* mmalloc(size_t size) {
  void* ptr = malloc(size);
  memset(ptr, 0, size);
  return ptr;
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
  printf("payload_prefix %s %lu\n", payload_prefix, token1_len);
  printf("version_identifier %s %lu\n", version_identifier, token2_len);
  printf("base32_encoded_cwt %s %lu\n", base32_encoded_cwt, token3_len);
  
  // TODO: add base32 padding
  size_t binary_cwt_max = strlen((char*) base32_encoded_cwt) + 1; // TODO: FIX: this is the length of stringified base32, not the binary length
  uint8_t *binary_cwt = mmalloc(binary_cwt_max);
  base32_decode(base32_encoded_cwt, binary_cwt);
  size_t binary_cwt_len = strlen((char*) binary_cwt);
  // printf("binary_cwt %s \n", binary_cwt);
  printf("strlen(binary_cwt) %zu \n", binary_cwt_len);


  CborParser parser;
  CborValue value;
  int result;
  cbor_parser_init(binary_cwt, binary_cwt_len, 0, &parser, &value);
  bool is_tag = cbor_value_is_tag(&value);
  assert(is_tag);
  printf("is_tag: %d\n",is_tag);

  CborTag tag;
  cbor_value_get_tag(&value, &tag);
  assert(tag == 18);
  printf("tag: %llu\n",tag);

  cbor_value_skip_tag(&value);
  CborType type1 = cbor_value_get_type(&value);
  assert(type1 == CborArrayType);
  printf("type1: %d\n",type1);

  size_t array_length;
  cbor_value_get_array_length(&value, &array_length);
  assert(array_length == 4);
  printf("array_length: %lu\n", array_length);

  CborValue element_value;
  cbor_value_enter_container(&value, &element_value);
  CborType type2 = cbor_value_get_type(&element_value);
  assert(type2 == CborByteStringType);
  printf("type2: %d\n",type2);

  size_t protected_len;
  cbor_value_calculate_string_length(&element_value, &protected_len);
  uint8_t *protected = mmalloc(protected_len + 1); // tinycbor adds null byte at the end
  cbor_value_copy_byte_string(&element_value, protected, &protected_len, &element_value); // TODO: i'd rather advance on my own
  printf("protected: %s\n", protected);
  printf("protected_len: %lu\n", protected_len);
  // TODO: check kid and alg

  CborType type3 = cbor_value_get_type(&element_value);
  assert(type3 == CborMapType); // empty map
  printf("type3: %d\n",type3);

  cbor_value_advance(&element_value);
  CborType type4 = cbor_value_get_type(&element_value);
  assert(type4 == CborByteStringType);
  printf("type4: %d\n",type4);

  size_t payload_len;
  cbor_value_calculate_string_length(&element_value, &payload_len);
  uint8_t *payload = mmalloc(payload_len + 1); // tinycbor adds null byte at the end
  cbor_value_copy_byte_string(&element_value, payload, &payload_len, &element_value); // TODO: i'd rather advance on my own
  printf("payload_len: %lu\n", payload_len);

  CborParser payload_parser;
  CborValue payload_value;
  cbor_parser_init(payload, payload_len, 0, &payload_parser, &payload_value);
  CborType payload_type = cbor_value_get_type(&payload_value);
  assert(payload_type == CborMapType);
  printf("payload_type: %d\n",payload_type);


  int valid_from;
  int expires_at;
  uint8_t *jti = NULL;
  char *givenName = NULL;
  char *familyName = NULL;
  char *dob = NULL;

  CborValue cwt_claim_element_value;
  cbor_value_enter_container(&payload_value, &cwt_claim_element_value);
  do {
    CborType cwt_claim_element_type = cbor_value_get_type(&cwt_claim_element_value);
    assert(cwt_claim_element_type == CborIntegerType || cwt_claim_element_type == CborTextStringType);
    printf("cwt_claim_element_type: %d\n",cwt_claim_element_type);

    if (cwt_claim_element_type == CborIntegerType) {
      int cwt_claim_key;
      cbor_value_get_int_checked(&cwt_claim_element_value, &cwt_claim_key);
      printf("cwt_claim_key: %d\n",cwt_claim_key);

      if (cwt_claim_key == 1) {
        cbor_value_advance(&cwt_claim_element_value);
        cwt_claim_element_type = cbor_value_get_type(&cwt_claim_element_value);
        assert(cwt_claim_element_type == CborTextStringType);
        printf("cwt_claim_element_type: %d\n",cwt_claim_element_type);

        bool is_iss_valid;
        cbor_value_text_string_equals(&cwt_claim_element_value, TRUSTED_ISSUER, &is_iss_valid); // TODO: dynamic
        assert(is_iss_valid == true);
      }
      else if (cwt_claim_key == 5) {
        cbor_value_advance(&cwt_claim_element_value);
        cwt_claim_element_type = cbor_value_get_type(&cwt_claim_element_value);
        assert(cwt_claim_element_type == CborIntegerType);
        printf("cwt_claim_element_type: %d\n",cwt_claim_element_type);

        cbor_value_get_int_checked(&cwt_claim_element_value, &valid_from);
        printf("valid_from: %d\n",valid_from);
      }
      else if (cwt_claim_key == 4) {
        cbor_value_advance(&cwt_claim_element_value);
        cwt_claim_element_type = cbor_value_get_type(&cwt_claim_element_value);
        assert(cwt_claim_element_type == CborIntegerType);
        printf("cwt_claim_element_type: %d\n",cwt_claim_element_type);

        cbor_value_get_int_checked(&cwt_claim_element_value, &expires_at);
        printf("expires_at: %d\n",expires_at);
      }
      else if (cwt_claim_key == 7) {
        cbor_value_advance(&cwt_claim_element_value);
        cwt_claim_element_type = cbor_value_get_type(&cwt_claim_element_value);
        assert(cwt_claim_element_type == CborByteStringType);
        printf("cwt_claim_element_type: %d\n",cwt_claim_element_type);

        size_t jti_len;
        cbor_value_calculate_string_length(&cwt_claim_element_value, &jti_len);
        if (jti != NULL) {
          free(jti);
        }
        jti = mmalloc(jti_len + 1); // tinycbor adds null byte at the end
        cbor_value_copy_byte_string(&cwt_claim_element_value, jti, &jti_len, NULL);

        printf("jti: %s\n",jti);
      }
    }
    else if (cwt_claim_element_type == CborTextStringType) {
      bool is_vc;
      cbor_value_text_string_equals(&cwt_claim_element_value, "vc", &is_vc); // TODO: dynamic

      if (is_vc) {
        printf("is_vc: %d\n",is_vc);
        cbor_value_advance(&cwt_claim_element_value);
        cwt_claim_element_type = cbor_value_get_type(&cwt_claim_element_value);
        assert(cwt_claim_element_type == CborMapType);
        printf("cwt_claim_element_type: %d\n",cwt_claim_element_type);

        CborValue vc_element_value;
        cbor_value_enter_container(&cwt_claim_element_value, &vc_element_value);

        do {
          CborType vc_element_type = cbor_value_get_type(&vc_element_value);
          printf("vc_element_type: %d\n",vc_element_type);
          assert(vc_element_type == CborTextStringType);
          
          size_t vc_element_key_len;
          cbor_value_calculate_string_length(&vc_element_value, &vc_element_key_len);
          char *vc_element_key = mmalloc(vc_element_key_len + 1); // tinycbor adds null byte at the end
          cbor_value_copy_text_string(&vc_element_value, vc_element_key, &vc_element_key_len, NULL);
          printf("vc_element_key: %s\n", vc_element_key);
          printf("vc_element_key_len: %lu\n", vc_element_key_len);

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
            printf("vc_element_type: %d\n",vc_element_type);

            CborValue credential_subject_element_value;
            cbor_value_enter_container(&vc_element_value, &credential_subject_element_value);

            do {
              CborType credential_subject_element_type = cbor_value_get_type(&credential_subject_element_value);
              printf("credential_subject_element_type: %d\n",credential_subject_element_type);
              assert(credential_subject_element_type == CborTextStringType);

              size_t credential_subject_element_key_len;
              cbor_value_calculate_string_length(&credential_subject_element_value, &credential_subject_element_key_len);
              char *credential_subject_element_key = mmalloc(credential_subject_element_key_len + 1); // tinycbor adds null byte at the end
              cbor_value_copy_text_string(&credential_subject_element_value, credential_subject_element_key, &credential_subject_element_key_len, NULL);
              printf("credential_subject_element_key: %s\n", credential_subject_element_key);
              printf("credential_subject_element_key_len: %lu\n", credential_subject_element_key_len);
              cbor_value_advance(&credential_subject_element_value);

              if (strcmp(credential_subject_element_key, "givenName") == 0) {
                if (givenName != NULL) {
                  free(givenName);
                }
                CborType credential_subject_element_type = cbor_value_get_type(&credential_subject_element_value);
                printf("credential_subject_element_type: %d\n",credential_subject_element_type);
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
                printf("credential_subject_element_type: %d\n",credential_subject_element_type);
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
                printf("credential_subject_element_type: %d\n",credential_subject_element_type);
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
  } while(!cbor_value_at_end(&cwt_claim_element_value)); // TODO: map is not exausted

  size_t signature_len;
  cbor_value_calculate_string_length(&element_value, &signature_len);
  uint8_t *signature = mmalloc(signature_len + 1); // tinycbor adds null byte at the end
  cbor_value_copy_byte_string(&element_value, signature, &signature_len, &element_value); // TODO: i'd rather advance on my own
  printf("signature_len: %lu\n", signature_len);
  printf("signature: %s\n", signature);

  printf("valid_from: %d\n", valid_from);
  printf("expires_at: %d\n", expires_at);
  printf("jti: %s\n", jti);
  printf("givenName: %s\n", givenName);
  printf("familyName: %s\n", familyName);
  printf("dob: %s\n", dob);


  
  CborEncoder encoder;
  CborEncoder array_encoder;
  size_t tobe_signed_buflen = 1024; // TODO: dynamic? usually 320 bytes or so depending on familyName and givenName
  uint8_t *tobe_signed_buf = mmalloc(tobe_signed_buflen); 
  cbor_encoder_init(&encoder, tobe_signed_buf, tobe_signed_buflen, 0);
  cbor_encoder_create_array(&encoder, &array_encoder, 4);
  uint8_t* buffer0 = (uint8_t*) "\0";
  cbor_encode_text_stringz(&array_encoder, "Signature1");
  cbor_encode_byte_string(&array_encoder, protected, protected_len);
  cbor_encode_byte_string(&array_encoder, buffer0, 0);
  cbor_encode_byte_string(&array_encoder, payload, payload_len);
  cbor_encoder_close_container_checked(&encoder, &array_encoder);

  printf("tobe_signed_buf: %s\n", tobe_signed_buf);

  size_t tobe_signed_buflen_actual = cbor_encoder_get_buffer_size(&encoder, tobe_signed_buf);
  printf("tobe_signed_buflen_actual: %zu\n", tobe_signed_buflen_actual);

  sb_sha256_state_t *sha256_state = mmalloc(sizeof(struct sb_sha256_state_t)); // TODO: put on stack?
  sb_byte_t *msg_hash = mmalloc(sizeof(sb_byte_t)); // TODO: put on stack?
  size_t msg_hash_len = sizeof(sb_byte_t);

  sb_sha256_message(sha256_state, msg_hash, tobe_signed_buf, tobe_signed_buflen_actual);

  printf("msg_hash: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", *msg_hash, *(msg_hash+1), *(msg_hash+2), *(msg_hash+3), *(msg_hash+4), *(msg_hash+5), *(msg_hash+6), *(msg_hash+7), *(msg_hash+8), *(msg_hash+9), *(msg_hash+10), *(msg_hash+11), *(msg_hash+12), *(msg_hash+13), *(msg_hash+14), *(msg_hash+15), *(msg_hash+16), *(msg_hash+17), *(msg_hash+18), *(msg_hash+19), *(msg_hash+20), *(msg_hash+21), *(msg_hash+22), *(msg_hash+23), *(msg_hash+24), *(msg_hash+25), *(msg_hash+26), *(msg_hash+27), *(msg_hash+28), *(msg_hash+29), *(msg_hash+30), *(msg_hash+31));

  sb_sw_context_t *context = mmalloc(sizeof(sb_sw_context_t));
  sb_sw_message_digest_t *dig = mmalloc(sizeof(sb_sw_message_digest_t));
  sb_error_t error = sb_sw_verify_signature_sha256(context, dig, signature, &TEST_PUB_2, msg_hash, msg_hash_len, NULL, SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG);

  printf("error: %d\n", error);
  printf("SB_ERROR_SIGNATURE_INVALID: %d\n", SB_ERROR_SIGNATURE_INVALID);

  if (error == SB_SUCCESS) {
    printf("Result: NZ COVID Pass is valid\n");
  }
  else if (error == SB_ERROR_SIGNATURE_INVALID) {
    printf("Result: NZ COVID Pass is invalid. Invalid signature.\n");
  }
  else {
    printf("Result: NZ COVID Pass is invalid. Unkown error.\n");
  }

  free(binary_cwt);
  free(protected);
  free(payload);
  free(jti);
  free(givenName);
  free(familyName);
  free(dob);
  return 0;
}
