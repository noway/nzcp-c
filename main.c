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
        // 0x60, 0xFE, 0xD4, 0xBA, 0x25, 0x5A, 0x9D, 0x31,
        // 0xC9, 0x61, 0xEB, 0x74, 0xC6, 0x35, 0x6D, 0x68,
        // 0xC0, 0x49, 0xB8, 0x92, 0x3B, 0x61, 0xFA, 0x6C,
        // 0xE6, 0x69, 0x62, 0x2E, 0x60, 0xF2, 0x9F, 0xB6,
        // 0x79, 0x03, 0xFE, 0x10, 0x08, 0xB8, 0xBC, 0x99,
        // 0xA4, 0x1A, 0xE9, 0xE9, 0x56, 0x28, 0xBC, 0x64,
        // 0xF2, 0xF1, 0xB2, 0x0C, 0x2D, 0x7E, 0x9F, 0x51,
        // 0x77, 0xA3, 0xC2, 0x94, 0xD4, 0x46, 0x22, 0x99

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
  printf("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", *signature, *(signature+1), *(signature+2), *(signature+3), *(signature+4), *(signature+5), *(signature+6), *(signature+7), *(signature+8), *(signature+9), *(signature+10), *(signature+11), *(signature+12), *(signature+13), *(signature+14), *(signature+15), *(signature+16), *(signature+17), *(signature+18), *(signature+19), *(signature+20), *(signature+21), *(signature+22), *(signature+23), *(signature+24), *(signature+25), *(signature+26), *(signature+27), *(signature+28), *(signature+29), *(signature+30), *(signature+31));
  printf("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", *(signature+32), *(signature+33), *(signature+34), *(signature+35), *(signature+36), *(signature+37), *(signature+38), *(signature+39), *(signature+40), *(signature+41), *(signature+42), *(signature+43), *(signature+44), *(signature+45), *(signature+46), *(signature+47), *(signature+48), *(signature+49), *(signature+50), *(signature+51), *(signature+52), *(signature+53), *(signature+54), *(signature+55), *(signature+56), *(signature+57), *(signature+58), *(signature+59), *(signature+60), *(signature+61), *(signature+62), *(signature+63));
  printf("\n", signature);

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

  // printf("tobe_signed_buf: %s\n", tobe_signed_buf);

  size_t tobe_signed_buflen_actual = cbor_encoder_get_buffer_size(&encoder, tobe_signed_buf);
  printf("tobe_signed_buflen_actual: %zu\n", tobe_signed_buflen_actual);

  sb_sha256_state_t *sha256_state = mmalloc(sizeof(struct sb_sha256_state_t)); // TODO: put on stack?
  size_t msg_hash_len = 32;
  sb_byte_t *msg_hash = mmalloc(msg_hash_len); // TODO: put on stack?

  sb_sha256_message(sha256_state, msg_hash, tobe_signed_buf, tobe_signed_buflen_actual);

  printf("msg_hash: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", *msg_hash, *(msg_hash+1), *(msg_hash+2), *(msg_hash+3), *(msg_hash+4), *(msg_hash+5), *(msg_hash+6), *(msg_hash+7), *(msg_hash+8), *(msg_hash+9), *(msg_hash+10), *(msg_hash+11), *(msg_hash+12), *(msg_hash+13), *(msg_hash+14), *(msg_hash+15), *(msg_hash+16), *(msg_hash+17), *(msg_hash+18), *(msg_hash+19), *(msg_hash+20), *(msg_hash+21), *(msg_hash+22), *(msg_hash+23), *(msg_hash+24), *(msg_hash+25), *(msg_hash+26), *(msg_hash+27), *(msg_hash+28), *(msg_hash+29), *(msg_hash+30), *(msg_hash+31));
  printf("msg_hash_len: %zu\n", msg_hash_len);

  // sb_sw_context_t *context = mmalloc(sizeof(struct sb_sw_context_t));
  // sb_sw_message_digest_t *dig = mmalloc(sizeof(sb_sw_message_digest_t));

  sb_sw_context_t context;
  // sb_sw_message_digest_t dig;

  // sb_sw_signature_t sw_signature = { {*signature} };
  // sb_sw_message_digest_t TEST_MESSAGE = { {*msg_hash} };
  // sb_sw_signature_t sw_signature = { {
  //   0xd2, 0xe0, 0x7b, 0x1d, 0xd7, 0x26, 0x3d, 0x83, 0x31, 0x66, 0xbd, 0xbb, 0x4f, 0x1a, 0x09, 0x38, 0x37, 0xa9, 0x05, 0xd7, 0xec, 0xa2, 0xee, 0x83, 0x6b, 0x6b, 0x2a, 0xda, 0x23, 0xc2, 0x31, 0x54, 0xfb, 0xa8, 0x8a, 0x52, 0x9f, 0x67, 0x5d, 0x66, 0x86, 0xee, 0x63, 0x2b, 0x09, 0xec, 0x58, 0x1a, 0xb0, 0x8f, 0x72, 0xb4, 0x58, 0x90, 0x4b, 0xb3, 0x39, 0x6d, 0x10, 0xfa, 0x66, 0xd1, 0x14, 0x77,
  // } };
  sb_sw_signature_t sw_signature = { {
    *signature, *(signature+1), *(signature+2), *(signature+3), *(signature+4), *(signature+5), *(signature+6), *(signature+7), *(signature+8), *(signature+9), *(signature+10), *(signature+11), *(signature+12), *(signature+13), *(signature+14), *(signature+15), *(signature+16), *(signature+17), *(signature+18), *(signature+19), *(signature+20), *(signature+21), *(signature+22), *(signature+23), *(signature+24), *(signature+25), *(signature+26), *(signature+27), *(signature+28), *(signature+29), *(signature+30), *(signature+31),
    *(signature+32), *(signature+33), *(signature+34), *(signature+35), *(signature+36), *(signature+37), *(signature+38), *(signature+39), *(signature+40), *(signature+41), *(signature+42), *(signature+43), *(signature+44), *(signature+45), *(signature+46), *(signature+47), *(signature+48), *(signature+49), *(signature+50), *(signature+51), *(signature+52), *(signature+53), *(signature+54), *(signature+55), *(signature+56), *(signature+57), *(signature+58), *(signature+59), *(signature+60), *(signature+61), *(signature+62), *(signature+63)
  } };

  // sb_sw_message_digest_t TEST_MESSAGE = { {
  //   0x27, 0x1c, 0xe3, 0x3d, 0x67, 0x1a, 0x2d, 0x3b, 0x81, 0x6d, 0x78, 0x81, 0x35, 0xf4, 0x34, 0x3e, 0x14, 0xbc, 0x66, 0x80, 0x2f, 0x8c, 0xd8, 0x41, 0xfa, 0xac, 0x93, 0x9e, 0x8c, 0x11, 0xf3, 0xee,
  // } };
  sb_sw_message_digest_t TEST_MESSAGE = { {
    *msg_hash, *(msg_hash+1), *(msg_hash+2), *(msg_hash+3), *(msg_hash+4), *(msg_hash+5), *(msg_hash+6), *(msg_hash+7), *(msg_hash+8), *(msg_hash+9), *(msg_hash+10), *(msg_hash+11), *(msg_hash+12), *(msg_hash+13), *(msg_hash+14), *(msg_hash+15), *(msg_hash+16), *(msg_hash+17), *(msg_hash+18), *(msg_hash+19), *(msg_hash+20), *(msg_hash+21), *(msg_hash+22), *(msg_hash+23), *(msg_hash+24), *(msg_hash+25), *(msg_hash+26), *(msg_hash+27), *(msg_hash+28), *(msg_hash+29), *(msg_hash+30), *(msg_hash+31)
  } };

  sb_error_t error = sb_sw_verify_signature(&context, &sw_signature, &TEST_PUB_2, &TEST_MESSAGE, 
                                            NULL, SB_SW_CURVE_P256, 
                                            SB_DATA_ENDIAN_BIG);

  printf("error: %d\n", error);

  if (error == SB_SUCCESS) { printf("error: SB_SUCCESS\n"); }
  if (error == SB_ERROR_INSUFFICIENT_ENTROPY) { printf("error: SB_ERROR_INSUFFICIENT_ENTROPY\n"); }
  if (error == SB_ERROR_INPUT_TOO_LARGE) { printf("error: SB_ERROR_INPUT_TOO_LARGE\n"); }
  if (error == SB_ERROR_REQUEST_TOO_LARGE) { printf("error: SB_ERROR_REQUEST_TOO_LARGE\n"); }
  if (error == SB_ERROR_RESEED_REQUIRED) { printf("error: SB_ERROR_RESEED_REQUIRED\n"); }
  if (error == SB_ERROR_DRBG_FAILURE) { printf("error: SB_ERROR_DRBG_FAILURE\n"); }
  if (error == SB_ERROR_CURVE_INVALID) { printf("error: SB_ERROR_CURVE_INVALID\n"); }
  if (error == SB_ERROR_PRIVATE_KEY_INVALID) { printf("error: SB_ERROR_PRIVATE_KEY_INVALID\n"); }
  if (error == SB_ERROR_PUBLIC_KEY_INVALID) { printf("error: SB_ERROR_PUBLIC_KEY_INVALID\n"); }
  if (error == SB_ERROR_SIGNATURE_INVALID) { printf("error: SB_ERROR_SIGNATURE_INVALID\n"); }
  if (error == SB_ERROR_DRBG_UNINITIALIZED) { printf("error: SB_ERROR_DRBG_UNINITIALIZED\n"); }
  if (error == SB_ERROR_INCORRECT_OPERATION) { printf("error: SB_ERROR_INCORRECT_OPERATION\n"); }
  if (error == SB_ERROR_NOT_FINISHED) { printf("error: SB_ERROR_NOT_FINISHED\n"); }
  if (error == SB_ERROR_ADDITIONAL_INPUT_REQUIRED) { printf("error: SB_ERROR_ADDITIONAL_INPUT_REQUIRED\n"); }


  // TODO: validate cwt claims

  free(binary_cwt);
  free(protected);
  free(payload);
  free(jti);
  free(givenName);
  free(familyName);
  free(dob);
  return 0;
}
