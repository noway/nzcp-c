#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "base32.h"
#include <tinycbor/cbor.h>

const uint8_t *EXAMPLE_PASS =
  (uint8_t *) "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAYFE6VGU4MCDGK7DHLLYWHVPUS2YIDJOA6Y524TD3AZRM263WTY2BE4DPKIF27WKF3UDNNVSVWRDYIYVJ65IRJJJ6Z25M2DO4YZLBHWFQGVQR5ZLIWEQJOZTS3IQ7JTNCFDX";

  
#define mmalloc(size) calloc(1, size)

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
  printf("binary_cwt %s \n", binary_cwt);
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
  uint8_t *jti;
  char *givenName;
  char *familyName;
  char *dob;

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
        cbor_value_text_string_equals(&cwt_claim_element_value, "did:web:nzcp.covid19.health.nz", &is_iss_valid); // TODO: dynamic
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

              size_t subject_credential_element_key_len;
              cbor_value_calculate_string_length(&credential_subject_element_value, &subject_credential_element_key_len);
              char *subject_credential_element_key = mmalloc(subject_credential_element_key_len + 1); // tinycbor adds null byte at the end
              cbor_value_copy_text_string(&credential_subject_element_value, subject_credential_element_key, &subject_credential_element_key_len, NULL);
              printf("subject_credential_element_key: %s\n", subject_credential_element_key);
              printf("subject_credential_element_key_len: %lu\n", subject_credential_element_key_len);
              cbor_value_advance(&credential_subject_element_value);


              if (strcmp(subject_credential_element_key, "givenName") == 0) {
                if (givenName == NULL) {
                  free(givenName);
                }
                size_t subject_credential_element_value_len;
                cbor_value_calculate_string_length(&credential_subject_element_value, &subject_credential_element_value_len);
                char *subject_credential_element_value = mmalloc(subject_credential_element_value_len + 1); // tinycbor adds null byte at the end
                cbor_value_copy_text_string(&credential_subject_element_value, subject_credential_element_value, &subject_credential_element_value_len, NULL);
                givenName = subject_credential_element_value;
              }
              if (strcmp(subject_credential_element_key, "familyName") == 0) {
                if (familyName == NULL) {
                  free(familyName);
                }
                size_t subject_credential_element_value_len;
                cbor_value_calculate_string_length(&credential_subject_element_value, &subject_credential_element_value_len);
                char *subject_credential_element_value = mmalloc(subject_credential_element_value_len + 1); // tinycbor adds null byte at the end
                cbor_value_copy_text_string(&credential_subject_element_value, subject_credential_element_value, &subject_credential_element_value_len, NULL);
                familyName = subject_credential_element_value;
              }
              if (strcmp(subject_credential_element_key, "dob") == 0) {
                if (dob == NULL) {
                  free(dob);
                }
                size_t subject_credential_element_value_len;
                cbor_value_calculate_string_length(&credential_subject_element_value, &subject_credential_element_value_len);
                char *subject_credential_element_value = mmalloc(subject_credential_element_value_len + 1); // tinycbor adds null byte at the end
                cbor_value_copy_text_string(&credential_subject_element_value, subject_credential_element_value, &subject_credential_element_value_len, NULL);
                dob = subject_credential_element_value;
              }

              free(subject_credential_element_key);

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

  printf("jti: %s\n", jti);
  printf("givenName: %s\n", givenName);
  printf("familyName: %s\n", familyName);
  printf("dob: %s\n", dob);

  free(binary_cwt);
  free(protected);
  free(payload);
  free(jti);
  free(givenName);
  free(familyName);
  free(dob);
  return 0;
}
