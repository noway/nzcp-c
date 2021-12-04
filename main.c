#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "base32.h"
#include <tinycbor/cbor.h>

const unsigned char *EXAMPLE_PASS =
  (unsigned char *) "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAYFE6VGU4MCDGK7DHLLYWHVPUS2YIDJOA6Y524TD3AZRM263WTY2BE4DPKIF27WKF3UDNNVSVWRDYIYVJ65IRJJJ6Z25M2DO4YZLBHWFQGVQR5ZLIWEQJOZTS3IQ7JTNCFDX";

  

unsigned long next_token_len(const unsigned char *uri, unsigned long skip_pos) {
  char *str_copy = malloc(strlen((char*) uri) + 1);
  strcpy(str_copy, (char*) uri);
  char *skipped_str_copy = (char*) (str_copy + skip_pos);
  char *token = strtok(skipped_str_copy, "/");
  unsigned long token_len = strlen(token);
  free(str_copy);
  return token_len;
}

int main(void) {

  unsigned long token1_len = next_token_len(EXAMPLE_PASS, 0);
  unsigned long token2_len = next_token_len(EXAMPLE_PASS, token1_len + 1);
  unsigned long token3_len = next_token_len(EXAMPLE_PASS, token1_len + 1 + token2_len + 1);

  const unsigned char* payload_prefix = EXAMPLE_PASS;
  const unsigned char* version_identifier = EXAMPLE_PASS + token1_len + 1;
  const unsigned char* base32_encoded_cwt = EXAMPLE_PASS + token1_len + 1 + token2_len + 1;

  // TODO: check payload prefix and version identifier
  printf("payload_prefix %s %lu\n", payload_prefix, token1_len);
  printf("version_identifier %s %lu\n", version_identifier, token2_len);
  printf("base32_encoded_cwt %s %lu\n", base32_encoded_cwt, token3_len);
  
  // TODO: add base32 padding
  size_t binary_cwt_max = strlen((char*) base32_encoded_cwt) + 1;
  unsigned char *binary_cwt = malloc(binary_cwt_max);
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
  uint8_t *protected = malloc(protected_len);
  cbor_value_copy_byte_string(&element_value, protected, &protected_len, &element_value);
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
  uint8_t *payload = malloc(payload_len);
  cbor_value_copy_byte_string(&element_value, payload, &payload_len, &element_value);
  printf("payload_len: %lu\n", payload_len);

  free(protected);
  free(payload);
  return 0;
}
