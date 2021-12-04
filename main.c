#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "base32.h"

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

  printf("payload_prefix %s %lu\n", payload_prefix, token1_len);
  printf("version_identifier %s %lu\n", version_identifier, token2_len);
  printf("base32_encoded_cwt %s %lu\n", base32_encoded_cwt, token3_len);


  return 0;
}
