#include <stdio.h>
#include <stdlib.h>
#include <nzcp.h>

int main(void) {
  static uint8_t *PASS_URI =
    (uint8_t *) "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAYFE6VGU4MCDGK7DHLLYWHVPUS2YIDJOA6Y524TD3AZRM263WTY2BE4DPKIF27WKF3UDNNVSVWRDYIYVJ65IRJJJ6Z25M2DO4YZLBHWFQGVQR5ZLIWEQJOZTS3IQ7JTNCFDX";

  nzcp_verification_result verification_result;
  nzcp_error error = nzcp_verify_pass_uri(PASS_URI, &verification_result, 1);
  if (error == NZCP_E_SUCCESS) {
    printf("jti: %s\n", verification_result.jti);
    printf("iss: %s\n", verification_result.iss);
    printf("nbf: %d\n", verification_result.nbf);
    printf("exp: %d\n", verification_result.exp);
    printf("given_name: %s\n", verification_result.given_name);
    printf("family_name: %s\n", verification_result.family_name);
    printf("dob: %s\n", verification_result.dob);
  }
  else {
    printf("error: %s\n", nzcp_error_string(error));
  }
  nzcp_free_verification_result(&verification_result);
  return 0;
}