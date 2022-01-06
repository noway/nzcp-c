#include <stdio.h>
#include <stdlib.h>
#include <nzcp.h>
#include <assert.h>
#include <string.h>

#define assert_eq(d, a, b) { if (a == b) { printf("pass - %s\n", d); } else { printf("fail - %s, %d != " #b "\n", d, a); } }
#define assert_neq(d, a, b) { if (a != b) { printf("pass - %s\n", d); } else { printf("fail - %s, %d == " #b "\n", d, a); } }
#define assert_eqs(d, a, b) { if (strcmp(a, b) == 0) { printf("pass - %s\n", d); } else { printf("fail - %s, \"%s\" != " #b "\n", d, a); } }




#define MODIFIED_SIGNATURE_PASS "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAYFE6VGU4MCDGK7DHLLYWHVPUS2YIAAAAAAAAAAAAAAAAC63WTY2BE4DPKIF27WKF3UDNNVSVWRDYIYVJ65IRJJJ6Z25M2DO4YZLBHWFQGVQR5ZLIWEQJOZTS3IQ7JTNCFDX"

#define MODIFIED_PAYLOAD_PASS "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEOKKALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWKU3UMV3GK2TGMFWWS3DZJZQW2ZLDIRXWKY3EN5RGUMJZGYYC2MBUFUYTMB2QMCSPKTKOGBBTFPRTVV4LD2X2JNMEAAAAAAAAAAAAAAAABPN3J4NASOBXVEC5P3FC52BWW2ZK3IR4EMKU7OUIUUU7M5OWNBXOMMVQT3CYDKYI64VULCIEXMZZNUIPUZWRCR3Q"

#define EXPIRED_PASS "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUX5AM2FQIGTBPBPYWYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVA56TNJCCUN2NVK5NGAYOZ6VIWACYIBM3QXW7SLCMD2WTJ3GSEI5JH7RXAEURGATOHAHXC2O6BEJKBSVI25ICTBR5SFYUDSVLB2F6SJ63LWJ6Z3FWNHOXF6A2QLJNUFRQNTRU"




int main(void) {
  nzcp_verification_result verification_result;
  int error;


  // test modified_signature_pass
  error = nzcp_verify_pass_uri((uint8_t *)MODIFIED_SIGNATURE_PASS, &verification_result, 1);
  assert_eq("test modified_signature_pass", error, NZCP_E_FAILED_SIGNATURE_VERIFICATION);
  nzcp_free_verification_result(&verification_result);

  // test modified_payload_pass
  error = nzcp_verify_pass_uri((uint8_t *)MODIFIED_PAYLOAD_PASS, &verification_result, 1);
  assert_eq("test modified_payload_pass", error, NZCP_E_FAILED_SIGNATURE_VERIFICATION);
  nzcp_free_verification_result(&verification_result);

  // test expired_pass
  error = nzcp_verify_pass_uri((uint8_t *)EXPIRED_PASS, &verification_result, 1);
  assert_eq("test expired_pass", error, NZCP_E_PASS_EXPIRED);
  nzcp_free_verification_result(&verification_result);

  for (size_t i = 7251; i <= 7252; i++)
  {
    char str[80]; // TODO: dynamically allocate
    sprintf(str, "fuzz/live_pass_%zu.txt", i);
    FILE *live_pass_file_descriptor = fopen(str, "rb");
    assert(live_pass_file_descriptor != NULL);
    fseek(live_pass_file_descriptor, 0, SEEK_END);
    size_t file_size = ftell(live_pass_file_descriptor);
    fseek(live_pass_file_descriptor, 0, SEEK_SET);
    uint8_t *file_contents = malloc(file_size + 1);
    *(file_contents + file_size) = '\0';
    assert(file_contents != NULL);
    size_t bytes_read = fread(file_contents, 1, file_size, live_pass_file_descriptor);
    assert(bytes_read == file_size);
    fclose(live_pass_file_descriptor);
    error = nzcp_verify_pass_uri((uint8_t *)file_contents, &verification_result, 0);
    assert_neq(str, error, NZCP_E_SUCCESS);
    nzcp_free_verification_result(&verification_result);
  }
  

  return 0;
}