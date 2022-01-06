#include <stdio.h>
#include <stdlib.h>
#include <nzcp.h>
#include <assert.h>
#include <string.h>

#define assert_eq(d, a, b) { if (a == b) { printf("pass - %s\n", d); passed++; } else { printf("fail - %s, %d != " #b "\n", d, a); } all++; }
#define assert_neq(d, a, b) { if (a != b) { printf("pass - %s\n", d); passed++; } else { printf("fail - %s, %d == " #b "\n", d, a); } all++; }
#define assert_eqs(d, a, b) { if (strcmp(a, b) == 0) { printf("pass - %s\n", d); passed++; } else { printf("fail - %s, \"%s\" != " #b "\n", d, a); } all++; }

#define EXAMPLE_PASS "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAYFE6VGU4MCDGK7DHLLYWHVPUS2YIDJOA6Y524TD3AZRM263WTY2BE4DPKIF27WKF3UDNNVSVWRDYIYVJ65IRJJJ6Z25M2DO4YZLBHWFQGVQR5ZLIWEQJOZTS3IQ7JTNCFDX"

#define BAD_PUBLIC_KEY_PASS "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAY73U6TCQ3KF5KFML5LRCS5D3PCYIB2D3EOIIZRPXPUA2OR3NIYCBMGYRZUMBNBDMIA5BUOZKVOMSVFS246AMU7ADZXWBYP7N4QSKNQ4TETIF4VIRGLHOXWYMR4HGQ7KYHHU"

#define PUBLIC_KEY_NOT_FOUND_PASS "NZCP:/1/2KCEVIQEIVVWK6JNGIASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVBMP3LEDMB4CLBS2I7IOYJZW46U2YIBCSOFZMQADVQGM3JKJBLCY7ATASDTUYWIP4RX3SH3IFBJ3QWPQ7FJE6RNT5MU3JHCCGKJISOLIMY3OWH5H5JFUEZKBF27OMB37H5AHF"

#define MODIFIED_SIGNATURE_PASS "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAYFE6VGU4MCDGK7DHLLYWHVPUS2YIAAAAAAAAAAAAAAAAC63WTY2BE4DPKIF27WKF3UDNNVSVWRDYIYVJ65IRJJJ6Z25M2DO4YZLBHWFQGVQR5ZLIWEQJOZTS3IQ7JTNCFDX"

#define MODIFIED_PAYLOAD_PASS "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEOKKALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWKU3UMV3GK2TGMFWWS3DZJZQW2ZLDIRXWKY3EN5RGUMJZGYYC2MBUFUYTMB2QMCSPKTKOGBBTFPRTVV4LD2X2JNMEAAAAAAAAAAAAAAAABPN3J4NASOBXVEC5P3FC52BWW2ZK3IR4EMKU7OUIUUU7M5OWNBXOMMVQT3CYDKYI64VULCIEXMZZNUIPUZWRCR3Q"

#define EXPIRED_PASS "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUX5AM2FQIGTBPBPYWYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVA56TNJCCUN2NVK5NGAYOZ6VIWACYIBM3QXW7SLCMD2WTJ3GSEI5JH7RXAEURGATOHAHXC2O6BEJKBSVI25ICTBR5SFYUDSVLB2F6SJ63LWJ6Z3FWNHOXF6A2QLJNUFRQNTRU"

#define NOT_ACTIVE_PASS "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRU2XI5UFQIGTMZIQIWYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVA27NR3GFF4CCGWF66QGMJSJIF3KYID3KTKCBUOIKIC6VZ3SEGTGM3N2JTWKGDBAPLSG76Q3MXIDJRMNLETOKAUTSBOPVQEQAX25MF77RV6QVTTSCV2ZY2VMN7FATRGO3JATR"

#define NOT_BASE32_URI "NZCP:/1/asdfghasSDFGHFDSADFGHFDSADFGHGFSDADFGBHFSADFGHFDSFGHFDDS0123456789"

#define WRONG_PREFIX_URI "AUCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAYFE6VGU4MCDGK7DHLLYWHVPUS2YIDJOA6Y524TD3AZRM263WTY2BE4DPKIF27WKF3UDNNVSVWRDYIYVJ65IRJJJ6Z25M2DO4YZLBHWFQGVQR5ZLIWEQJOZTS3IQ7JTNCFDX"

#define WRONG_VERSION_URI "NZCP:/2/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAYFE6VGU4MCDGK7DHLLYWHVPUS2YIDJOA6Y524TD3AZRM263WTY2BE4DPKIF27WKF3UDNNVSVWRDYIYVJ65IRJJJ6Z25M2DO4YZLBHWFQGVQR5ZLIWEQJOZTS3IQ7JTNCFDX"

#define EMPTY_PASS "NZCP:/1/"

#define EMPTY_URI ""


int main(void) {

  int all = 0;
  int passed = 0;

  nzcp_verification_result verification_result;
  int error;

  // test example pass with live pub key
  error = nzcp_verify_pass_uri((uint8_t *)EXAMPLE_PASS, &verification_result, 0);
  assert_eq("test example pass with live pub key", error, NZCP_E_WRONG_KID);
  nzcp_free_verification_result(&verification_result);

  // test example_pass
  error = nzcp_verify_pass_uri((uint8_t *)EXAMPLE_PASS, &verification_result, 1);
  assert_eq("test example_pass", error, NZCP_E_SUCCESS);
  nzcp_free_verification_result(&verification_result);

  // test bad_public_key_pass
  error = nzcp_verify_pass_uri((uint8_t *)BAD_PUBLIC_KEY_PASS, &verification_result, 1);
  assert_eq("test bad_public_key_pass", error, NZCP_E_FAILED_SIGNATURE_VERIFICATION);
  nzcp_free_verification_result(&verification_result);

  // test public_key_not_found_pass
  error = nzcp_verify_pass_uri((uint8_t *)PUBLIC_KEY_NOT_FOUND_PASS, &verification_result, 1);
  assert_eq("test public_key_not_found_pass", error, NZCP_E_WRONG_KID);
  nzcp_free_verification_result(&verification_result);

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

  // test not_active_pass
  error = nzcp_verify_pass_uri((uint8_t *)NOT_ACTIVE_PASS, &verification_result, 1);
  assert_eq("test not_active_pass", error, NZCP_E_PASS_NOT_ACTIVE);
  nzcp_free_verification_result(&verification_result);

  // test not_base32_uri
  error = nzcp_verify_pass_uri((uint8_t *)NOT_BASE32_URI, &verification_result, 1);
  assert_eq("test not_base32_uri", error, NZCP_E_CBOR_ERROR);
  nzcp_free_verification_result(&verification_result);

  // test wrong_prefix_uri
  error = nzcp_verify_pass_uri((uint8_t *)WRONG_PREFIX_URI, &verification_result, 1);
  assert_eq("test wrong_prefix_uri", error, NZCP_E_BAD_URI_PREFIX);
  nzcp_free_verification_result(&verification_result);

  // test wrong_version_uri
  error = nzcp_verify_pass_uri((uint8_t *)WRONG_VERSION_URI, &verification_result, 1);
  assert_eq("test wrong_version_uri", error, NZCP_E_BAD_VERSION_IDENTIFIER);
  nzcp_free_verification_result(&verification_result);

  // test empty_pass
  error = nzcp_verify_pass_uri((uint8_t *)EMPTY_PASS, &verification_result, 1);
  assert_eq("test empty_pass", error, NZCP_E_CBOR_ERROR);
  nzcp_free_verification_result(&verification_result);

  // test empty_uri
  error = nzcp_verify_pass_uri((uint8_t *)EMPTY_URI, &verification_result, 1);
  assert_eq("test empty_uri", error, NZCP_E_EMPTY_URI);
  nzcp_free_verification_result(&verification_result);

  // open live pass from a file
  FILE *live_pass_file_descriptor = fopen("live_pass.txt", "rb");
  assert(live_pass_file_descriptor != NULL);
  fseek(live_pass_file_descriptor, 0, SEEK_END);
  size_t file_size = ftell(live_pass_file_descriptor);
  fseek(live_pass_file_descriptor, 0, SEEK_SET);
  uint8_t *file_contents = malloc(file_size + 1);
  *(file_contents + file_size) = '\0'; // null-terminate the pass
  assert(file_contents != NULL);
  size_t bytes_read = fread(file_contents, 1, file_size, live_pass_file_descriptor);
  assert(bytes_read == file_size);
  fclose(live_pass_file_descriptor);
  error = nzcp_verify_pass_uri(file_contents, &verification_result, 0);
  assert_eq("open live pass from a file", error, NZCP_E_SUCCESS);
  nzcp_free_verification_result(&verification_result);
  free(file_contents);

  // test nzcp_error_string
  error = NZCP_E_SUCCESS;
  assert_eqs("test nzcp_error_string", nzcp_error_string(error), "Success");
  nzcp_free_verification_result(&verification_result);

  // test nzcp_error_string
  error = NZCP_E_FAILED_SIGNATURE_VERIFICATION;
  assert_eqs("test nzcp_error_string", nzcp_error_string(error), "Failed signature verification");
  nzcp_free_verification_result(&verification_result);

  // test nzcp_error_string
  error = 12345;
  assert_eqs("test nzcp_error_string", nzcp_error_string(error), "Unknown");
  nzcp_free_verification_result(&verification_result);


  for (size_t i = 1; i <= 10000; i++)
  {
    char str[80]; // TODO: dynamically allocate
    sprintf(str, "fuzz/live_pass_%zu.txt", i);
    FILE *live_pass_file_descriptor = fopen(str, "rb");
    assert(live_pass_file_descriptor != NULL);
    fseek(live_pass_file_descriptor, 0, SEEK_END);
    size_t file_size = ftell(live_pass_file_descriptor);
    fseek(live_pass_file_descriptor, 0, SEEK_SET);
    uint8_t *file_contents = malloc(file_size + 1);
    *(file_contents + file_size) = '\0'; // null-terminate the pass
    assert(file_contents != NULL);
    size_t bytes_read = fread(file_contents, 1, file_size, live_pass_file_descriptor);
    assert(bytes_read == file_size);
    fclose(live_pass_file_descriptor);
    error = nzcp_verify_pass_uri(file_contents, &verification_result, 0);
    assert_neq(str, error, NZCP_E_SUCCESS);
    nzcp_free_verification_result(&verification_result);
    free(file_contents);
  }
  

  for (size_t i = 1; i <= 10000; i++)
  {
    char str[80]; // TODO: dynamically allocate
    sprintf(str, "fuzz/example_pass_%zu.txt", i);
    FILE *example_pass_file_descriptor = fopen(str, "rb");
    assert(example_pass_file_descriptor != NULL);
    fseek(example_pass_file_descriptor, 0, SEEK_END);
    size_t file_size = ftell(example_pass_file_descriptor);
    fseek(example_pass_file_descriptor, 0, SEEK_SET);
    uint8_t *file_contents = malloc(file_size + 1);
    *(file_contents + file_size) = '\0'; // null-terminate the pass
    assert(file_contents != NULL);
    size_t bytes_read = fread(file_contents, 1, file_size, example_pass_file_descriptor);
    assert(bytes_read == file_size);
    fclose(example_pass_file_descriptor);
    error = nzcp_verify_pass_uri(file_contents, &verification_result, 0);
    assert_neq(str, error, NZCP_E_SUCCESS);
    nzcp_free_verification_result(&verification_result);
    free(file_contents);
  }

  printf("%d/%d passed\n", passed, all);

  return 0;
}