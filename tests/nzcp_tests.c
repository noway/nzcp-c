#include <stdio.h>
#include <stdlib.h>
#include <nzcp.h>
#include <assert.h>

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
  nzcp_verification_result verification_result;
  int error;

  error = nzcp_verify_pass_uri((uint8_t *)EXAMPLE_PASS, &verification_result, 1);
  printf("%d\n",error);
  assert(error == NZCP_E_SUCCESS);

  error = nzcp_verify_pass_uri((uint8_t *)BAD_PUBLIC_KEY_PASS, &verification_result, 1);
  printf("%d\n",error);
  assert(error == NZCP_E_FAILED_SIGNATURE_VERIFICATION);

  error = nzcp_verify_pass_uri((uint8_t *)PUBLIC_KEY_NOT_FOUND_PASS, &verification_result, 1);
  printf("%d\n",error);
  assert(error == NZCP_E_WRONG_KID);

  // error = nzcp_verify_pass_uri((uint8_t *)MODIFIED_SIGNATURE_PASS, &verification_result, 1);
  // printf("%d\n",error);
  // assert(error == NZCP_E_FAILED_SIGNATURE_VERIFICATION);

  // error = nzcp_verify_pass_uri((uint8_t *)MODIFIED_PAYLOAD_PASS, &verification_result, 1);
  // printf("%d\n",error);
  // assert(error == NZCP_E_FAILED_SIGNATURE_VERIFICATION);

  // error = nzcp_verify_pass_uri((uint8_t *)EXPIRED_PASS, &verification_result, 1);
  // printf("error %d\n",error);
  // assert(error == NZCP_E_PASS_EXPIRED);

  error = nzcp_verify_pass_uri((uint8_t *)NOT_ACTIVE_PASS, &verification_result, 1);
  printf("%d\n",error);
  assert(error == NZCP_E_PASS_NOT_ACTIVE);

  error = nzcp_verify_pass_uri((uint8_t *)NOT_BASE32_URI, &verification_result, 1);
  printf("%d\n",error);
  assert(error == NZCP_E_CBOR_ERROR);

  error = nzcp_verify_pass_uri((uint8_t *)WRONG_PREFIX_URI, &verification_result, 1);
  printf("%d\n",error);
  assert(error == NZCP_E_BAD_URI_PREFIX);

  error = nzcp_verify_pass_uri((uint8_t *)WRONG_VERSION_URI, &verification_result, 1);
  printf("%d\n",error);
  assert(error == NZCP_E_BAD_VERSION_IDENTIFIER);

  error = nzcp_verify_pass_uri((uint8_t *)EMPTY_PASS, &verification_result, 1);
  printf("%d\n",error);
  assert(error == NZCP_E_CBOR_ERROR);

  error = nzcp_verify_pass_uri((uint8_t *)EMPTY_URI, &verification_result, 1);
  printf("%d\n",error);
  assert(error == NZCP_E_BAD_URI_PREFIX);



  return 0;
}