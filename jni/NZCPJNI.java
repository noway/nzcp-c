public class NZCPJNI {

    public static final int E_SUCCESS = 0;
    public static final int E_BAD_URI_PREFIX = 1;
    public static final int E_BAD_VERSION_IDENTIFIER = 2;
    public static final int E_CBOR_ERROR = 3;
    public static final int E_BAD_TAG = 4;
    public static final int E_MALFORMED_CWT = 5;
    public static final int E_MALFORMED_CWT_HEADER = 6;
    public static final int E_WRONG_KID = 7;
    public static final int E_WRONG_ALG = 8;
    public static final int E_MALFORMED_CWT_CLAIMS = 9;
    public static final int E_MALFORMED_CWT_ISSUER = 10;
    public static final int E_MALFORMED_CWT_NBF = 11;
    public static final int E_MALFORMED_CWT_EXP = 12;
    public static final int E_MALFORMED_CWT_CTI = 13;
    public static final int E_MALFORMED_CWT_VC = 14;
    public static final int E_MALFORMED_VC_CONTEXT = 15;
    public static final int E_MALFORMED_VC_VERSION = 16;
    public static final int E_MALFORMED_VC_TYPE = 17;
    public static final int E_MALFORMED_CREDENTIAL_SUBJECT = 18;
    public static final int E_MALFORMED_GIVEN_NAME = 19;
    public static final int E_MALFORMED_FAMILY_NAME = 20;
    public static final int E_MALFORMED_DOB = 21;
    public static final int E_WRONG_TRUSTED_ISSUER = 22;
    public static final int E_BAD_CTI = 23;
    public static final int E_BAD_ISS = 24;
    public static final int E_BAD_NBF = 25;
    public static final int E_BAD_EXP = 26;
    public static final int E_PASS_NOT_ACTIVE = 27;
    public static final int E_PASS_EXPIRED = 28;
    public static final int E_BAD_VC_CONTEXT = 29;
    public static final int E_BAD_VC_TYPE = 30;
    public static final int E_BAD_VC_VERSION = 31;
    public static final int E_BAD_GIVEN_NAME = 32;
    public static final int E_BAD_DOB = 33;
    public static final int E_FAILED_SIGNATURE_VERIFICATION = 34;
    public static final int E_BAD_INTEGRATION = 35;

    public String jti;
    public String iss;
    public Integer nbf;
    public Integer exp;
    public String given_name;
    public String family_name;
    public String dob;

    static {
        System.load(System.getProperty("user.dir") + "/libnzcpjni.so"); // TODO: proper path concat
    }
    public native int verify_pass_uri(String pass_uri, boolean is_example);

    public static void main(String[] args) {
        NZCPJNI nzcp = new NZCPJNI();
        int error = nzcp.verify_pass_uri("NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAYFE6VGU4MCDGK7DHLLYWHVPUS2YIDJOA6Y524TD3AZRM263WTY2BE4DPKIF27WKF3UDNNVSVWRDYIYVJ65IRJJJ6Z25M2DO4YZLBHWFQGVQR5ZLIWEQJOZTS3IQ7JTNCFDX", true);

        if (error == NZCPJNI.E_SUCCESS) {
            System.out.printf("[JAVA] jti: %s\n", nzcp.jti);
            System.out.printf("[JAVA] iss: %s\n", nzcp.iss);
            System.out.printf("[JAVA] nbf: %d\n", nzcp.nbf);
            System.out.printf("[JAVA] exp: %d\n", nzcp.exp);
            System.out.printf("[JAVA] given_name: %s\n", nzcp.given_name);
            System.out.printf("[JAVA] family_name: %s\n", nzcp.family_name);
            System.out.printf("[JAVA] dob: %s\n", nzcp.dob);
        }
        else {
            System.out.printf("[JAVA] error code %d\n", error);

        }
    }
}
