class Main {
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
            System.out.printf("[JAVA] error %s\n", NZCPJNI.error_string(error));
        }
    }
}
