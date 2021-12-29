#include <stdio.h>
#include <jni.h>
#include <nzcp.h>
#include "NZCPJNI.h"

JNIEXPORT jint JNICALL Java_NZCPJNI_verify_1pass_1uri (JNIEnv * env, jobject self, jstring pass_uri, jboolean is_example) {
    const char *pass_uri_native = env->GetStringUTFChars(pass_uri, 0);
    bool is_example_native = is_example == JNI_TRUE;

    nzcp_verification_result verification_result;
    int error = nzcp_verify_pass_uri((uint8_t *) pass_uri_native, &verification_result, is_example_native);
    printf("given_name %s\n", verification_result.given_name);
    printf("family_name %s\n", verification_result.family_name);
    nzcp_free_verification_result(&verification_result);

    env->ReleaseStringUTFChars(pass_uri, pass_uri_native);
    return error;
}
