#include <stdio.h>
#include <jni.h>
#include "NZCPJNI.h"

JNIEXPORT jint JNICALL Java_NZCPJNI_verify_1pass_1uri (JNIEnv * env, jobject self, jstring pass_uri) {
    const char *pass_uri_native = env->GetStringUTFChars(pass_uri, 0);
    printf("Hello from nzcpjni %s", pass_uri_native);
    env->ReleaseStringUTFChars(pass_uri, pass_uri_native);
    return 0;
}
