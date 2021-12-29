#include <stdio.h>
#include <jni.h>
#include "NZCPJNI.h"

JNIEXPORT jint JNICALL Java_NZCPJNI_verify_1pass_1uri (JNIEnv *, jobject, jstring) {
    printf("Hello from nzcpjni");
    return 0;
}
