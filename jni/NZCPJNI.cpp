#include <stdio.h>
#include <jni.h>
#include <nzcp.h>
#include "NZCPJNI.h"

#define SetFieldString(field, value) \
    fid = env->GetFieldID(cls, field, "Ljava/lang/String;"); \
    if (fid == NULL) { \
        return NZCP_E_BAD_INTEGRATION; \
    } \
    jstr = env->NewStringUTF(value); \
    if (jstr == NULL) { \
        return NZCP_E_BAD_INTEGRATION; \
    } \
    env->SetObjectField(obj, fid, jstr); \

#define SetFieldInt(field, value) \
    fid = env->GetFieldID(cls, field, "Ljava/lang/Integer;"); \
    if (fid == NULL) { \
        return NZCP_E_BAD_INTEGRATION; \
    } \
    wjint = env->NewObject(intcls, intinit, value); \
    if (wjint == NULL) { \
        return NZCP_E_BAD_INTEGRATION; \
    } \
    env->SetObjectField(obj, fid, wjint); \

JNIEXPORT jint JNICALL Java_NZCPJNI_verify_1pass_1uri(JNIEnv * env, jobject obj, jstring pass_uri, jboolean is_example) {
    jclass cls = env->GetObjectClass(obj);
    jclass intcls = env->FindClass("java/lang/Integer");
    jmethodID intinit = env->GetMethodID(intcls, "<init>", "(I)V");
    jfieldID fid;
    jstring jstr;
    jobject wjint;

    const char *pass_uri_native = env->GetStringUTFChars(pass_uri, 0);
    bool is_example_native = is_example == JNI_TRUE;

    nzcp_verification_result verification_result;
    int error = nzcp_verify_pass_uri((uint8_t *) pass_uri_native, &verification_result, is_example_native);

    SetFieldString("jti", verification_result.jti);
    SetFieldString("iss", verification_result.iss);
    SetFieldInt("nbf", verification_result.nbf);
    SetFieldInt("exp", verification_result.exp);
    SetFieldString("given_name", verification_result.given_name);
    SetFieldString("family_name", verification_result.family_name);
    SetFieldString("dob", verification_result.dob);

    nzcp_free_verification_result(&verification_result);
    env->ReleaseStringUTFChars(pass_uri, pass_uri_native);
    return error;
}
