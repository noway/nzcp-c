#include <stdio.h>
#include <jni.h>
#include <nzcp.h>
#include "NZCPJNI.h"

enum jni_error { JNI_SUCCESS, JNI_BAD_POINTER };

#define ERROR_TRY_RETURN(x, e) { jni_error err = x; if (err != JNI_SUCCESS) { return e; } }
#define NULL_TRY_RETURN(x, e) { if (x == NULL) { return e; } }
#define UNUSED(x) (void)(x)

static inline jni_error SetFieldString(JNIEnv* env, jobject obj, const char* name, const char* value) {
    jclass cls = env->GetObjectClass(obj);
    NULL_TRY_RETURN(cls, JNI_BAD_POINTER);
    jfieldID fid = env->GetFieldID(cls, name, "Ljava/lang/String;");
    NULL_TRY_RETURN(fid, JNI_BAD_POINTER);
    jstring jstr = env->NewStringUTF(value);
    NULL_TRY_RETURN(jstr, JNI_BAD_POINTER); 
    env->SetObjectField(obj, fid, jstr);
    return JNI_SUCCESS;
}

static inline jni_error SetFieldInteger(JNIEnv* env, jobject obj, const char* name, int value) {
    jclass cls = env->GetObjectClass(obj);
    NULL_TRY_RETURN(cls, JNI_BAD_POINTER);
    jfieldID fid = env->GetFieldID(cls, name, "Ljava/lang/Integer;");
    NULL_TRY_RETURN(fid, JNI_BAD_POINTER);
    jclass intcls = env->FindClass("java/lang/Integer");
    NULL_TRY_RETURN(intcls, JNI_BAD_POINTER);
    jmethodID intinit = env->GetMethodID(intcls, "<init>", "(I)V");
    NULL_TRY_RETURN(intinit, JNI_BAD_POINTER);
    jobject wjint = env->NewObject(intcls, intinit, value);
    NULL_TRY_RETURN(wjint, JNI_BAD_POINTER);
    env->SetObjectField(obj, fid, wjint);
    return JNI_SUCCESS;
}

JNIEXPORT jint JNICALL Java_NZCPJNI_verify_1pass_1uri(JNIEnv * env, jobject obj, jstring pass_uri, jboolean is_example) {

    const char *pass_uri_native = env->GetStringUTFChars(pass_uri, 0);
    bool is_example_native = is_example == JNI_TRUE;

    nzcp_verification_result verification_result;
    int error = nzcp_verify_pass_uri((uint8_t *) pass_uri_native, &verification_result, is_example_native);
    if (error != NZCP_E_SUCCESS) {
        return error;
    }

    ERROR_TRY_RETURN(SetFieldString(env, obj, "jti", verification_result.jti), NZCP_E_BAD_INTEGRATION);
    ERROR_TRY_RETURN(SetFieldString(env, obj, "iss", verification_result.iss), NZCP_E_BAD_INTEGRATION);
    ERROR_TRY_RETURN(SetFieldInteger(env, obj, "nbf", verification_result.nbf), NZCP_E_BAD_INTEGRATION);
    ERROR_TRY_RETURN(SetFieldInteger(env, obj, "exp", verification_result.exp), NZCP_E_BAD_INTEGRATION);
    ERROR_TRY_RETURN(SetFieldString(env, obj, "given_name", verification_result.given_name), NZCP_E_BAD_INTEGRATION);
    ERROR_TRY_RETURN(SetFieldString(env, obj, "family_name", verification_result.family_name), NZCP_E_BAD_INTEGRATION);
    ERROR_TRY_RETURN(SetFieldString(env, obj, "dob", verification_result.dob), NZCP_E_BAD_INTEGRATION);

    nzcp_free_verification_result(&verification_result);
    env->ReleaseStringUTFChars(pass_uri, pass_uri_native);
    return error;
}

JNIEXPORT jstring JNICALL Java_NZCPJNI_error_1string(JNIEnv * env, jclass cls, jint error) {
    UNUSED(cls);
    jstring jstr = env->NewStringUTF(nzcp_error_string(error));
    return jstr;
}
