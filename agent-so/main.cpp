#include <android/log.h>
#include <jni.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>

// this function is intercepted by frida,
// so implementation here is not really important
__attribute__((visibility("default"))) void report(void *address_of_crash) {
  __android_log_print(ANDROID_LOG_INFO, "MyLib", "Crash at %p",
                      address_of_crash);
  exit(0);
}

// we are intercepting this function in frida
// so implementation here doesn't matter extern
__attribute__((visibility("default"))) void
handle_signal(int signal, siginfo_t *info, void *reserved) {
  __android_log_print(ANDROID_LOG_INFO, "MyLib", "Caught signal %d", signal);
  // SIGSEGV -> Segmentation Fault
  if (signal == SIGSEGV) {
    __android_log_print(ANDROID_LOG_INFO, "MyLib", "SIGSEGV");
    // signal code is: SEGV_ACCERR -> ACCESS ERROR
    if (info->si_code == SEGV_ACCERR) {
      __android_log_print(ANDROID_LOG_INFO, "MyLib", "SEGV_ACCERR at %p",
                          info->si_addr);
      report((void *)info->si_addr);
      __android_log_print(ANDROID_LOG_INFO, "MyLib", "After report");
      exit(0);
    }
  }
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
  // Register signal handler
  struct sigaction sa;
  sa.sa_sigaction = handle_signal;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;

  if (sigaction(SIGSEGV, &sa, nullptr) == -1) {
    __android_log_print(ANDROID_LOG_ERROR, "MyLib",
                        "Failed to set signal handler");
  } else {
    __android_log_print(ANDROID_LOG_INFO, "MyLib",
                        "Signal handler set successfully");
  }

  return JNI_VERSION_1_6;
}
