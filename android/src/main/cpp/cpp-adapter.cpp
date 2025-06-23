#include <jni.h>
#include "NitroAesOnLoad.hpp"

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
  return margelo::nitro::nitroaes::initialize(vm);
}
