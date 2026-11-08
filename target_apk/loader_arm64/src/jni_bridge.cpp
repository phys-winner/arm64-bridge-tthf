// SPDX-License-Identifier: GPL-3.0-or-later
#include <jni.h>
#include <android/log.h>
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
#include <string>
#include <vector>
#include <memory>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <cinttypes>
#include <atomic>
#include <thread>
#include <chrono>
#include "dynarmic_host.h"
#include "elf_loader.h"
#include "thunk_manager.h"
#include "jni_fake_env.h"

#define LOG_TAG "TT_Arm64Bridge"
#include "bridge_logging.h"

static std::unique_ptr<DynarmicHost> g_host;
static JavaVM* g_jvm = nullptr;
static bool g_jni_onload_done = false;
static jobject g_activity_global = nullptr; // global ref to MainActivity for asset reads

// Guest symbol cache (resolved by name from libtinythief.so / libfmodex.so)
static uint32_t g_sym_appInit = 0, g_sym_onCreate = 0, g_sym_cacheObj = 0, g_sym_clearObj = 0;
static uint32_t g_sym_onChar = 0, g_sym_onGesture = 0, g_sym_onKey = 0, g_sym_onOpenFile = 0;
static uint32_t g_sym_onOrientation = 0, g_sym_onPause = 0, g_sym_onResume = 0;
static uint32_t g_sym_onTouch = 0, g_sym_onTouchMouse = 0, g_sym_onWindowFocus = 0;
static uint32_t g_sym_glDraw = 0, g_sym_glReset = 0, g_sym_glResize = 0;
static uint32_t g_sym_fmodGetInfo = 0, g_sym_fmodProcess = 0;

// Reads a whole asset into memory. Returns empty vector on failure.
static std::vector<uint8_t> ReadAsset(JNIEnv* env, jobject activity, const char* assetName) {
    std::vector<uint8_t> out;
    jclass cls = env->GetObjectClass(activity);
    jmethodID getAssets = env->GetMethodID(cls, "getAssets", "()Landroid/content/res/AssetManager;");
    if (!getAssets) { env->ExceptionClear(); return out; }
    jobject assets = env->CallObjectMethod(activity, getAssets);
    if (!assets) { env->ExceptionClear(); return out; }

    AAssetManager* mgr = AAssetManager_fromJava(env, assets);
    if (!mgr) return out;
    AAsset* a = AAssetManager_open(mgr, assetName, AASSET_MODE_STREAMING);
    if (!a) {
        LOGE("ReadAsset: asset %s not found", assetName);
        return out;
    }
    off_t len = AAsset_getLength(a);
    out.resize(static_cast<size_t>(len));
    AAsset_read(a, out.data(), len);
    AAsset_close(a);
    LOGI("ReadAsset: %s -> %zu bytes", assetName, out.size());
    return out;
}

std::vector<uint8_t> HostReadAsset(const char* name) {
    std::vector<uint8_t> out;
    if (!name || !*name) return out;

    // Part of the game data (commonGamePlay.swf, the paid-episode levels and
    // most sounds) shipped in the expansion file and lives under assets/obb/
    // here; the guest asks for the plain path.
    JNIEnv* env = FakeJniEnv::Instance().GetEnv();
    if (env && g_activity_global) {
        out = ReadAsset(env, g_activity_global, name);
        if (out.empty() && strncmp(name, "assets/", 7) != 0) {
            std::string prefixed = std::string("assets/") + name;
            out = ReadAsset(env, g_activity_global, prefixed.c_str());
        }
        if (out.empty() && strncmp(name, "obb/", 4) != 0) {
            std::string obb = std::string("obb/") + name;
            out = ReadAsset(env, g_activity_global, obb.c_str());
        }
    }
    return out;
}

static bool EnsureGameLoaded(JNIEnv* env) {
    if (g_host) return true;

    g_host = std::make_unique<DynarmicHost>();
    if (!g_host->Initialize()) {
        LOGE("Failed to initialize Dynarmic Host");
        g_host.reset();
        return false;
    }
    FakeJniEnv::Instance().Init(*g_host);
    FakeJniEnv::Instance().AttachHostEnv(env);

    if (!g_activity_global) {
        LOGE("No activity to read assets from!");
        g_host.reset();
        return false;
    }
    std::vector<uint8_t> game_data = ReadAsset(env, g_activity_global, "arm32/libtinythief.so");
    std::vector<uint8_t> fmodex_data = ReadAsset(env, g_activity_global, "arm32/libfmodex.so");
    if (game_data.empty() || fmodex_data.empty()) {
        LOGE("Failed to read arm32 assets");
        g_host.reset();
        return false;
    }
    if (!g_host->LoadGameMemory(game_data, fmodex_data)) {
        LOGE("Failed to load and relocate game libraries");
        g_host.reset();
        return false;
    }

    // Guest JNI_OnLoad normally stores JavaVM* in dword_6400E4; we provide the
    // fake VM table instead.
    g_host->MemoryWrite32(0x40000000 + 0x6400E4, FakeJniEnv::Instance().VmTableGuestAddr());

    ElfLoader& el = g_host->GetElfLoader();
    g_sym_appInit       = el.GetSymbolAddress("Java_com_roviostars_tinythief_MainActivity_NativeAppInit");
    g_sym_onCreate      = el.GetSymbolAddress("Java_com_roviostars_tinythief_MainActivity_NativeOnCreate");
    g_sym_cacheObj      = el.GetSymbolAddress("Java_com_roviostars_tinythief_MainActivity_NativeCacheObject");
    g_sym_clearObj      = el.GetSymbolAddress("Java_com_roviostars_tinythief_MainActivity_NativeClearObject");
    g_sym_onChar        = el.GetSymbolAddress("Java_com_roviostars_tinythief_MainActivity_NativeOnChar");
    g_sym_onGesture     = el.GetSymbolAddress("Java_com_roviostars_tinythief_MainActivity_NativeOnGesture");
    g_sym_onKey         = el.GetSymbolAddress("Java_com_roviostars_tinythief_MainActivity_NativeOnKey");
    g_sym_onOpenFile    = el.GetSymbolAddress("Java_com_roviostars_tinythief_MainActivity_NativeOnOpenFile");
    g_sym_onOrientation = el.GetSymbolAddress("Java_com_roviostars_tinythief_MainActivity_NativeOnOrientation");
    g_sym_onPause       = el.GetSymbolAddress("Java_com_roviostars_tinythief_MainActivity_NativeOnPause");
    g_sym_onResume      = el.GetSymbolAddress("Java_com_roviostars_tinythief_MainActivity_NativeOnResume");
    g_sym_onTouch       = el.GetSymbolAddress("Java_com_roviostars_tinythief_MainActivity_NativeOnTouch");
    g_sym_onTouchMouse  = el.GetSymbolAddress("Java_com_roviostars_tinythief_MainActivity_NativeOnTouchMouse");
    g_sym_onWindowFocus = el.GetSymbolAddress("Java_com_roviostars_tinythief_MainActivity_NativeOnWindowFocusChanged");
    g_sym_glDraw        = el.GetSymbolAddress("Java_com_roviostars_tinythief_GLView_NativeDraw");
    g_sym_glReset       = el.GetSymbolAddress("Java_com_roviostars_tinythief_GLView_NativeReset");
    g_sym_glResize      = el.GetSymbolAddress("Java_com_roviostars_tinythief_GLView_NativeResize");
    if (g_host->GetFModExLoader()) {
        g_sym_fmodGetInfo  = g_host->GetFModExLoader()->GetSymbolAddress("Java_org_fmod_FMODAudioDevice_fmodGetInfo");
        g_sym_fmodProcess  = g_host->GetFModExLoader()->GetSymbolAddress("Java_org_fmod_FMODAudioDevice_fmodProcess");
    }

    LOGI("Symbols: appInit=%08X onCreate=%08X glDraw=%08X glResize=%08X fmodGetInfo=%08X fmodProcess=%08X",
         g_sym_appInit, g_sym_onCreate, g_sym_glDraw, g_sym_glResize, g_sym_fmodGetInfo, g_sym_fmodProcess);

    LOGI("Game libraries loaded and relocated successfully!");
    return true;
}

static uint32_t FakeEnv() { return FakeJniEnv::Instance().EnvTableGuestAddr(); }

// -------------------------------------------------------------
// MainActivity natives (forwarded into guest)
// -------------------------------------------------------------

static void TT_NativeAppInit(JNIEnv* env, jclass clazz) {
    LOGI("NativeAppInit");
    if (!g_activity_global) {
        // The native library can be loaded from MainActivity's class initializer,
        // before Android has constructed the Activity. Defer all guest-memory
        // setup until NativeOnCreate owns a valid Activity for asset reads.
        LOGI("Game not loaded yet (assets need Activity) - deferring init");
        return;
    }
    if (!EnsureGameLoaded(env)) {
        return;
    }
    if (g_sym_appInit) g_host->RunFunction(g_sym_appInit, {FakeEnv(), 0});
}

static void TT_NativeOnCreate(JNIEnv* env, jobject thiz) {
    LOGI("NativeOnCreate");
    // First Activity entry point: keep a global ref for asset reads, load the
    // guest libs, then run (possibly deferred) NativeAppInit + NativeOnCreate.
    if (!g_activity_global) g_activity_global = env->NewGlobalRef(thiz);
    if (!EnsureGameLoaded(env)) return;
    if (g_sym_appInit && g_host->MemoryRead32(0x40000000 + 0x6400E0) == 0) {
        LOGI("Running deferred NativeAppInit");
        g_host->RunFunction(g_sym_appInit, {FakeEnv(), 0});
    }
    FakeJniEnv& fj = FakeJniEnv::Instance();
    fj.AttachHostEnv(env);
    uint32_t handle = fj.AddObjectRef(thiz);
    if (g_sym_onCreate) g_host->RunFunction(g_sym_onCreate, {FakeEnv(), handle});
}

static void TT_NativeCacheObject(JNIEnv* env, jobject thiz) {
    // Guest stores NewGlobalRef(thiz) at engine+280 — the Activity handle the
    // asset open path (sub_70590) reads for GetObjectClass/CallBooleanMethod.
    // Passing 0 here makes the movie load fail (GetObjectClass(NULL) -> 0).
    if (!g_host) return;
    FakeJniEnv& fj = FakeJniEnv::Instance();
    fj.AttachHostEnv(env);
    uint32_t handle = fj.AddObjectRef(thiz);
    if (g_sym_cacheObj) g_host->RunFunction(g_sym_cacheObj, {FakeEnv(), handle});
}

static void TT_NativeClearObject(JNIEnv* env, jobject thiz) {
    if (!g_host) return;
    if (g_sym_clearObj) g_host->RunFunction(g_sym_clearObj, {FakeEnv(), 0});
}

static void TT_NativeOnChar(JNIEnv* env, jclass clazz, jint ch) {
    if (!g_host) return;
    if (g_sym_onChar) g_host->RunFunction(g_sym_onChar, {FakeEnv(), 0, static_cast<uint32_t>(ch)});
}

static void TT_NativeOnGesture(JNIEnv* env, jclass clazz, jint event, jint type,
                               jfloat x1, jfloat y1, jfloat x2, jfloat y2, jfloat scale) {
    if (!g_host) return;
    if (!g_sym_onGesture) return;
    uint32_t bits[5];
    memcpy(&bits[0], &x1, 4);
    memcpy(&bits[1], &y1, 4);
    memcpy(&bits[2], &x2, 4);
    memcpy(&bits[3], &y2, 4);
    memcpy(&bits[4], &scale, 4);
    g_host->RunFunction(g_sym_onGesture,
                        {FakeEnv(), 0, static_cast<uint32_t>(event), static_cast<uint32_t>(type),
                         bits[0], bits[1], bits[2], bits[3], bits[4]});
}

static void TT_NativeOnKey(JNIEnv* env, jclass clazz, jboolean down, jint key) {
    if (!g_host) return;
    if (g_sym_onKey) g_host->RunFunction(g_sym_onKey, {FakeEnv(), 0, down ? 1u : 0u, static_cast<uint32_t>(key)});
}

static void TT_NativeOnOpenFile(JNIEnv* env, jclass clazz, jstring path) {
    LOGI("NativeOnOpenFile");
    if (!g_host) return;
    FakeJniEnv& fj = FakeJniEnv::Instance();
    fj.AttachHostEnv(env);
    uint32_t handle = fj.AddObjectRef(path);
    if (g_sym_onOpenFile) g_host->RunFunction(g_sym_onOpenFile, {FakeEnv(), 0, handle});
}

static void TT_NativeOnOrientation(JNIEnv* env, jclass clazz, jint orientation, jboolean isPortrait) {
    if (!g_host) return;
    if (g_sym_onOrientation)
        g_host->RunFunction(g_sym_onOrientation, {FakeEnv(), 0, static_cast<uint32_t>(orientation), isPortrait ? 1u : 0u});
}

static void TT_NativeOnPause(JNIEnv* env, jclass clazz) {
    if (!g_host) return;
    if (g_sym_onPause) g_host->RunFunction(g_sym_onPause, {FakeEnv(), 0});
}

static void TT_NativeOnResume(JNIEnv* env, jclass clazz) {
    if (!g_host) return;
    if (g_sym_onResume) g_host->RunFunction(g_sym_onResume, {FakeEnv(), 0});
}

static void TT_NativeOnTouch(JNIEnv* env, jclass clazz, jint pointerId, jint action, jfloat x, jfloat y) {
    if (!g_host) return;
    if (!g_sym_onTouch) return;
    uint32_t bx, by;
    memcpy(&bx, &x, 4);
    memcpy(&by, &y, 4);
    // softfp: jfloat args are plain 32-bit words in the normal arg sequence
    // (env, clazz, pointerId, action -> r0..r3; x, y -> stack).
    g_host->RunFunction(g_sym_onTouch,
                        {FakeEnv(), 0, static_cast<uint32_t>(pointerId), static_cast<uint32_t>(action), bx, by});
}

static void TT_NativeOnTouchMouse(JNIEnv* env, jclass clazz, jint action, jfloat x, jfloat y) {
    if (!g_host) return;
    if (!g_sym_onTouchMouse) return;
    uint32_t bx, by;
    memcpy(&bx, &x, 4);
    memcpy(&by, &y, 4);
    g_host->RunFunction(g_sym_onTouchMouse,
                        {FakeEnv(), 0, static_cast<uint32_t>(action), bx, by});
}

static void TT_NativeOnWindowFocusChanged(JNIEnv* env, jclass clazz, jboolean hasFocus) {
    if (!g_host) return;
    if (g_sym_onWindowFocus) g_host->RunFunction(g_sym_onWindowFocus, {FakeEnv(), 0, hasFocus ? 1u : 0u});
}

// IAP responses: game IAP pipeline is dead (SWF patched), native side ignored
static void TT_NativeUtilsPaymentCompleteResponse(JNIEnv* env, jclass clazz, jstring s, jboolean b) {}
static void TT_NativeUtilsProductInfoReceivedResponse(JNIEnv* env, jclass clazz, jint i,
                                                      jobjectArray a, jintArray b, jobjectArray c) {}
static void TT_NativeUtilsRestoreCompletePurchasesResponse(JNIEnv* env, jclass clazz, jboolean b) {}

// -------------------------------------------------------------
// GLView natives
// -------------------------------------------------------------

// Both GL natives dereference the engine singleton (GOT slot 0x6400E4, see
// Java_..._NativeReset at 0x74AF8). engine+0x90 is the "App::Init finished"
// byte and engine+0xC0 the "renderer already created" byte. onSurfaceCreated
// fires long before App::Init returns, and the guest's own answer to that is
// Event::Wait(engine+148) — which the WaitIdle patch defeats, so NativeReset
// used to run against a zeroed engine and blx an unallocated vtable slot
// (see the [RUNAWAY] guard in MemoryReadCode). Gate both entry points on the
// engine byte instead and let onDrawFrame retry: it runs every frame anyway.
// 0x74AFC: ldr r4,[pc,#0x74] (=0x5CB5D4); 0x74B00: add r4,pc,r4 with pc=0x74B08
// -> r4 = 0x6400DC, and the engine pointer is [r4+0xC].
static constexpr uint32_t kEngineGlobal = 0x406400E8;
static std::atomic<uint64_t> g_pending_resize{0}; // (w<<32)|h, 0 = none

static uint32_t GuestEngineIfReady() {
    if (!g_host) return 0;
    uint32_t engine = g_host->MemoryRead32(kEngineGlobal);
    if (engine < 0x1000) return 0;
    if (!g_host->MemoryRead8(engine + 0x90)) return 0;
    return engine;
}

static void TT_GL_NativeReset(JNIEnv* env, jclass clazz);

static void TT_GL_NativeDraw(JNIEnv* env, jclass clazz) {
    if (!g_host) return;

    uint32_t engine = GuestEngineIfReady();
    if (!engine) return;
    // onSurfaceCreated may have been skipped for the same reason — run the
    // deferred reset now (the guest sets engine+0xC0 once it has done it).
    if (!g_host->MemoryRead8(engine + 0xC0)) TT_GL_NativeReset(env, clazz);
    if (uint64_t wh = g_pending_resize.exchange(0)) {
        LOGI("NativeResize replay %dx%d", (int)(wh >> 32), (int)(uint32_t)wh);
        if (g_sym_glResize)
            g_host->RunFunction(g_sym_glResize,
                                {FakeEnv(), 0, static_cast<uint32_t>(wh >> 32),
                                 static_cast<uint32_t>(wh)});
    }

    // Java_GLView_NativeDraw is sub_1502F4(engine+140) — it drains the render
    // queue and displays every registered target.
    if (g_sym_glDraw) g_host->RunFunction(g_sym_glDraw, {FakeEnv(), 0});
}

static void TT_GL_NativeReset(JNIEnv* env, jclass clazz) {
    if (!g_host) return;
    uint32_t engine = GuestEngineIfReady();
    if (!engine) {
        LOGI("TT_GL_NativeReset deferred (engine=0x%08X not initialised)",
             g_host->MemoryRead32(kEngineGlobal));
        return;
    }
    LOGI("TT_GL_NativeReset entered (engine=0x%08X player=0x%08X)",
         engine, g_host->MemoryRead32(engine + 0x8C));
    if (g_sym_glReset) g_host->RunFunction(g_sym_glReset, {FakeEnv(), 0});
}

static void TT_GL_NativeResize(JNIEnv* env, jclass clazz, jint w, jint h) {
    LOGI("NativeResize %dx%d", w, h);
    if (!g_host) return;
    if (!GuestEngineIfReady()) { // same engine-not-ready race as NativeReset
        g_pending_resize.store((static_cast<uint64_t>(w) << 32) | static_cast<uint32_t>(h));
        LOGI("NativeResize deferred until the engine is initialised");
        return;
    }
    if (g_sym_glResize) g_host->RunFunction(g_sym_glResize, {FakeEnv(), 0, static_cast<uint32_t>(w), static_cast<uint32_t>(h)});
}

// -------------------------------------------------------------
// FMODAudioDevice natives (forwarded into guest libfmodex.so)
// -------------------------------------------------------------

// FMODAudioDevice.run() calls fmodGetInfo + fmodProcess ~125x/s, always on the
// same device object. AddObjectRef per call meant a permanent NewGlobalRef per
// call: the JNI global reference table hit its 51200-entry cap and aborted the
// process after ~2 minutes. Reuse the handle; re-register only if the device is
// actually replaced.
static uint32_t FmodDeviceHandle(JNIEnv* env, FakeJniEnv& fj, jobject thiz) {
    static uint32_t s_handle = 0;
    jobject prev = fj.ResolveObject(s_handle);
    if (!prev || !env->IsSameObject(prev, thiz)) s_handle = fj.AddObjectRef(thiz);
    return s_handle;
}

static jint TT_FMOD_fmodGetInfo(JNIEnv* env, jobject thiz, jint info) {
    if (!g_host || !g_sym_fmodGetInfo) return 0;
    FakeJniEnv& fj = FakeJniEnv::Instance();
    fj.AttachHostEnv(env);
    uint32_t thizHandle = FmodDeviceHandle(env, fj, thiz);
    return static_cast<jint>(g_host->RunFunction(g_sym_fmodGetInfo,
        {FakeEnv(), thizHandle, static_cast<uint32_t>(info)}));
}

static jint TT_FMOD_fmodProcess(JNIEnv* env, jobject thiz, jobject buffer) {
    if (!g_host || !g_sym_fmodProcess) return 0;
    FakeJniEnv& fj = FakeJniEnv::Instance();
    fj.AttachHostEnv(env);
    uint32_t thizHandle = FmodDeviceHandle(env, fj, thiz);
    uint32_t bufHandle = fj.RegisterDirectBuffer(buffer);
    if (!bufHandle) return -1;
    jint res = static_cast<jint>(g_host->RunFunction(g_sym_fmodProcess,
        {FakeEnv(), thizHandle, bufHandle}));
    fj.CommitDirectBuffer(bufHandle);
    return res;
}

// -------------------------------------------------------------
// JNI Registration
// -------------------------------------------------------------

static const JNINativeMethod g_mainactivity_methods[] = {
    {"NativeAppInit", "()V", (void*)TT_NativeAppInit},
    {"NativeCacheObject", "()V", (void*)TT_NativeCacheObject},
    {"NativeClearObject", "()V", (void*)TT_NativeClearObject},
    {"NativeOnChar", "(I)V", (void*)TT_NativeOnChar},
    {"NativeOnCreate", "()V", (void*)TT_NativeOnCreate},
    {"NativeOnGesture", "(IIFFFFF)V", (void*)TT_NativeOnGesture},
    {"NativeOnKey", "(ZI)V", (void*)TT_NativeOnKey},
    {"NativeOnOpenFile", "(Ljava/lang/String;)V", (void*)TT_NativeOnOpenFile},
    {"NativeOnOrientation", "(IZ)V", (void*)TT_NativeOnOrientation},
    {"NativeOnPause", "()V", (void*)TT_NativeOnPause},
    {"NativeOnResume", "()V", (void*)TT_NativeOnResume},
    {"NativeOnTouch", "(IIFF)V", (void*)TT_NativeOnTouch},
    {"NativeOnTouchMouse", "(IFF)V", (void*)TT_NativeOnTouchMouse},
    {"NativeOnWindowFocusChanged", "(Z)V", (void*)TT_NativeOnWindowFocusChanged},
    {"NativeUtilsPaymentCompleteResponse", "(Ljava/lang/String;Z)V", (void*)TT_NativeUtilsPaymentCompleteResponse},
    {"NativeUtilsProductInfoReceivedResponse", "(I[Ljava/lang/String;[I[Ljava/lang/String;)V", (void*)TT_NativeUtilsProductInfoReceivedResponse},
    {"NativeUtilsRestoreCompletePurchasesResponse", "(Z)V", (void*)TT_NativeUtilsRestoreCompletePurchasesResponse},
};

static const JNINativeMethod g_glview_methods[] = {
    {"NativeDraw", "()V", (void*)TT_GL_NativeDraw},
    {"NativeReset", "()V", (void*)TT_GL_NativeReset},
    {"NativeResize", "(II)V", (void*)TT_GL_NativeResize},
};

static const JNINativeMethod g_fmod_methods[] = {
    {"fmodGetInfo", "(I)I", (void*)TT_FMOD_fmodGetInfo},
    {"fmodProcess", "(Ljava/nio/ByteBuffer;)I", (void*)TT_FMOD_fmodProcess},
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    if (g_jni_onload_done) return JNI_VERSION_1_6;
    g_jni_onload_done = true;
    g_jvm = vm;
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    FakeJniEnv::Instance().SetJavaVM(vm);

    LOGI("JNI_OnLoad: Tiny Thief ARM32->ARM64 bridge");

    jclass main_cls = env->FindClass("com/roviostars/tinythief/MainActivity");
    if (main_cls) {
        env->RegisterNatives(main_cls, g_mainactivity_methods, sizeof(g_mainactivity_methods)/sizeof(g_mainactivity_methods[0]));
        LOGI("Registered %zu natives for MainActivity", sizeof(g_mainactivity_methods)/sizeof(g_mainactivity_methods[0]));
    }
    if (env->ExceptionCheck()) { env->ExceptionDescribe(); env->ExceptionClear(); }

    jclass glview_cls = env->FindClass("com/roviostars/tinythief/GLView");
    if (glview_cls) {
        env->RegisterNatives(glview_cls, g_glview_methods, sizeof(g_glview_methods)/sizeof(g_glview_methods[0]));
        LOGI("Registered %zu natives for GLView", sizeof(g_glview_methods)/sizeof(g_glview_methods[0]));
    }
    if (env->ExceptionCheck()) { env->ExceptionDescribe(); env->ExceptionClear(); }

    jclass fmod_cls = env->FindClass("org/fmod/FMODAudioDevice");
    if (fmod_cls) {
        env->RegisterNatives(fmod_cls, g_fmod_methods, sizeof(g_fmod_methods)/sizeof(g_fmod_methods[0]));
        LOGI("Registered %zu natives for FMODAudioDevice", sizeof(g_fmod_methods)/sizeof(g_fmod_methods[0]));
    }
    if (env->ExceptionCheck()) { env->ExceptionDescribe(); env->ExceptionClear(); }

    return JNI_VERSION_1_6;
}
