// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <jni.h>
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>

namespace Dynarmic::A32 { class Jit; }
class DynarmicHost;

// Fake JNIEnv/JavaVM tables built in guest memory. Guest 32-bit code calls
// env->XXX via its fixed JNI function-table offsets; each slot is an SVC
// trampoline dispatched here. Opaque jobject/jmethodID/jfieldID values passed
// to/from the guest are 32-bit handles backed by a host-side table.
class FakeJniEnv {
public:
    static FakeJniEnv& Instance();

    // Must be called after DynarmicHost::Initialize() (needs guest memory + thunk manager)
    void Init(DynarmicHost& host);
    // Host JNIEnv used to call the real 64-bit JVM (set on first JNI entry)
    void AttachHostEnv(JNIEnv* env);
    void SetJavaVM(JavaVM* vm) { m_vm = vm; }
    // Per-host-thread JNIEnv (AttachCurrentThread for guest worker threads)
    JNIEnv* GetEnv();

    uint32_t EnvTableGuestAddr() const { return m_env_table; }
    uint32_t VmTableGuestAddr() const { return m_vm_table; }

    // ---- handles ----
    uint32_t AddObjectRef(jobject o);              // NewGlobalRef + handle
    jobject  ResolveObject(uint32_t handle) const;
    uint32_t AddMethod(jmethodID mid, bool isStatic, uint32_t clsHandle, const std::string& sig);
    uint32_t AddField(jfieldID fid);

    // ---- dispatch (called from thunk handlers) ----
    void DispatchEnvSlot(uint32_t offset, Dynarmic::A32::Jit& jit);
    void DispatchVmSlot(uint32_t offset, Dynarmic::A32::Jit& jit);

    // ---- direct ByteBuffer bridging (FMOD fmodProcess) ----
    // Registers a Java direct ByteBuffer, mirrors its content into guest
    // scratch memory and returns the guest handle.
    uint32_t RegisterDirectBuffer(jobject buf);
    // Copies guest scratch back into the host direct buffer.
    void CommitDirectBuffer(uint32_t handle);
    jlong DirectBufferCapacity(uint32_t handle) const;

private:
    struct MethodInfo {
        jmethodID mid = nullptr;
        bool isStatic = false;
        uint32_t clsHandle = 0;
        std::string sig;
    };

    struct DirectBuf {
        jobject jobj = nullptr;   // global ref
        void* hostPtr = nullptr;
        jlong capacity = 0;
        uint32_t scratch = 0;     // guest addr
    };

    struct GuestArg {
        char type = 0;      // Z B C S I J F D L
        uint64_t v = 0;
        jobject obj = nullptr;
    };

    JavaVM* m_vm = nullptr;
    DynarmicHost* m_host = nullptr;
    mutable std::mutex m_mutex;
    uint32_t m_env_table = 0;
    uint32_t m_vm_table = 0;

    uint32_t m_next_obj_handle = 0x00020000;
    uint32_t m_next_mid_handle = 0x00030000;
    uint32_t m_next_fid_handle = 0x00040000;

    std::unordered_map<uint32_t, jobject> m_objects;
    std::unordered_map<uint32_t, MethodInfo> m_methods;
    std::unordered_map<uint32_t, jfieldID> m_fields;
    std::unordered_map<uint32_t, DirectBuf> m_direct_bufs;
    std::unordered_map<uint32_t, uint32_t> m_jstr_utf; // jstring handle -> guest copy

    std::vector<char> ParseParams(const std::string& sig) const;
    std::vector<GuestArg> ReadArgsA(Dynarmic::A32::Jit& jit, const std::vector<char>& params, uint32_t jvalue_guest);
    std::vector<GuestArg> ReadArgsV(Dynarmic::A32::Jit& jit, const std::vector<char>& params, uint32_t va_list_guest);
    std::vector<GuestArg> ReadArgsVar(Dynarmic::A32::Jit& jit, const std::vector<char>& params);

    void CallMethod(Dynarmic::A32::Jit& jit, uint32_t mid_handle, uint32_t obj_handle,
                    char retType, const std::vector<GuestArg>& args, bool isStatic);
};
