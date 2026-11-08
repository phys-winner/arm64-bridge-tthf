// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <dynarmic/interface/A32/a32.h>

// Helper to convert 32-bit guest pointer to 64-bit host pointer
inline void* GuestToHost(uint8_t* base, uint32_t gaddr) {
    if (gaddr == 0) return nullptr;
    return reinterpret_cast<void*>(base + gaddr);
}

// Helper to convert 64-bit host pointer into 32-bit guest address (if within guest arena)
inline uint32_t HostToGuest(uint8_t* base, void* hptr) {
    if (!hptr) return 0;
    return static_cast<uint32_t>(reinterpret_cast<uintptr_t>(hptr) - reinterpret_cast<uintptr_t>(base));
}

// -------------------------------------------------------------
// Soft-float-ABI (base AAPCS) helpers.
// libtinythief.so has no Tag_ABI_VFP_args attribute, i.e. it is built
// -mfloat-abi=softfp: VFP is used for arithmetic, but FP *arguments and
// results* travel in the core registers:
//   float  arg N  -> r[N]                     (r0..r3, then the stack)
//   double arg N  -> r[2N]:r[2N+1] lo:hi      (even-aligned pair)
//   float  return -> r0,  double return -> r0:r1
// Verified in the guest: `VMOV R0, S14 / BL sqrtf / VMOV S15, R0`, and
// Java_..._NativeOnTouch reading its jfloat args off the stack.
//
// `idx` is the argument slot, so the index arithmetic is the same as it was
// for the VFP register file — only the register bank changes.
// -------------------------------------------------------------

inline float ReadSF(Dynarmic::A32::Jit& jit, int idx) {
    float v;
    uint32_t raw = jit.Regs()[idx];
    memcpy(&v, &raw, 4);
    return v;
}

inline void WriteSF(Dynarmic::A32::Jit& jit, int idx, float v) {
    uint32_t raw;
    memcpy(&raw, &v, 4);
    jit.Regs()[idx] = raw;
}

inline double ReadDF(Dynarmic::A32::Jit& jit, int d_idx) {
    uint64_t raw = static_cast<uint64_t>(jit.Regs()[d_idx * 2]) |
                   (static_cast<uint64_t>(jit.Regs()[d_idx * 2 + 1]) << 32);
    double v;
    memcpy(&v, &raw, 8);
    return v;
}

inline void WriteDF(Dynarmic::A32::Jit& jit, int d_idx, double v) {
    uint64_t raw;
    memcpy(&raw, &v, 8);
    jit.Regs()[d_idx * 2] = static_cast<uint32_t>(raw & 0xFFFFFFFFu);
    jit.Regs()[d_idx * 2 + 1] = static_cast<uint32_t>(raw >> 32);
}

// Argument slots past r3 live on the guest stack at [sp + byte_off].
inline float ReadStackF(Dynarmic::A32::Jit& jit, uint8_t* guest_base, int byte_off) {
    uint32_t sp = jit.Regs()[13];
    float v;
    memcpy(&v, guest_base + sp + byte_off, 4);
    return v;
}
