// SPDX-License-Identifier: GPL-3.0-or-later
#include "thunk_manager.h"
#include "dynarmic_host.h"
#include "thunk_types.h"
#include <android/log.h>
#include <stdexcept>

#define LOG_TAG "TT_ThunkManager"
#include "bridge_logging.h"

ThunkManager::ThunkManager(DynarmicHost& host) : m_host(host) {}

ThunkManager::~ThunkManager() = default;

void ThunkManager::RegisterAllThunks() {
    RegisterGLThunks();
    RegisterLibcThunks();
}

uint32_t ThunkManager::RegisterThunk(const std::string& name, ThunkHandler handler) {
    std::lock_guard lock(m_registry_mutex);
    if (name.empty() || !handler) throw std::invalid_argument("Invalid thunk registration");
    // Re-registering an existing name replaces the handler but keeps the
    // same trampoline address (relocations already resolved elsewhere).
    auto existing = m_symbol_to_address.find(name);
    uint32_t thunk_id;
    uint32_t thunk_addr;
    if (existing != m_symbol_to_address.end()) {
        thunk_addr = existing->second;
        thunk_id = m_host.MemoryRead32(thunk_addr) & 0x00FFFFFF;
    } else {
        thunk_id = (m_next_thunk_addr - 0x00010000) / 8 + 1;
        if (thunk_id > kMaxThunks) throw std::overflow_error("Guest trampoline page exhausted");
        thunk_addr = m_next_thunk_addr;
        m_next_thunk_addr += 8; // 2 instructions per trampoline

        // ARM32 trampoline: SVC #thunk_id ; BX LR
        m_host.MemoryWrite32(thunk_addr, 0xEF000000 | thunk_id);
        m_host.MemoryWrite32(thunk_addr + 4, 0xE12FFF1E);
        m_symbol_to_address[name] = thunk_addr;
    }
    auto entry = std::make_unique<ThunkEntry>(ThunkEntry{name, std::move(handler)});
    const auto* published = entry.get();
    m_entries.push_back(std::move(entry));
    m_dispatch[thunk_id - 1].store(published, std::memory_order_release);
    return thunk_addr;
}

uint32_t ThunkManager::GetOrCreateThunkAddress(const std::string& name) {
    {
        std::lock_guard lock(m_registry_mutex);
        auto it = m_symbol_to_address.find(name);
        if (it != m_symbol_to_address.end()) return it->second;
    }
    // Default dummy stub if not explicitly registered
    return RegisterThunk(name, [name](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGI("[THUNK] Default stub executed for: %s", name.c_str());
        jit.Regs()[0] = 0;
    });
}

bool ThunkManager::HasThunk(const std::string& name) const {
    std::lock_guard lock(m_registry_mutex);
    return m_symbol_to_address.find(name) != m_symbol_to_address.end();
}

void ThunkManager::DispatchThunk(uint32_t thunk_id, Dynarmic::A32::Jit& jit) {
    const auto* entry = thunk_id && thunk_id <= kMaxThunks
        ? m_dispatch[thunk_id - 1].load(std::memory_order_acquire) : nullptr;
    if (entry) {
        entry->handler(jit, m_host);
        return;
    }
    LOGE("[THUNK] Unknown thunk ID: %u at PC: 0x%08X", thunk_id, jit.Regs()[15]);
    jit.Regs()[0] = 0;
}
