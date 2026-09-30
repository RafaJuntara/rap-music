#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cstdint>
#include <cstring>

namespace {
    using CMDPROC = void(__cdecl*)(const char*);
    using AddCommandFn = void(__thiscall*)(uintptr_t, const char*, CMDPROC);
    using AddMessageFn = void(__thiscall*)(uintptr_t, uint32_t, const char*);

    // SA-MP 0.3.7-R1 verified profile.
    constexpr DWORD R1_ENTRYPOINT = 0x31DF13;
    constexpr uintptr_t R1_INPUT_PTR = 0x21A0E8;
    constexpr uintptr_t R1_ADD_COMMAND = 0x65AD0;
    constexpr uintptr_t R1_CHAT_PTR = 0x21A0E4;
    constexpr uintptr_t R1_ADD_MESSAGE = 0x645A0;

    HMODULE g_samp = nullptr;
    uintptr_t g_base = 0;
    volatile LONG g_registered = 0;

    uintptr_t base() {
        return reinterpret_cast<uintptr_t>(g_samp);
    }

    bool validModule() {
        if (!g_samp) return false;
        auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(g_samp);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(g_base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
        if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) return false;
        return nt->OptionalHeader.AddressOfEntryPoint == R1_ENTRYPOINT;
    }

    bool readable(const void* p, SIZE_T size) {
        if (!p || size == 0) return false;
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(p, &mbi, sizeof(mbi))) return false;
        if (mbi.State != MEM_COMMIT) return false;
        const DWORD protect = mbi.Protect & 0xFF;
        if (protect == PAGE_NOACCESS || protect == PAGE_GUARD) return false;
        const auto begin = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        const auto end = begin + mbi.RegionSize;
        const auto addr = reinterpret_cast<uintptr_t>(p);
        return addr >= begin && size <= (end - addr);
    }

    void chat(const char* text) {
        auto slot = reinterpret_cast<uintptr_t*>(g_base + R1_CHAT_PTR);
        if (!readable(slot, sizeof(uintptr_t))) return;
        auto pChat = *slot;
        if (!pChat) return;
        auto fn = reinterpret_cast<AddMessageFn>(g_base + R1_ADD_MESSAGE);
        if (!readable(reinterpret_cast<const void*>(fn), 1)) return;
        fn(pChat, 0xFFFFFFFFu, text);
    }

    void __cdecl cmdMusic(const char* args) {
        if (!args) args = "";
        while (*args == ' ' || *args == '\t') ++args;

        if (_strnicmp(args, "play", 4) == 0) {
            chat("~ RapMusic: play command received.");
        } else if (_strnicmp(args, "pause", 5) == 0) {
            chat("~ RapMusic: pause command received.");
        } else if (_strnicmp(args, "next", 4) == 0) {
            chat("~ RapMusic: next command received.");
        } else if (_strnicmp(args, "prev", 4) == 0) {
            chat("~ RapMusic: prev command received.");
        } else if (_strnicmp(args, "now", 3) == 0) {
            chat("~ RapMusic: now command received.");
        } else {
            chat("~ RapMusic: usage: /music play | pause | next | prev | now");
        }
    }

    bool tryRegister() {
        auto inputSlot = reinterpret_cast<uintptr_t*>(g_base + R1_INPUT_PTR);
        if (!readable(inputSlot, sizeof(uintptr_t))) return false;

        auto input = *inputSlot;
        if (!input) return false;

        auto add = reinterpret_cast<AddCommandFn>(g_base + R1_ADD_COMMAND);
        if (!readable(reinterpret_cast<const void*>(add), 1)) return false;

        add(input, "music", cmdMusic);
        InterlockedExchange(&g_registered, 1);
        chat("~ RapMusic R1 loaded. /music is registered.");
        return true;
    }

    DWORD WINAPI initThread(LPVOID) {
        for (int i = 0; i < 300; ++i) {
            g_samp = GetModuleHandleA("samp.dll");
            if (g_samp) break;
            Sleep(100);
        }

        if (!g_samp) return 0;
        g_base = base();

        if (!validModule()) return 0;

        // Wait for SA-MP's CInput object to be initialized.
        for (int i = 0; i < 300 && !g_registered; ++i) {
            if (tryRegister()) break;
            Sleep(100);
        }

        return 0;
    }
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        HANDLE thread = CreateThread(nullptr, 0, initThread, nullptr, 0, nullptr);
        if (thread) CloseHandle(thread);
    }
    return TRUE;
}
