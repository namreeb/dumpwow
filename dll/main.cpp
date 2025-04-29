/*
    MIT License

    Copyright (c) 2025 namreeb http://github.com/namreeb/dumpwow

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

#include "log.hpp"
#include "misc.hpp"

#include <Windows.h>
#include <chrono>
#include <hadesmem/patcher.hpp>
#include <hadesmem/pelib/nt_headers.hpp>
#include <hadesmem/pelib/pe_file.hpp>
#include <hadesmem/pelib/section_list.hpp>
#include <hadesmem/pelib/tls_dir.hpp>
#include <iomanip>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

// protect against TLS callbacks interfering with our task
void InitializeTLSProtection(const hadesmem::Process& process,
                             size_t ldrp_call_init_routine_rva,
                             size_t tls_callback_caller_rva,
                             size_t guard_dispatch_icall_offset, PVOID wow_base,
                             DWORD main_thread_id, size_t text_start_rva,
                             size_t text_end_rva);

// hook BaseThreadInitThunk which will call the entry point
void HookBaseThreadInitThunk(const hadesmem::Process& process,
                             DWORD main_thread_id, PVOID wow_base,
                             DWORD wow_pe_size);

// hook NtSetInformationThread to prevent ThreadHideFromDebugger
void HookSetInformationThread(const hadesmem::Process& process);

extern void do_dump(PVOID, DWORD, PVOID);

struct TlsCallbackEntry
{
    PVOID address;
    PVOID callbacks_before[6];
    std::uint8_t initial_bytes[16];
    std::uint8_t last_seen_bytes[sizeof(TlsCallbackEntry::initial_bytes)];
};

static std::vector<TlsCallbackEntry> tls_callback_history;

static PVOID g_tls_callbacks;

extern "C" __declspec(dllexport) void
DumpBinary(size_t ldrp_call_init_routine_rva, size_t tls_callback_caller_rva,
           size_t guard_dispatch_icall_offset, DWORD main_thread_id,
           PVOID wow_base, DWORD wow_pe_size, size_t text_start_rva,
           size_t text_end_rva)
{
    tls_callback_history.clear();
    tls_callback_history.reserve(10);

    try
    {
        const hadesmem::Process process(::GetCurrentProcessId());
        const hadesmem::PeFile wow_pe(process, wow_base,
                                      hadesmem::PeFileType::kImage, wow_pe_size);
        const hadesmem::TlsDir tls_dir(process, wow_pe);

        g_tls_callbacks =
            reinterpret_cast<PVOID>(tls_dir.GetAddressOfCallBacks());

        InitializeTLSProtection(process, ldrp_call_init_routine_rva,
                                tls_callback_caller_rva,
                                guard_dispatch_icall_offset, wow_base,
                                main_thread_id, text_start_rva, text_end_rva);

        HookBaseThreadInitThunk(process, main_thread_id, wow_base, wow_pe_size);
    }
    catch (const std::exception& e)
    {
        std::wstringstream str;
        str << "Unpacker initialization failed: " << e.what();
        ::MessageBox(nullptr, str.str().c_str(), L"Unpacker", 0);
    }
}

void __fastcall log_tls(PVOID base, DWORD reason, PVOID callback)
{
#ifdef _DEBUG
    // first, see if any previously encountered TLS callbacks have changed
    for (auto& e : tls_callback_history)
    {
        if (memcmp(e.last_seen_bytes, e.address, sizeof(e.last_seen_bytes)))
        {
            gLog << "Before calling TLS callback 0x" << callback
                 << ", observed change to callback at 0x" << e.address
                 << ".  New bytes:";
            for (auto i = 0u; i < sizeof(e.last_seen_bytes); ++i)
            {
                const unsigned int byte = *reinterpret_cast<std::uint8_t*>(
                    reinterpret_cast<uintptr_t>(e.address) + i);
                gLog << " " << std::hex << std::uppercase << std::setw(2)
                     << std::setfill('0') << byte;
            }
            gLog << std::endl;

            ::memcpy(e.last_seen_bytes, e.address, sizeof(e.last_seen_bytes));
        }
    }
#endif

    TlsCallbackEntry entry;
    ::memset(&entry, 0, sizeof(entry));

    entry.address = callback;
    ::memcpy(entry.initial_bytes, callback, sizeof(entry.initial_bytes));
    ::memcpy(entry.last_seen_bytes, callback, sizeof(entry.last_seen_bytes));

    static auto constexpr callback_count =
        sizeof(entry.callbacks_before) / sizeof(entry.callbacks_before[0]);

    auto current_callback = reinterpret_cast<PVOID*>(g_tls_callbacks);

    for (auto i = 0u; i < callback_count; ++i)
    {
        entry.callbacks_before[i] = *current_callback;

        if (!entry.callbacks_before[i])
            break;

        ++current_callback;
    }

    // the last should always be nullptr
    if (entry.callbacks_before[callback_count - 1])
        throw std::runtime_error("TLS callback history overflow");

    tls_callback_history.push_back(entry);

#ifdef _DEBUG
    gLog << "Callbacks before calling this one:\n";

    for (auto i = 0u; i < callback_count; ++i)
    {
        if (!entry.callbacks_before[i])
            break;

        gLog << "    " << std::dec << i << ": 0x" << entry.callbacks_before[i]
             << std::endl;
    }

    gLog << "Calling TLS callback in main thread: 0x" << callback
         << " reason: " << std::dec << reason << " bytes:";

    for (auto i = 0u; i < sizeof(entry.initial_bytes); ++i)
    {
        const unsigned int byte = *reinterpret_cast<std::uint8_t*>(
            reinterpret_cast<uintptr_t>(callback) + i);
        gLog << " " << std::hex << std::uppercase << std::setw(2)
             << std::setfill('0') << byte;
    }

    gLog << std::endl;

    gLog << "\n\n" << std::endl;
#endif
}

void InitializeTLSProtection(const hadesmem::Process& process,
                             size_t ldrp_call_init_routine_rva,
                             size_t tls_callback_caller_rva,
                             size_t guard_dispatch_icall_offset, PVOID wow_base,
                             DWORD main_thread_id, size_t text_start_rva,
                             size_t text_end_rva)
{
    auto const ntdll = reinterpret_cast<uintptr_t>(::GetModuleHandle(L"ntdll"));

    auto const tls_callback_caller = ntdll + tls_callback_caller_rva;
    auto const ldrp_call_init_routine = ntdll + ldrp_call_init_routine_rva;

    // address of where guard_dispatch_icall is called for TLS callbacks
    auto const guard_dispatch_icall_call_site =
        ldrp_call_init_routine + guard_dispatch_icall_offset;

    // address of the function itself
    auto const guard_dispatch_icall =
        guard_dispatch_icall_call_site + 5 +
        hadesmem::Read<std::int32_t>(
            process, reinterpret_cast<PVOID>(guard_dispatch_icall_call_site + 1));

    if (hadesmem::Read<std::uint8_t>(
            process, reinterpret_cast<PVOID>(guard_dispatch_icall)) != 0xE9)
        throw std::runtime_error("Did not find JMP in guard_dispatch_icall");

    auto const jmp_dest =
        guard_dispatch_icall + 5u +
        hadesmem::Read<std::int32_t>(
            process, reinterpret_cast<PVOID>(guard_dispatch_icall + 1));

    static constexpr std::uint8_t payload[] = {
        // mov r9, gs:[0x48] (current thread id)
        0x65, 0x4c, 0x8b, 0x0c, 0x25, 0x48, 0x00, 0x00, 0x00,
        // cmp r9, <main thread id>
        0x49, 0x81, 0xf9, 0x00, 0x00, 0x00, 0x00,
        // jne <end>
        0x75, 0x49,
        // mov r9, <wow base>
        0x49, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // cmp rax, r9
        0x4c, 0x39, 0xc8,
        // jb <end>
        0x72, 0x3a,
        // mov r9, <wow end>
        0x49, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // cmp rax, r9
        0x4c, 0x39, 0xc8,
        // jae <end>
        0x73, 0x2b,
        // push rbp
        0x55,
        // mov rbp, rsp
        0x48, 0x89, 0xe5,
        // push rax
        0x50,
        // push rcx
        0x51,
        // push rdx
        0x52,
        // push r8
        0x41, 0x50,
        // mov r8, rax
        0x49, 0x89, 0xc0,
        // mov rax, <func ptr>
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // sub rsp, 0x20 (shadow space)
        0x48, 0x83, 0xec, 0x20,
        // call rax
        0xff, 0xd0,
        // add rsp, 0x20 (shadow space)
        0x48, 0x83, 0xc4, 0x20,
        // pop r8
        0x41, 0x58,
        // pop rdx
        0x5a,
        // mov edx, 1 (DLL_PROCESS_ATTACH)
        0xba, 0x01, 0x00, 0x00, 0x00,
        // pop rcx
        0x59,
        // pop rax
        0x58,
        // leave
        0xc9,
        // jmp <old loc>
        0xe9, 0x00, 0x00, 0x00, 0x00};

    auto static constexpr main_thread_ofs = 12;
    auto static constexpr wow_base_ofs = 20;
    auto static constexpr wow_end_ofs = 35;
    auto static constexpr func_ptr_ofs = 62;
    auto static constexpr jmp_ptr_ofs = sizeof(payload) - 4;

    bool payload_written = false;
    for (auto i = 1u; i < 10; ++i)
    {
        // look for large enough alignment space for our payload
        auto const check_address = guard_dispatch_icall + 0x10u * i;

        // check if there is space in this location
        bool space = true;
        for (auto j = 0u; j <= sizeof(payload); ++j)
            if (hadesmem::Read<std::uint8_t>(
                    process, reinterpret_cast<PVOID>(check_address + j)) != 0xCC)
            {
                space = false;
                break;
            }

        if (!space)
            continue;

        auto const new_rva = static_cast<std::int32_t>(
            jmp_dest - (check_address + jmp_ptr_ofs + 4));

        // write payload
        hadesmem::Write(process, reinterpret_cast<PVOID>(check_address), payload);

        // update values within payload
        hadesmem::Write(process,
                        reinterpret_cast<PVOID>(check_address + main_thread_ofs),
                        main_thread_id);
        hadesmem::Write(process,
                        reinterpret_cast<PVOID>(check_address + wow_base_ofs),
                        reinterpret_cast<uintptr_t>(wow_base) + text_start_rva);
        hadesmem::Write(process,
                        reinterpret_cast<PVOID>(check_address + wow_end_ofs),
                        reinterpret_cast<uintptr_t>(wow_base) + text_end_rva);
        hadesmem::Write(process,
                        reinterpret_cast<PVOID>(check_address + func_ptr_ofs),
                        &log_tls);
        hadesmem::Write(process,
                        reinterpret_cast<PVOID>(check_address + jmp_ptr_ofs),
                        new_rva);

        // update call within LdrpCallInitRoutine
        auto const trampoline_offset = static_cast<std::int32_t>(
            static_cast<intptr_t>(check_address) -
            static_cast<intptr_t>(guard_dispatch_icall_call_site) - 5);

        hadesmem::Write(
            process, reinterpret_cast<PVOID>(guard_dispatch_icall_call_site + 1),
            trampoline_offset);

        // done!
        payload_written = true;
        break;
    }

    if (!payload_written)
        throw std::runtime_error("No space for payload");

    // redirect call to guard_dispatch_icall in LdrCallInitRoutine

    for (auto i = 0u; i < 0x100; ++i)
    {
        // static signature check
        if (hadesmem::Read<std::uint32_t>(
                process, reinterpret_cast<PVOID>(ldrp_call_init_routine + i)) !=
            0x498BC4E8)
            continue;

        auto const offset = hadesmem::Read<std::int32_t>(
            process, reinterpret_cast<PVOID>(ldrp_call_init_routine + i + 4));
        auto const target =
            reinterpret_cast<PVOID>(ldrp_call_init_routine + i + 8 + offset);

        std::stringstream str;

        str << "Address: " << (PVOID)(ldrp_call_init_routine + i) << " offset: 0x"
            << std::hex << offset << " target: " << target;

        ::MessageBoxA(nullptr, str.str().c_str(), "DEBUG", 0);
    }
}

using BaseThreadInitThunkT = std::uint64_t (*)(std::uint64_t, PVOID,
                                               std::uint64_t);

std::uint64_t BaseThreadInitThunkHook(hadesmem::PatchDetourBase* detour,
                                      PVOID base, DWORD wow_pe_size,
                                      DWORD main_thread_id, std::uint64_t a1,
                                      PVOID func, std::uint64_t a3)
{
    if (::GetCurrentThreadId() != main_thread_id)
        return detour->GetTrampolineT<BaseThreadInitThunkT>()(a1, func, a3);

    try
    {
        detour->Remove();
#ifdef _DEBUG
        static auto constexpr callback_count =
            sizeof(TlsCallbackEntry::callbacks_before) /
            sizeof(TlsCallbackEntry::callbacks_before[0]);

        auto current_callback = reinterpret_cast<PVOID*>(g_tls_callbacks);

        gLog << "TLS callbacks before dump:\n";
        for (auto i = 0u; i < callback_count; ++i)
        {
            if (!*current_callback)
                break;

            gLog << "    " << std::dec << i << ": 0x" << *current_callback
                 << std::endl;
            ++current_callback;
        }
#endif
        do_dump(base, wow_pe_size, func);
    }
    catch (const std::exception& e)
    {
        ::MessageBoxA(nullptr, boost::diagnostic_information(e).c_str(),
                      "Unpacker Error", MB_ICONERROR);
    }

    ::TerminateProcess(::GetCurrentProcess(), 0);

    detour->Remove();
    return detour->GetTrampolineT<BaseThreadInitThunkT>()(a1, func, a3);
}

void HookBaseThreadInitThunk(const hadesmem::Process& process,
                             DWORD main_thread_id, PVOID wow_base,
                             DWORD wow_pe_size)
{
    auto const k32 = ::GetModuleHandle(L"kernel32");
    if (!k32)
        throw std::runtime_error("Could not find kernel32");

    auto const orig = reinterpret_cast<BaseThreadInitThunkT>(
        ::GetProcAddress(k32, "BaseThreadInitThunk"));

    if (!orig)
        throw std::runtime_error("Could not find kernel32!BaseThreadInitThunk");

    // this is a memory leak but the process will not be long running so we
    // dont care
    auto const init_detour = new hadesmem::PatchDetour<BaseThreadInitThunkT>(
        process, orig,
        [main_thread_id, wow_base, wow_pe_size](hadesmem::PatchDetourBase* detour,
                                                std::uint64_t a1, PVOID func,
                                                std::uint64_t a3)
        {
            return BaseThreadInitThunkHook(detour, wow_base, wow_pe_size,
                                           main_thread_id, a1, func, a3);
        });

    init_detour->Apply();
}

void HookSetInformationThread(const hadesmem::Process& process)
{
    auto const ntdll = ::GetModuleHandle(L"ntdll");
    if (!ntdll)
        throw std::runtime_error("Could not find ntdll");

    using SetInformationThreadT =
        NTSTATUS (*)(HANDLE, THREADINFOCLASS, PVOID, ULONG);

    auto const orig = reinterpret_cast<SetInformationThreadT>(
        ::GetProcAddress(ntdll, "NtSetInformationThread"));

    if (!orig)
        throw std::runtime_error("Could not find ntdll!NtSetInformationThread");

    auto const set_information_thread_detour =
        new hadesmem::PatchDetour<SetInformationThreadT>(
            process, orig,
            [](hadesmem::PatchDetourBase* detour, HANDLE thread_handle,
               THREADINFOCLASS info_class, PVOID thread_info, ULONG info_length)
            {
                static constexpr THREADINFOCLASS ThreadHideFromDebugger =
                    static_cast<THREADINFOCLASS>(0x11);

                if (info_class == ThreadHideFromDebugger && !thread_info &&
                    !info_length)
                    return static_cast<NTSTATUS>(0);

                return detour->GetTrampolineT<SetInformationThreadT>()(
                    thread_handle, info_class, thread_info, info_length);
            });

    set_information_thread_detour->Apply();
}