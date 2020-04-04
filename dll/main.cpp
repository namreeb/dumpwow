/*
    MIT License

    Copyright (c) 2020 namreeb (legal@namreeb.org) http://github.com/namreeb/dumpwow

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

#include "misc.hpp"
#include "log.hpp"

#include <hadesmem/patcher.hpp>
#include <hadesmem/pelib/pe_file.hpp>
#include <hadesmem/pelib/nt_headers.hpp>

#include <Windows.h>

#include <sstream>
#include <iomanip>
#include <string>

// hook LdrpCallTlsInitializers to replace the reason 
void HookCallTLSCallbacks(const hadesmem::Process &process, size_t rva,
    DWORD main_thread_id);

// hook BaseThreadInitThunk which will call the entry point
void HookBaseThreadInitThunk(const hadesmem::Process &process,
    DWORD main_thread_id, PVOID wow_base, DWORD wow_size);

// hook NtSetInformationThread to prevent ThreadHideFromDebugger
void HookSetInformationThread(const hadesmem::Process &process);

extern void do_dump(PVOID, DWORD);

extern "C" __declspec(dllexport) void Initialize(
    size_t call_tls_initializers_rva, DWORD main_thread_id, PVOID wow_base,
    DWORD wow_size)
{
    try
    {
        const hadesmem::Process process(::GetCurrentProcessId());

        HookCallTLSCallbacks(process, call_tls_initializers_rva,
            main_thread_id);
        HookBaseThreadInitThunk(process, main_thread_id, wow_base, wow_size);
        HookSetInformationThread(process);
    }
    catch (const std::exception &e)
    {
        std::wstringstream str;
        str << "Unpacker initialization failed: " << e.what();
        ::MessageBox(nullptr, str.str().c_str(), L"Unpacker", 0);
    }
}

void HookCallTLSCallbacks(const hadesmem::Process &process, size_t rva,
    DWORD main_thread_id)
{
    auto const ntdll = ::GetModuleHandle(L"ntdll");

    using LdrpCallTlsInitializersT = bool(*)(int, PVOID);

    auto const orig_call_tls_initializers = reinterpret_cast<
        LdrpCallTlsInitializersT>(reinterpret_cast<unsigned char *>(ntdll)
            + rva);

    // this is a memory leak but the process will not be long running so we
    // dont care
    auto const call_tls_detour = new hadesmem::PatchDetour<
        LdrpCallTlsInitializersT>(process, orig_call_tls_initializers,
            [main_thread_id](hadesmem::PatchDetourBase *detour,
                int reason, PVOID header)
    {
        // replace DLL_THREAD_ATTACH with DLL_PROCESS_ATTACH for the
        // main thread while this hook is active during startup.
        if (::GetCurrentThreadId() == main_thread_id &&
            reason == DLL_THREAD_ATTACH)
            reason = DLL_PROCESS_ATTACH;
        return detour->GetTrampolineT<LdrpCallTlsInitializersT>()
            (reason, header);
    });

    call_tls_detour->Apply();
}

using BaseThreadInitThunkT = std::uint64_t(*)(std::uint64_t,
    PVOID, std::uint64_t);

std::uint64_t BaseThreadInitThunkHook(hadesmem::PatchDetourBase *detour,
    PVOID base, DWORD pe_size, DWORD main_thread_id, std::uint64_t a1,
    PVOID func, std::uint64_t a3)
{
    if (::GetCurrentThreadId() != main_thread_id)
        return detour->GetTrampolineT<BaseThreadInitThunkT>()(a1, func,
            a3);

    try
    {
        const hadesmem::Process process(::GetCurrentProcessId());

        // PE header in memory is clobbered by TLS callbacks
        auto pe_buff = read_pe_header_from_exe(get_exe_path(), pe_size);

        const hadesmem::PeFile pe_file(process, &pe_buff[0],
            hadesmem::PeFileType::kData, static_cast<DWORD>(pe_buff.size()));

        const hadesmem::NtHeaders nt_header(process, pe_file);

        auto const entry_point = reinterpret_cast<PVOID>(
            reinterpret_cast<char *>(base) +
            nt_header.GetAddressOfEntryPoint());

        if (func != entry_point)
            return detour->GetTrampolineT<BaseThreadInitThunkT>()(a1, func,
                a3);

        if (*reinterpret_cast<std::uint8_t *>(entry_point) != 0xE9)
            throw std::runtime_error(
                "Entry point should start with a JMP (0xE9)");

        try
        {
            detour->Remove();
            do_dump(base, pe_size);
        }
        catch (const std::exception &e)
        {
            ::MessageBoxA(nullptr, boost::diagnostic_information(e).c_str(),
                "Unpacker Error", MB_ICONERROR);
        }
    }
    catch (const std::exception &e)
    {
        ::MessageBoxA(nullptr, boost::diagnostic_information(e).c_str(),
            "BaseThreadInitThunk Error", MB_ICONERROR);
    }

    ::TerminateProcess(::GetCurrentProcess(), 0);

    detour->Remove();
    return detour->GetTrampolineT<BaseThreadInitThunkT>()(a1, func,
        a3);
}

void HookBaseThreadInitThunk(const hadesmem::Process &process,
    DWORD main_thread_id, PVOID wow_base, DWORD wow_size)
{
    auto const k32 = ::GetModuleHandle(L"kernel32");
    if (!k32)
        throw std::runtime_error("Could not find kernel32");

    auto const orig = reinterpret_cast<BaseThreadInitThunkT>(
        ::GetProcAddress(k32, "BaseThreadInitThunk"));

    if (!orig)
        throw std::runtime_error("Could not find kernel32!BaseThreadInitThunk");

    auto pe_buff = read_pe_header_from_exe(get_exe_path(), wow_size);

    const hadesmem::PeFile pe_file(process, &pe_buff[0],
        hadesmem::PeFileType::kData, static_cast<DWORD>(pe_buff.size()));
    const hadesmem::NtHeaders nt_headers(process, pe_file);

    auto const entry_point = reinterpret_cast<const void *>(
        reinterpret_cast<std::uint8_t *>(wow_base) +
        nt_headers.GetAddressOfEntryPoint());

    // this is a memory leak but the process will not be long running so we
    // dont care
    auto const init_detour = new hadesmem::PatchDetour<
        BaseThreadInitThunkT>(process, orig,
            [entry_point, main_thread_id, wow_base, wow_size](
                hadesmem::PatchDetourBase *detour, std::uint64_t a1,
                PVOID func, std::uint64_t a3)
        {
            return BaseThreadInitThunkHook(detour, wow_base, wow_size,
                main_thread_id, a1, func, a3);
        });

    init_detour->Apply();
}

void HookSetInformationThread(const hadesmem::Process &process)
{
    auto const ntdll = ::GetModuleHandle(L"ntdll");
    if (!ntdll)
        throw std::runtime_error("Could not find ntdll");

    using SetInformationThreadT = NTSTATUS(*)(HANDLE, THREADINFOCLASS, PVOID,
        ULONG);

    auto const orig = reinterpret_cast<SetInformationThreadT>(
        ::GetProcAddress(ntdll, "NtSetInformationThread"));

    if (!orig)
        throw std::runtime_error(
            "Could not find ntdll!NtSetInformationThread");

    auto const set_information_thread_detour = new hadesmem::PatchDetour<
        SetInformationThreadT>(process, orig,
            [](hadesmem::PatchDetourBase *detour, HANDLE thread_handle,
                THREADINFOCLASS info_class, PVOID thread_info,
                ULONG info_length)
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