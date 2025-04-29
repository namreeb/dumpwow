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
#define _SILENCE_EXPERIMENTAL_FILESYSTEM_DEPRECATION_WARNING

#include "raii_proc.hpp"

#include <Windows.h>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <experimental/filesystem>
#include <fstream>
#include <hadesmem/find_pattern.hpp>
#include <hadesmem/injector.hpp>
#include <hadesmem/module.hpp>
#include <hadesmem/pelib/pe_file.hpp>
#include <hadesmem/pelib/section_list.hpp>
#include <hadesmem/pelib/tls_dir.hpp>
#include <hadesmem/read.hpp>
#include <hadesmem/region_list.hpp>
#include <hadesmem/write.hpp>
#include <intrin.h>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::experimental::filesystem;

bool launch_wow_suspended(const fs::path& path, PROCESS_INFORMATION& proc_info);
hadesmem::PeFile find_wow_pe(const hadesmem::Process& process, size_t& text_start,
                             size_t& text_end);
bool find_tls_offsets(size_t& ldrp_call_init_routine_rva,
                      size_t& tls_callback_caller_rva,
                      size_t& guard_dispatch_icall_offset);
void* find_tls_callback_directory(const hadesmem::Process& process,
                                  const hadesmem::PeFile& pe);
BOOL control_handler(DWORD ctrl_type);
void process_log_file(const fs::path& exe_path);

std::atomic_bool g_exit_wow;

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        std::cerr << "Usage: " << argv[0] << " <wow.exe>" << std::endl;
        return EXIT_FAILURE;
    }

    size_t ldrp_call_init_routine_rva, tls_callback_caller_rva,
        guard_dispatch_icall_offset;

    if (!find_tls_offsets(ldrp_call_init_routine_rva, tls_callback_caller_rva,
                          guard_dispatch_icall_offset))
    {
        std::cerr << "Failed to find TLS offsets" << std::endl;
        return EXIT_FAILURE;
    }

    const fs::path path(argv[1]);

    try
    {
        if (!::SetConsoleCtrlHandler(control_handler, TRUE))
        {
            std::cerr << "SetConsoleCtrlHandler failed" << std::endl;
            return EXIT_FAILURE;
        }

        PROCESS_INFORMATION proc_info;
        if (!launch_wow_suspended(path, proc_info))
        {
            std::cerr << "launch_wow_suspended failed" << std::endl;
            return EXIT_FAILURE;
        }

        std::cout << "Wow PID:                " << proc_info.dwProcessId
                  << std::endl;
        g_exit_wow = false;

        const hadesmem::Process process(proc_info.dwProcessId);

        // ensure process is killed upon exit
        const RaiiProc proc_killer(process.GetId());

        size_t text_start_rva, text_end_rva;
        auto const pe_file = find_wow_pe(process, text_start_rva, text_end_rva);

        std::cout << "Wow base address:       0x" << std::hex
                  << reinterpret_cast<std::uintptr_t>(pe_file.GetBase())
                  << std::endl;

        // temporarily disable TLS callbacks to prevent them from executing
        // when we inject
        auto const tls_callback_directory =
            find_tls_callback_directory(process, pe_file);

        if (!tls_callback_directory)
        {
            std::cerr << "Unable to find TLS callback directory" << std::endl;
            return EXIT_FAILURE;
        }

        std::cout << "TLS callback directory: 0x" << std::hex
                  << reinterpret_cast<std::uintptr_t>(tls_callback_directory)
                  << std::endl;

        auto const first_callback =
            hadesmem::Read<void*>(process, tls_callback_directory);

        std::cout << "First TLS callback:     0x" << std::hex
                  << reinterpret_cast<std::uintptr_t>(first_callback)
                  << std::endl;

        hadesmem::Write<void*>(process, tls_callback_directory, nullptr);

        auto const verify =
            hadesmem::Read<void*>(process, tls_callback_directory);

        if (verify)
        {
            std::cerr << "Failed to zero first TLS callback" << std::endl;
            return EXIT_FAILURE;
        }

        // with the TLS callbacks disabled, our DLL may be safely injected
        const hadesmem::Module unpacker(
            process, hadesmem::InjectDll(process, L"unpacker.dll",
                                         hadesmem::InjectFlags::kPathResolution));

        // call init function in DLL
        auto const func = reinterpret_cast<void (*)(
            size_t, size_t, size_t, DWORD, PVOID, DWORD, size_t, size_t)>(
            hadesmem::FindProcedure(process, unpacker, "DumpBinary"));

        hadesmem::Call(process, func, hadesmem::CallConv::kDefault,
                       ldrp_call_init_routine_rva, tls_callback_caller_rva,
                       guard_dispatch_icall_offset, proc_info.dwThreadId,
                       pe_file.GetBase(), pe_file.GetSize(), text_start_rva,
                       text_end_rva);

        // restore first TLS callback
        hadesmem::Write<void*>(process, tls_callback_directory, first_callback);

        CONTEXT context;
        memset(&context, 0, sizeof(context));
        context.ContextFlags = CONTEXT_ALL;
        ::GetThreadContext(proc_info.hThread, &context);

        if (!::ResumeThread(proc_info.hThread))
        {
            std::cerr << "Failed to resume main thread" << std::endl;
            return EXIT_FAILURE;
        }

        DWORD exit_code = 0;

        do
        {
            if (g_exit_wow)
            {
                std::cout << "Received CTRL-C.  Terminating wow..." << std::endl;
                ::TerminateProcess(process.GetHandle(), 0);
                g_exit_wow = false;
            }

            if (!::GetExitCodeProcess(proc_info.hProcess, &exit_code))
            {
                std::cerr << "GetExitCodeProcess failed" << std::endl;
                return EXIT_FAILURE;
            }

            // if there is a different exit code, the process has exited
            if (exit_code != STILL_ACTIVE)
                break;

            // if STILL_ACTIVE is the exit code, the process may have chosen to
            // exit using that error code, so try one more check
            if (::WaitForSingleObject(proc_info.hProcess, 0) != WAIT_TIMEOUT)
                break;

            // if the waiting timed out, it means the process is still running.
            // so let us sleep for a little while and then check again
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
        } while (true);

        if (!::SetConsoleCtrlHandler(control_handler, FALSE))
        {
            std::cerr << "SetConsoleCtrlHandler failed" << std::endl;
            return EXIT_FAILURE;
        }

        std::cout << "Wow exited with code:   0x" << std::hex << exit_code
                  << std::endl;

        process_log_file(path);
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error:\n" << boost::diagnostic_information(e) << std::endl;
        process_log_file(path);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

bool launch_wow_suspended(const fs::path& path, PROCESS_INFORMATION& proc_info)
{
    // disable ASLR for subprocesses.  this will cause the base address used
    // in memory to match the base address that static analysis tools will use
    SIZE_T cb;
    if (!::InitializeProcThreadAttributeList(nullptr, 1, 0, &cb) &&
        ::GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        return false;

    auto attribs = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(malloc(cb));

    if (!attribs)
        return false;

    if (!::InitializeProcThreadAttributeList(attribs, 1, 0, &cb))
    {
        free(attribs);
        return false;
    }

    DWORD64 attribute =
        PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_OFF;
    if (!::UpdateProcThreadAttribute(
            attribs, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &attribute,
            sizeof(DWORD64), nullptr, nullptr))
    {
        free(attribs);
        return false;
    }

    // launch wow in a suspended state
    STARTUPINFO start_info {};
    start_info.cb = static_cast<DWORD>(sizeof(start_info));
    memset(&proc_info, 0, sizeof(proc_info));

    wchar_t path_raw[MAX_PATH];
    memcpy(&path_raw[0], path.wstring().c_str(),
           (1 + path.wstring().length()) * sizeof(wchar_t));

    auto const result =
        !!::CreateProcessW(path_raw, nullptr, nullptr, nullptr, FALSE,
                           CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, nullptr,
                           nullptr, &start_info, &proc_info);

    return result;
}

hadesmem::PeFile find_wow_pe(const hadesmem::Process& process, size_t& text_start,
                             size_t& text_end)
{
    const hadesmem::RegionList region_list(process);

    // find the PE header for wow
    for (auto const& region : region_list)
    {
        if (region.GetState() == MEM_FREE)
            continue;

        if (region.GetType() != MEM_IMAGE)
            continue;

        if (region.GetProtect() != PAGE_READONLY)
            continue;

        if (region.GetAllocBase() != region.GetBase())
            continue;

        hadesmem::PeFile pe_file(process, region.GetBase(),
                                 hadesmem::PeFileType::kImage,
                                 static_cast<DWORD>(region.GetSize()));

        std::vector<ULONGLONG> callbacks;

        try
        {
            const hadesmem::TlsDir tls_dir(process, pe_file);
            tls_dir.GetCallbacks(std::back_inserter(callbacks));
        }
        catch (const hadesmem::Error&)
        {
            continue;
        }

        // wow has tls callbacks
        if (callbacks.empty())
            continue;

        const hadesmem::SectionList sl {process, pe_file};

        for (auto const& sec : sl)
        {
            if (sec.GetName() == ".text")
            {
                text_start = sec.GetVirtualAddress();
                text_end = text_start + sec.GetSizeOfRawData();
                return pe_file;
            }
        }

        break;
    }

    throw std::runtime_error("WoW PE header not found");
}

void* find_tls_callback_directory(const hadesmem::Process& process,
                                  const hadesmem::PeFile& pe)
{
    try
    {
        const hadesmem::TlsDir tls_dir(process, pe);
        return reinterpret_cast<void*>(tls_dir.GetAddressOfCallBacks());
    }
    catch (const hadesmem::Error&)
    {
        return nullptr;
    }
}

bool find_tls_offsets(size_t& ldrp_call_init_routine_rva,
                      size_t& tls_callback_caller_rva,
                      size_t& guard_dispatch_icall_offset)
{
    auto const ntdll = ::GetModuleHandle(L"ntdll");

    if (!ntdll)
        return false;

    const hadesmem::Process process(::GetCurrentProcessId());

    auto const peb_access = reinterpret_cast<uintptr_t>(
        hadesmem::Find(process, L"ntdll.dll",
                       L"48 89 54 24 ?? 44 89 44 24 ?? 65 48 8b 04 25 60 00 00 "
                       L"00 48 8b 90 ?? 00 00 00",
                       0, 0));

    if (!peb_access)
        return false;

    ldrp_call_init_routine_rva = 0;
    for (auto i = 1; i < 60; ++i)
        // did we find the start of alignment space?
        if (hadesmem::Read<std::uint32_t>(
                process, reinterpret_cast<PVOID>(peb_access - i)) == 0xCCCCCCCC)
        {
            ldrp_call_init_routine_rva =
                peb_access - i + 4 - reinterpret_cast<uintptr_t>(ntdll);
            break;
        }

    if (!ldrp_call_init_routine_rva)
        return false;

    auto const call_guard_dispatch = reinterpret_cast<uintptr_t>(hadesmem::Find(
        process,
        reinterpret_cast<PVOID>(reinterpret_cast<uintptr_t>(ntdll) +
                                ldrp_call_init_routine_rva),
        0x200, L"48 8b ?? e8 ?? ?? ?? 00", 0, 0));

    if (!call_guard_dispatch)
        return false;

    auto const offset = *reinterpret_cast<std::int32_t*>(call_guard_dispatch + 4);
    auto const gdi = call_guard_dispatch + 8 + offset;

    if (*reinterpret_cast<std::uint8_t*>(gdi) != 0xE9)
        return false;

    // compute the offset into LdrpCallInitRoutine of the call to
    // guard_dispatch_icall
    guard_dispatch_icall_offset = call_guard_dispatch + 3 -
                                  reinterpret_cast<uintptr_t>(ntdll) -
                                  ldrp_call_init_routine_rva;

    uintptr_t start = 0u;

    do
    {
        auto current = hadesmem::Find(process, L"ntdll.dll",
                                      L"49 3b c0 74 ?? 45 33 c0 e8 ?? ?? ?? 00 "
                                      L"b8 01 00 00 00 48 83 c4 28 c3 cc",
                                      0, start);

        if (!current)
            return false;

        auto const c = reinterpret_cast<uintptr_t>(current);

        auto const rel_jump = *reinterpret_cast<std::int32_t*>(c + 9);
        auto const func = c + 13 + rel_jump;

        // did we find the right function call?  if so, find the start of the
        // function and return
        if (func == gdi)
        {
            start = c;
            break;
        }

        // if not, keep searching
        start = c + 0x15;
    } while (true);

    for (auto i = 1u; i < 30; ++i)
        if (*reinterpret_cast<std::uint32_t*>(start - i) == 0xCCCCCCCC)
        {
            tls_callback_caller_rva =
                start - i + 4 - reinterpret_cast<uintptr_t>(ntdll);
            return true;
        }

    return false;
}

void process_log_file(const fs::path& exe_path)
{
    auto const parent = exe_path.parent_path();
    auto const log_path = parent / "log.txt";

    std::ifstream in(log_path, std::ios::ate);

    if (!in)
    {
        std::cerr << "Failed to read " << log_path << std::endl;
        return;
    }

    auto const file_size = static_cast<size_t>(in.tellg());
    in.seekg(std::ios::beg);

    std::vector<char> file_data(file_size + 1);
    in.read(&file_data[0], file_data.size());
    file_data[file_data.size() - 1] = '\0';
    in.close();

    std::cout << "\nLog:\n\n" << &file_data[0];

    std::remove(log_path.string().c_str());
}

BOOL control_handler(DWORD ctrl_type)
{
    if (ctrl_type == CTRL_C_EVENT)
    {
        g_exit_wow = true;
        return TRUE;
    }

    std::cout << "Received unrecognized event: " << std::dec << ctrl_type
              << std::endl;

    return FALSE;
}
