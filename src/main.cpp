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

#include "raii_proc.hpp"

#include <hadesmem/injector.hpp>
#include <hadesmem/region_list.hpp>
#include <hadesmem/module.hpp>
#include <hadesmem/read.hpp>
#include <hadesmem/write.hpp>
#include <hadesmem/pelib/pe_file.hpp>
#include <hadesmem/pelib/tls_dir.hpp>
#include <hadesmem/find_pattern.hpp>

#include <Windows.h>
#include <intrin.h>

#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <thread>
#include <chrono>
#include <fstream>
#include <cstdio>
#include <atomic>

#pragma intrinsic(_ReturnAddress)

#define CALL_FIRST  1

namespace fs = std::experimental::filesystem;

bool launch_wow_suspended(const fs::path &path,
    PROCESS_INFORMATION &proc_info);
hadesmem::PeFile find_wow_pe(const hadesmem::Process &process);
void *find_tls_callback_directory(const hadesmem::Process &process,
    const hadesmem::PeFile &pe);
BOOL ControlHandler(DWORD ctrl_type);
bool FindVEHCallerRVA();
size_t find_call_tls_initializers_rva();
void process_log_file(const fs::path &exe_path);

size_t g_veh_caller_rva;
std::atomic_bool g_exit_wow;

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        std::cerr << "Usage: " << argv[0] << " <wow.exe>" << std::endl;
        return EXIT_FAILURE;
    }

    auto const call_tls_initializers_rva = find_call_tls_initializers_rva();

    if (!call_tls_initializers_rva)
    {
        std::cerr << "Failed to find LdrpCallTlsInitializers" << std::endl;
        return EXIT_FAILURE;
    }

    const fs::path path(argv[1]);

    try
    {
        PROCESS_INFORMATION proc_info;
        if (!launch_wow_suspended(path, proc_info))
        {
            std::cerr << "launch_wow_suspended failed" << std::endl;
            return EXIT_FAILURE;
        }

        g_exit_wow = false;

        const hadesmem::Process process(proc_info.dwProcessId,
            proc_info.hProcess);

        // ensure process is killed upon exit
        const RaiiProc proc_killer(process.GetId());

        auto const pe_file = find_wow_pe(process);

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

        auto const first_callback = hadesmem::Read<void *>(process,
            tls_callback_directory);

        std::cout << "First TLS callback:     0x" << std::hex
            << reinterpret_cast<std::uintptr_t>(first_callback)
            << std::endl;

        hadesmem::Write<void *>(process, tls_callback_directory, nullptr);

        auto const verify = hadesmem::Read<void *>(process,
            tls_callback_directory);

        if (verify)
        {
            std::cerr << "Failed to zero first TLS callback" << std::endl;
            return EXIT_FAILURE;
        }

        // with the TLS callbacks disabled, our DLL may be safely injected
        const hadesmem::Module unpacker(process, hadesmem::InjectDll(process,
            L"unpacker.dll", hadesmem::InjectFlags::kPathResolution));

        // call init function in DLL
        auto const func = reinterpret_cast<
            void(*)(size_t, DWORD, PVOID, DWORD)>(
            hadesmem::FindProcedure(process, unpacker, "Initialize"));

        hadesmem::Call(process, func, hadesmem::CallConv::kDefault,
            call_tls_initializers_rva, proc_info.dwThreadId,
            pe_file.GetBase(), pe_file.GetSize());

        // restore first TLS callback
        hadesmem::Write<void *>(process, tls_callback_directory,
            first_callback);

        if (!::SetConsoleCtrlHandler(ControlHandler, TRUE))
        {
            std::cerr << "SetConsoleCtrlHandler failed" << std::endl;
            return EXIT_FAILURE;
        }

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
                std::cout << "Received CTRL-C.  Terminating wow..."
                    << std::endl;
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

        if (!::SetConsoleCtrlHandler(ControlHandler, FALSE))
        {
            std::cerr << "SetConsoleCtrlHandler failed" << std::endl;
            return EXIT_FAILURE;
        }

        std::cout << "Wow exited with code:   0x" << std::hex << exit_code
            << std::endl;

        process_log_file(path);
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error:\n" << boost::diagnostic_information(e)
            << std::endl;
        process_log_file(path);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

LONG NTAPI VectoredExceptionHandler(struct _EXCEPTION_POINTERS *exceptionInfo)
{
    auto const return_address = reinterpret_cast<const std::uint8_t *>(
        ::_ReturnAddress());
    auto const base = reinterpret_cast<const std::uint8_t *>(
        ::GetModuleHandle(L"ntdll"));

    g_veh_caller_rva = return_address - base - 6;

    return EXCEPTION_CONTINUE_EXECUTION;
}

// find the RVA of RtlpCallVectoredHandlers within NTDLL so we know where to
// find it once we launch wow
bool FindVEHCallerRVA()
{
    // first, add our own VEH
    auto const veh_handle = ::AddVectoredExceptionHandler(CALL_FIRST,
        &VectoredExceptionHandler);

    // second, raise an exception
    ::RaiseException(1, 0, 0, nullptr);

    // third, remove the VEH
    if (!::RemoveVectoredExceptionHandler(veh_handle))
        return false;

    // at this point, g_veh_caller_rva will have a value.  now check if it is
    // valid
    auto const call_site = reinterpret_cast<std::uint8_t *>(
        GetModuleHandle(L"ntdll")) + g_veh_caller_rva;

    // first byte of indirect call instruction is right?
    return *call_site == 0xFF && *(call_site + 5) == 0;
}

bool launch_wow_suspended(const fs::path &path,
    PROCESS_INFORMATION &proc_info)
{
    // launch wow in a suspended state
    STARTUPINFO start_info {};
    start_info.cb = static_cast<DWORD>(sizeof(start_info));
    memset(&proc_info, 0, sizeof(proc_info));

    return !!::CreateProcessW(path.wstring().c_str(), nullptr, nullptr,
        nullptr, FALSE, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
        nullptr, nullptr, &start_info, &proc_info);
}

hadesmem::PeFile find_wow_pe(const hadesmem::Process &process)
{
    const hadesmem::RegionList region_list(process);

    // find the PE header for wow
    for (auto const &region : region_list)
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
        catch (const hadesmem::Error &)
        {
            continue;
        }

        // wow has tls callbacks
        if (callbacks.empty())
            continue;

        return std::move(pe_file);
    }

    throw std::runtime_error("Could not find wow PE");
}

void *find_tls_callback_directory(const hadesmem::Process &process,
    const hadesmem::PeFile &pe)
{
    try
    {
        const hadesmem::TlsDir tls_dir(process, pe);
        return reinterpret_cast<void *>(tls_dir.GetAddressOfCallBacks());
    }
    catch (const hadesmem::Error &)
    {
        return nullptr;
    }
}

size_t find_call_tls_initializers_rva()
{
    auto const ntdll = ::GetModuleHandle(L"ntdll");

    if (!ntdll)
        return 0;

    const hadesmem::Process process(::GetCurrentProcessId());

    // find "LdrpCallTlsInitializers"
    auto const magic_value = hadesmem::Find(process, L"ntdll.dll",
        L"4C 64 72 70 43 61 6C 6C 54 6C 73 49 "
         "6E 69 74 69 61 6C 69 7A 65 72 73 00",
        hadesmem::PatternFlags::kScanData,
        0);

    if (!magic_value)
        return 0;

    const std::uint8_t *magic_value_ref = nullptr;

    // find recurrences of the byte pattern which dereferences the magic value
    // and check for one that actually is dereferencing it
    for (auto p = hadesmem::Find(process, L"ntdll.dll",
        L"4c 8d 05 ?? ?? ?? 00", 0, 0); p;)
    {
        auto const p_offset = reinterpret_cast<std::uint8_t *>(p) -
            reinterpret_cast<std::uint8_t *>(ntdll);

        auto const expected_offset = static_cast<std::uint32_t>(
            reinterpret_cast<std::uintptr_t>(magic_value) -
            reinterpret_cast<std::uintptr_t>(p)) - 7;

        auto const offset = hadesmem::Read<std::uint32_t>(process,
            reinterpret_cast<unsigned char *>(p) + 3);

        if (offset == expected_offset)
        {
            magic_value_ref = reinterpret_cast<const std::uint8_t *>(p);
            break;
        }

        p = hadesmem::Find(process, L"ntdll.dll", L"4c 8d 05 ?? ?? ?? 00", 0,
            p_offset);
    }

    // not found?  give up
    if (!magic_value_ref)
        return 0;

    const std::uint8_t *func = nullptr;

    // begin searching backwards for a few INT3 (0xCC) instructions to guess at
    // the start of the function
    for (int offset = 0; offset < 0x200; ++offset)
    {
        auto const p = reinterpret_cast<const std::uint8_t *>(magic_value_ref)
            - offset;

        if (*p != 0xCC &&
            *(p - 1) == 0xCC &&
            *(p - 2) == 0xCC &&
            *(p - 3) == 0xCC &&
            *(p - 4) == 0xCC)
        {
            func = p;
            break;
        }
    }

    // function start not found?  give up
    if (!func)
        return 0;

    return static_cast<std::uint64_t>(func -
        reinterpret_cast<const std::uint8_t *>(ntdll));
}

void process_log_file(const fs::path &exe_path)
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

BOOL ControlHandler(DWORD ctrl_type)
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