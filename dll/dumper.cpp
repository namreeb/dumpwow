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

#include "imports.hpp"
#include "log.hpp"
#include "misc.hpp"
#include "relocations.hpp"

#include <Windows.h>
#include <cassert>
#include <cstring>
#include <experimental/filesystem>
#include <fstream>
#include <hadesmem/module.hpp>
#include <hadesmem/pelib/export_dir.hpp>
#include <hadesmem/pelib/nt_headers.hpp>
#include <hadesmem/pelib/pe_file.hpp>
#include <hadesmem/pelib/section.hpp>
#include <hadesmem/pelib/section_list.hpp>
#include <hadesmem/pelib/tls_dir.hpp>
#include <hadesmem/region.hpp>
#include <hadesmem/region_list.hpp>
#include <stdexcept>
#include <vector>

namespace fs = std::experimental::filesystem;

fs::path get_output_path(const fs::path& input_path);
PVOID find_remapped_base(const hadesmem::Process& process, PVOID base);
void repair_binary_in_memory(const fs::path& path,
                             const hadesmem::Process& process, PVOID base,
                             PVOID readonly_base, DWORD pe_size,
                             std::vector<std::uint8_t>& import_data);

void do_dump(PVOID base, DWORD pe_size, PVOID init_func)
{
    auto const readonly_base = base;
    auto const exe_path = get_exe_path();
    auto const output_path = get_output_path(exe_path);
    const size_t init_func_rva =
        reinterpret_cast<char*>(init_func) - reinterpret_cast<char*>(base);

    const hadesmem::Process process(::GetCurrentProcessId());

    // this will let us work with the writable part of memory
    base = find_remapped_base(process, base);

    std::vector<std::uint8_t> import_data;
    repair_binary_in_memory(exe_path, process, base, readonly_base, pe_size,
                            import_data);

    std::ofstream out(output_path, std::ios::binary);

    if (!out)
        throw std::runtime_error("Failed to open unpacked exe for writing");

    // first, write PE header
    const hadesmem::PeFile pe_file(process, base, hadesmem::PeFileType::kImage,
                                   pe_size);
    const hadesmem::NtHeaders nt_header(process, pe_file);

    out.write(reinterpret_cast<const char*>(base),
              static_cast<std::streamsize>(nt_header.GetSizeOfHeaders()));

    // second, write sections
    const hadesmem::SectionList section_list(process, pe_file);
    for (auto const& section : section_list)
    {
        // TODO: better logic to identify our section here
        if (section.GetName() == ".wowim")
            continue;

        auto const section_base =
            reinterpret_cast<const char*>(base) + section.GetVirtualAddress();
        out.write(section_base, section.GetSizeOfRawData());
    }

    // third, write the new section created for imports
    if (!import_data.empty())
        out.write(reinterpret_cast<const char*>(&import_data[0]),
                  import_data.size());

    out.close();
}

fs::path get_output_path(const fs::path& input_path)
{
    auto const dir = input_path.parent_path();
    auto const extension = input_path.extension();
    auto const stem = input_path.stem();

    return dir / (stem.string() + "_unpacked" + extension.string());
}

PVOID find_remapped_base(const hadesmem::Process& process, PVOID base)
{
    const hadesmem::RegionList region_list(process);

    const hadesmem::PeFile pe_file(process, base, hadesmem::PeFileType::kImage,
                                   0);

    // find the PE header in the remapped location
    for (auto const& region : region_list)
    {
        if (region.GetState() == MEM_FREE)
            continue;

        if (region.GetAllocBase() != region.GetBase())
            continue;

        if (region.GetSize() != pe_file.GetSize())
            continue;

        if (memcmp(base, region.GetBase(), region.GetSize()))
            continue;

#ifdef _DEBUG
        gLog << "\nRemapped base:\t\t0x" << std::hex << region.GetBase()
             << " protection: 0x" << region.GetProtect() << " size: 0x"
             << region.GetSize() << std::endl;
#endif

        return region.GetBase();
    }

    throw std::runtime_error(
        "find_remapped_base failed to find remapped location");
}

std::vector<std::uint8_t> read_from_exe(const fs::path& exe, size_t offset,
                                        size_t size)
{
    std::vector<std::uint8_t> result(size);

    std::ifstream in(exe, std::ios::binary);

    if (!in)
        throw std::runtime_error("Failed to read PE header from binary");

    in.seekg(offset);
    in.read(reinterpret_cast<char*>(&result[0]),
            static_cast<std::streamsize>(result.size()));
    in.close();

    return result;
}

void repair_binary_in_memory(const fs::path& path,
                             const hadesmem::Process& process, PVOID base,
                             PVOID readonly_base, DWORD pe_size,
                             std::vector<std::uint8_t>& import_data)
{
    // read PE header and first chunk of data from EXE file, everything up to the
    // entry point
    auto const pe_exe = read_from_exe(path, 0, pe_size);

    // install EXE PE header into memory
    ::memcpy(base, &pe_exe[0], pe_exe.size());

    // use the PE header read from the file
    const hadesmem::PeFile pe_file(process, base, hadesmem::PeFileType::kImage,
                                   pe_size);

    const hadesmem::NtHeaders nt_header(process, pe_file);
    hadesmem::SectionList section_list(process, pe_file);
    auto raw_data_pointer = nt_header.GetSizeOfHeaders();

    // used later
    PVOID rdata = nullptr;

    DWORD text_raw_base = 0;
    DWORD text_base = 0;

    for (auto& section : section_list)
    {
        auto const virtual_size =
            round_up(section.GetVirtualSize(), nt_header.GetSectionAlignment());

        auto const section_base = reinterpret_cast<PVOID>(
            reinterpret_cast<std::uint8_t*>(base) + section.GetVirtualAddress());

        if (section.GetName() == ".rdata")
            rdata = section_base;
        else if (section.GetName() == ".text")
        {
            text_raw_base = section.GetPointerToRawData();
            text_base = section.GetVirtualAddress();
        }

        // for some reason the wow binary has section with unusual sizes.  that's
        // fine, but lets clean it up by enforcing section alignment from the pe
        section.SetVirtualSize(virtual_size);

        // the unpacking may have enlarged the section.  increase the raw size
        // to match the virtual size, and then remove as much zero-fill from
        // the end as we can.
        for (auto remain = virtual_size; remain != 0; --remain)
        {
            auto const curr =
                reinterpret_cast<const std::uint8_t*>(section_base) + remain - 1;

            // we cannot shrink beyond this point
            if (*curr != 0x00)
            {
                auto const old_size = section.GetSizeOfRawData();
                section.SetSizeOfRawData(
                    round_up(remain, nt_header.GetFileAlignment()));
                break;
            }
        }

        // with sections changing size, we should also update the raw location
        section.SetPointerToRawData(raw_data_pointer);
        raw_data_pointer += section.GetSizeOfRawData();

        section.UpdateWrite();
    }

    if (!text_base)
        throw std::runtime_error("Could not find .text segment");

    // recover from the .exe all data from the .text segment before the entry
    // point
    auto const exe_data_size = nt_header.GetAddressOfEntryPoint() - text_base;
    auto const exe_data = read_from_exe(path, text_raw_base, exe_data_size);

    ::memcpy(
        reinterpret_cast<PVOID>(reinterpret_cast<uintptr_t>(base) + text_base),
        &exe_data[0], exe_data.size());

    auto const entry_point =
        reinterpret_cast<uintptr_t>(base) + nt_header.GetAddressOfEntryPoint();

    if (*reinterpret_cast<const std::uint8_t*>(entry_point) != 0xE9)
        throw std::runtime_error("Entry point should start with a JMP (0xE9)");

    auto const new_ep_offset =
        *reinterpret_cast<const std::int32_t*>(entry_point + 1);

    auto const new_ep =
        reinterpret_cast<const void*>(entry_point + new_ep_offset + 5);

    gLog << "True entry point:\t0x" << std::hex << new_ep << std::endl;

    // the second TLS callback will generate simple pointer decryption
    // trampolines to mask calls to imported DLL functions.  to resolve
    // these calls we will perform a concolic execution of the trampolines
    // and see what function pointer results.
    if (rdata)
        rebuild_imports(process, pe_file, rdata, readonly_base, import_data);
    else
        gLog << "Did not find .rdata section.  Skipping import resolution."
             << std::endl;

    // tls callbacks will point to the original (now unwritable) region of
    // memory.  the addresses should be rebased to be consistent with the base
    // address in the PE header.  we initialize this before applying
    // relocations on purpose!
    const hadesmem::TlsDir tls_dir(process, pe_file);

    // apply relocations to the new base address
    apply_relocations(base);

    auto p_current_callback =
        rebase(base, reinterpret_cast<PVOID*>(tls_dir.GetAddressOfCallBacks()));

    auto const image_base = reinterpret_cast<PVOID>(nt_header.GetImageBase());

    while (*p_current_callback)
    {
        try
        {
            *p_current_callback = rebase(image_base, *p_current_callback);
        }
        catch (const std::runtime_error&)
        {
            // rebase failed.  probably because it already was rebased by
            // applying relocations.  ignored.
        }

        ++p_current_callback;
    }
}
