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

#include <hadesmem/region.hpp>
#include <hadesmem/region_list.hpp>
#include <hadesmem/module.hpp>
#include <hadesmem/pelib/pe_file.hpp>
#include <hadesmem/pelib/nt_headers.hpp>
#include <hadesmem/pelib/section.hpp>
#include <hadesmem/pelib/section_list.hpp>

#include <Windows.h>

#include <stdexcept>
#include <filesystem>
#include <fstream>
#include <vector>
#include <cstring>
#include <cassert>

namespace fs = std::experimental::filesystem;

fs::path get_output_path(const fs::path &input_path);
PVOID find_remapped_base(const hadesmem::Process &process, PVOID base);
void repair_binary(const fs::path &path,const hadesmem::Process &process,
    PVOID base, std::vector<std::uint8_t> &pe);

void do_dump(PVOID base, DWORD pe_size)
{
    auto const exe_path = get_exe_path();
    auto const output_path = get_output_path(exe_path);

    const hadesmem::Process process(::GetCurrentProcessId());

    // this will let us work with the writable part of memory
    base = find_remapped_base(process, base);

    // memory_pe will hold the PE header data before any changes were made
    std::vector<std::uint8_t> memory_pe(pe_size);
    repair_binary(exe_path, process, base, memory_pe);

    std::ofstream out(output_path, std::ios::binary);

    if (!out)
        throw std::runtime_error("Failed to open unpacked exe for writing");

    // first, write PE header
    const hadesmem::PeFile pe_file(process, base, hadesmem::PeFileType::kImage,
        pe_size);
    const hadesmem::NtHeaders nt_header(process, pe_file);

    out.write(reinterpret_cast<const char *>(base),
        static_cast<std::streamsize>(nt_header.GetSizeOfHeaders()));

    // second, write sections
    const hadesmem::SectionList section_list(process, pe_file);
    for (auto const &section : section_list)
    {
        auto const section_base = reinterpret_cast<const char *>(base) +
            section.GetVirtualAddress();
        out.write(section_base, section.GetSizeOfRawData());
    }

    out.close();
}

fs::path get_output_path(const fs::path &input_path)
{
    auto const dir = input_path.parent_path();
    auto const extension = input_path.extension();
    auto const stem = input_path.stem();

    return dir / (stem.string() + "_unpacked" + extension.string());
}

PVOID find_remapped_base(const hadesmem::Process &process, PVOID base)
{
    const hadesmem::RegionList region_list(process);

    const hadesmem::PeFile pe_file(process, base, hadesmem::PeFileType::kImage,
        0);

    // find the PE header in the remapped location
    for (auto const &region : region_list)
    {
        if (region.GetState() == MEM_FREE)
            continue;

        if (region.GetAllocBase() != region.GetBase())
            continue;

        if (region.GetSize() != pe_file.GetSize())
            continue;

        if (memcmp(base, region.GetBase(), region.GetSize()))
            continue;

        //gLog << "Remapped base:\t0x" << std::hex << region.GetBase()
        //    << " protection: 0x" << region.GetProtect()
        //    << " size: 0x" << region.GetSize() << std::endl;

        return region.GetBase();
    }

    throw std::runtime_error(
        "find_remapped_base failed to find remapped location");
}

// modified from https://stackoverflow.com/a/9194117
DWORD round_up(DWORD numToRound, DWORD multiple)
{
    assert(multiple > 0);
    return ((numToRound + multiple - 1) / multiple) * multiple;
}

void repair_binary(const fs::path &path, const hadesmem::Process &process,
    PVOID base, std::vector<std::uint8_t> &pe)
{
    // copy the current PE header into the vector to save in case we need it
    memcpy(&pe[0], base, pe.size());

    const hadesmem::PeFile clobbered_pe(process, &pe[0],
        hadesmem::PeFileType::kData, static_cast<DWORD>(pe.size()));

    // read PE header from EXE file
    auto const pe_exe = read_pe_header_from_exe(path,
        static_cast<DWORD>(pe.size()));

    // install EXE PE header into memory
    memcpy(base, &pe_exe[0], pe_exe.size());

    // use the PE header read from the file
    const hadesmem::PeFile pe_file(process, base,
        hadesmem::PeFileType::kImage, static_cast<DWORD>(pe.size()));

    hadesmem::NtHeaders nt_header(process, pe_file);
    hadesmem::SectionList section_list(process, pe_file);
    auto raw_data_pointer = nt_header.GetSizeOfHeaders();

    for (auto &section : section_list)
    {
        auto const virtual_size = round_up(section.GetVirtualSize(),
            nt_header.GetSectionAlignment());

        auto const section_base = reinterpret_cast<PVOID>(
            reinterpret_cast<std::uint8_t *>(base) +
            section.GetVirtualAddress());

        // for some reason the wow binary has section with unusual sizes.  that's
        // fine, but lets clean it up by enforcing section alignment from the pe
        section.SetVirtualSize(virtual_size);

        // the unpacking may have enlarged the section.  increase the raw size
        // to match the virtual size, and then remove as much zero-fill from
        // the end as we can.
        for (auto remain = virtual_size; remain != 0; --remain)
        {
            auto const curr = reinterpret_cast<const std::uint8_t *>(
                section_base) + remain - 1;

            // we cannot shrink beyond this point
            if (*curr != 0x00)
            {
                auto const old_size = section.GetSizeOfRawData();
                section.SetSizeOfRawData(round_up(remain,
                    nt_header.GetFileAlignment()));
                break;
            }
        }

        // with sections changing size, we should also update the raw location
        section.SetPointerToRawData(raw_data_pointer);
        raw_data_pointer += section.GetSizeOfRawData();

        section.UpdateWrite();
    }

    std::uint8_t buff[5];

    auto const entry_point = reinterpret_cast<const char *>(base) +
        nt_header.GetAddressOfEntryPoint();

    memcpy(buff, entry_point, sizeof(buff));

    if (buff[0] == 0xE9)
    {
        auto const new_ep_offset = *reinterpret_cast<const std::int32_t *>(
            entry_point + 1);

        auto const new_ep = reinterpret_cast<const void *>(entry_point +
            new_ep_offset + 5);

        gLog << "True entry point:\t0x" << std::hex << new_ep << std::endl;
    }
}
