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

#pragma once

#define _SILENCE_EXPERIMENTAL_FILESYSTEM_DEPRECATION_WARNING

#include <Windows.h>

#include <experimental/filesystem>
#include <vector>
#include <cstdint>

#include <hadesmem/region.hpp>

namespace fs = std::experimental::filesystem;

fs::path get_exe_path();
std::vector<std::uint8_t> read_pe_header_from_exe(const fs::path &exe, DWORD pe_size);
DWORD round_up(DWORD numToRound, DWORD multiple);

std::string wstring_to_string(const std::wstring& str);

template <typename T>
T rebase(void* new_base, T address)
{
    const hadesmem::Process process(::GetCurrentProcessId());
    const hadesmem::Region region(process, reinterpret_cast<const void*>(
        address));

    auto const rva = static_cast<std::uint64_t>(
        reinterpret_cast<const char*>(address) -
        reinterpret_cast<const char*>(region.GetAllocBase()));

    return reinterpret_cast<T>(reinterpret_cast<char*>(new_base) + rva);
}
