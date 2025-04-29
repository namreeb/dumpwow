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

#pragma once

#define _SILENCE_EXPERIMENTAL_FILESYSTEM_DEPRECATION_WARNING

#include <Windows.h>
#include <cstdint>
#include <exception>
#include <experimental/filesystem>
#include <hadesmem/region.hpp>
#include <vector>

namespace fs = std::experimental::filesystem;

fs::path get_exe_path();
DWORD round_up(DWORD numToRound, DWORD multiple);

std::string wstring_to_string(const std::wstring& str);

template <typename T>
T rebase(void* new_base, T address)
{
    const hadesmem::Process process(::GetCurrentProcessId());
    const hadesmem::Region region(process,
                                  reinterpret_cast<const void*>(address));

    if (!region.GetAllocBase())
        throw std::runtime_error(
            "No alloc base for given address.  Cannot compute offset.");

    auto const rva = static_cast<std::uint64_t>(
        reinterpret_cast<const std::uint8_t*>(address) -
        reinterpret_cast<const std::uint8_t*>(region.GetAllocBase()));

    return reinterpret_cast<T>(reinterpret_cast<std::uint8_t*>(new_base) + rva);
}
