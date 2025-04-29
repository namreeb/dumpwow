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

#include "relocations.hpp"

#include "misc.hpp"

void apply_relocations(PVOID image_base)
{
    const auto module = PIMAGE_DOS_HEADER(image_base);
    auto headers =
        PIMAGE_NT_HEADERS64(reinterpret_cast<char*>(module) + module->e_lfanew);
    auto relocation = PIMAGE_BASE_RELOCATION(
        reinterpret_cast<char*>(module) +
        headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
            .VirtualAddress);

    while (relocation->SizeOfBlock && relocation->VirtualAddress)
    {
        const auto block_relocation_count =
            (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
            sizeof(WORD);
        const auto block_entries = PWORD(reinterpret_cast<char*>(relocation) +
                                         sizeof(IMAGE_BASE_RELOCATION));

        for (size_t i = 0; i < block_relocation_count; i++)
        {
            switch (block_entries[i] >> 12)
            {
                case IMAGE_REL_BASED_DIR64:
                {
                    const auto p = reinterpret_cast<uintptr_t*>(
                        reinterpret_cast<char*>(module) +
                        relocation->VirtualAddress + (block_entries[i] & 0xFFF));

                    *p = rebase(reinterpret_cast<PVOID>(
                                    headers->OptionalHeader.ImageBase),
                                *p);
                }
                break;
                case IMAGE_REL_BASED_ABSOLUTE:
                case IMAGE_REL_BASED_HIGHLOW:
                case IMAGE_REL_BASED_HIGH:
                case IMAGE_REL_BASED_LOW:
                default:
                {
                    // No need to fix absolute relocation it's just a dummy for
                    // alignment. Other relocation types are not used in 64bit
                    // binaries.
                }
                break;
            }
        }

        relocation = PIMAGE_BASE_RELOCATION(reinterpret_cast<char*>(relocation) +
                                            relocation->SizeOfBlock);
    }
}
