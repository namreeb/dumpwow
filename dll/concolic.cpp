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

#include "concolic.hpp"

#include <Windows.h>

#include <cstdint>

namespace
{
template <typename T>
T read(PVOID &address)
{
    auto const ret_ptr = reinterpret_cast<T *>(address);

    address = reinterpret_cast<PVOID>(
        reinterpret_cast<std::uintptr_t>(address) + sizeof(T));

    return *ret_ptr;
}
}

bool conclic_begin(PVOID start, ConclicThreadContext &context)
{
    memset(&context, 0, sizeof(context));

    auto current = start;

    // 48:B8 5F8A36EDFA7F0000 -> mov rax,7FFAED368A5F
    if (read<std::uint8_t>(current) != 0x48 ||
        read<std::uint8_t>(current) != 0xB8)
        return false;

    context.rax = read<std::uint64_t>(current);

    do
    {
        auto const op1 = read<std::uint8_t>(current);

        switch (op1)
        {
            // FFE0 -> jmp rax
            case 0xFF:
            {
                return read<std::uint8_t>(current) == 0xE0;
            }
            // E9 98F4FFFF -> jmp -2920
            // E9 C3040000 -> jmp +1219
            case 0xE9:
            {
                auto const offset = read<std::int32_t>(current);
                current = reinterpret_cast<PVOID>(
                    reinterpret_cast<std::uintptr_t>(current) + offset);
                break;
            }
            case 0x48:
            {
                auto const op2 = read<std::uint8_t>(current);
                switch (op2)
                {
                    // 48:05 54AA1D29 -> add rax,291DAA54
                    case 0x05:
                    {
                        auto const operand = read<std::uint32_t>(current);
                        context.rax += operand;
                        break;
                    }
                    // 48:2D F78E5718 -> sub rax,18578EF7
                    case 0x2D:
                    {
                        auto const operand = read<std::uint32_t>(current);
                        context.rax -= operand;
                        break;
                    }
                    // 48:35 04BE0778 -> xor rax,7807BE04
                    case 0x35:
                    {
                        auto const operand = read<std::uint32_t>(current);
                        context.rax ^= operand;
                        break;
                    }

                    default:
                        return false;
                }

                break;
            }

            default:
                return false;
        }
    } while (true);

    return true;
}