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

//#define DEBUG_CONCOLIC

#ifdef DEBUG_CONCOLIC
#include "log.hpp"
#include <sstream>
#endif

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
#ifdef DEBUG_CONCOLIC
    auto instruction_ea = current;
#endif

    // 48:B8 5F8A36EDFA7F0000 -> mov rax,7FFAED368A5F
    if (read<std::uint8_t>(current) != 0x48 ||
        read<std::uint8_t>(current) != 0xB8)
    {
#ifdef DEBUG_CONCOLIC
        gLog << "ea: 0x" << instruction_ea << " initial mov not found"
            << std::endl;
#endif
        return false;
    }

    context.rax = read<std::uint64_t>(current);
#ifdef DEBUG_CONCOLIC
    gLog << "ea: 0x" << instruction_ea << " initial mov rax, 0x" << std::hex
        << context.rax << std::endl;
#endif

    do
    {
#ifdef DEBUG_CONCOLIC
        instruction_ea = current;
#endif
        auto const op1 = read<std::uint8_t>(current);

        switch (op1)
        {
            // FFE0 -> jmp rax
            case 0xFF:
            {
                auto const result = read<std::uint8_t>(current) == 0xE0;
#ifdef DEBUG_CONCOLIC
                gLog << "returning " << (result ? "true" : "false")
                    << ". rax: 0x" << std::hex << context.rax << std::dec
                    << "\n" << std::endl;
#endif
                return result;
            }
            // E9 98F4FFFF -> jmp -2920
            // E9 C3040000 -> jmp +1219
            case 0xE9:
            {
                auto const offset = read<std::int32_t>(current);
                current = reinterpret_cast<PVOID>(
                    reinterpret_cast<std::uintptr_t>(current) + offset);
#ifdef DEBUG_CONCOLIC
                gLog << "ea: 0x" << instruction_ea << " jump to 0x" << current
                    << std::endl;
#endif
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
                        auto const operand = read<std::int32_t>(current);
#ifdef DEBUG_CONCOLIC
                        gLog << "ea: 0x" << instruction_ea << " add "
                            << std::hex << operand << " from " << context.rax
                            << " to " << context.rax + operand << std::dec
                            << std::endl;
#endif
                        context.rax += operand;
                        break;
                    }
                    // 48:2D F78E5718 -> sub rax,18578EF7
                    case 0x2D:
                    {
                        auto const operand = read<std::int32_t>(current);
#ifdef DEBUG_CONCOLIC
                        gLog << "ea: 0x" << instruction_ea << " sub "
                            << std::hex << operand << " from " << context.rax
                            << " to " << context.rax - operand << std::dec
                            << std::endl;
#endif
                        context.rax -= operand;
                        break;
                    }
                    // 48:35 04BE0778 -> xor rax,7807BE04
                    case 0x35:
                    {
                        auto const operand = static_cast<std::int64_t>(
                            read<std::int32_t>(current));
#ifdef DEBUG_CONCOLIC
                        gLog << "ea: 0x" << instruction_ea << " xor "
                            << std::hex << operand << " from " << context.rax
                            << " to " << (context.rax ^ operand) << std::dec
                            << std::endl;
#endif
                        context.rax ^= operand;
                        break;
                    }

                    default:
                    {
#ifdef DEBUG_CONCOLIC
                        gLog << "ea: 0x" << instruction_ea
                            << " 0x48 op2 unrecognized: " << std::hex << op1
                            << std::dec << std::endl;
#endif
                        return false;
                    }
                }

                break;
            }
            case 0x49:
            {
                auto const op2 = read<std::uint8_t>(current);
                switch (op2)
                {
                    // 49 0f af c2 -> imul rax, r10
                    case 0x0F:
                    {
                        auto const op3 = read<std::uint8_t>(current);

                        if (op3 != 0xAF)
                        {
#ifdef DEBUG_CONCOLIC
                            gLog << "ea: 0x" << instruction_ea
                                << " imul op3 unrecognized: " << std::hex
                                << static_cast<int>(op3) << std::dec
                                << std::endl;
#endif
                            return false;
                        }

                        auto const op4 = read<std::uint8_t>(current);

                        if (op4 == 0xC2)
                        {
                            auto const signed_rax = static_cast<std::int64_t>(
                                context.rax);
                            auto const signed_r10 = static_cast<std::int64_t>(
                                context.r10);

#ifdef DEBUG_CONCOLIC
                            gLog << "ea: 0x" << instruction_ea
                                << " imul rax, r10 (0x" << std::hex
                                << context.rax << " * 0x" << context.r10
                                << " = 0x" << (signed_rax*signed_r10) << "), ("
                                << std::dec << signed_rax << " * "
                                << signed_r10 << " = "
                                << (signed_rax*signed_r10) << ")" << std::endl;
#endif

                            context.rax = signed_rax * signed_r10;
                        }
                        else
                        {
#ifdef DEBUG_CONCOLIC
                            gLog << "ea: 0x" << instruction_ea
                                << " imul op4 unrecognized: " << std::hex
                                << static_cast<int>(op4) << std::dec
                                << std::endl;
#endif
                            return false;
                        }

                        break;
                    }
                    // 49 ba bb 40 7d ba f7 07 31 3c -> mov r10, 3C3107F7BA7D40BB
                    case 0xBA:
                    {
                        auto const operand = read<std::uint64_t>(current);
#ifdef DEBUG_CONCOLIC
                        gLog << "ea: 0x" << instruction_ea << " r10 set to 0x"
                            << std::hex << operand << std::dec << std::endl;
#endif

                        context.r10 = operand;
                        break;
                    }
                    default:
                    {
#ifdef DEBUG_CONCOLIC
                        gLog << "ea: 0x" << instruction_ea
                            << " 0x49 op2 unrecognized: " << std::hex << op1
                            << std::dec << std::endl;
#endif
                        return false;
                    }
                }
                break;
            }

            default:
            {
#ifdef DEBUG_CONCOLIC
                gLog << "ea: 0x" << instruction_ea << " op1 unrecognized: "
                    << std::hex << op1 << std::dec << std::endl;
#endif
                return false;
            }
        }
    } while (true);

    return true;
}