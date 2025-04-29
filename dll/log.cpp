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

#include "log.hpp"

#include "misc.hpp"

#include <fstream>
#include <functional>
#include <stdexcept>
#include <string>

int LogStreamBuffer::sync()
{
    if (!str().empty())
    {
        _callback(str());
        str("");
    }

    return std::stringbuf::sync();
}
Log::Log(std::function<void(const std::string&)> callback)
    : _buffer(callback), std::ostream(&_buffer)
{
}

std::ostream& operator<<(std::ostream& _Ostr, const std::wstring& _Str)
{
    return _Ostr << wstring_to_string(_Str);
}

Log gLog(
    [](const std::string& buff)
    {
        auto const exe_path = get_exe_path();
        auto const parent = exe_path.parent_path();
        auto const log_path = parent / "log.txt";

        std::ofstream out(log_path, std::ios::app);

        if (!out)
            throw std::runtime_error("Failed to open log file");

        out << buff;
        out.close();
    });
