#include "ids_line_reader.h"
#include <cassert>
#include <cstring>
#include <string>
#include <vector>

int main() {
    using Reader = ids::LineReader;
    Reader reader;
    auto feed = [&](const std::string& bytes) {
        Reader::Result result = Reader::Result::Pending;
        for (unsigned char ch : bytes) result = reader.push(ch);
        return result;
    };
    assert(feed("INFER -1,-1\n") == Reader::Result::Line);
    assert(std::strcmp(reader.line(), "INFER -1,-1") == 0);
    reader.reset();
    assert(feed("INFER -1,") == Reader::Result::Pending);
    assert(feed("0\n") == Reader::Result::Line);
    assert(std::strcmp(reader.line(), "INFER -1,0") == 0);
    reader.reset();
    assert(feed("STA") == Reader::Result::Pending);
    assert(reader.push(0) == Reader::Result::Pending);
    assert(feed("TUS\n") == Reader::Result::InvalidControl);
    assert(reader.bad_byte() == 0 && reader.bad_offset() == 3 && reader.received() == 7);
    assert(reader.prefix()[3] == 0);
    reader.reset();
    assert(reader.push(255) == Reader::Result::Pending);
    assert(feed("STATUS\n") == Reader::Result::InvalidControl);
    assert(reader.bad_byte() == 255 && reader.bad_offset() == 0);
    reader.reset();
    assert(feed("INFER\t0,0\n") == Reader::Result::InvalidControl);
    assert(reader.bad_byte() == 9 && reader.bad_offset() == 5);
    reader.reset();
    assert(feed("\n") == Reader::Result::Line && reader.length() == 0);
    reader.reset();
    assert(feed("STATUS\r\n") == Reader::Result::Line);
    assert(std::strcmp(reader.line(), "STATUS") == 0 && reader.received() == 7);
    reader.reset();
    assert(feed(std::string(Reader::kLimit, 'A') + "\n") == Reader::Result::Line);
    assert(reader.length() == Reader::kLimit && reader.prefix_size() == Reader::kPrefixBytes);
    reader.reset();
    assert(feed(std::string(Reader::kLimit + 1, 'A') + "\n") == Reader::Result::TooLong);
    assert(reader.length() == Reader::kLimit && reader.received() == Reader::kLimit + 1);
    reader.reset();
    assert(feed("INFER 0,0\n") == Reader::Result::Line);
    assert(!reader.invalid());
    reader.reset();
    std::vector<std::string> commands;
    for (const auto& chunk : {std::string("INFE"), std::string("R -1,-1\nINFER -1,0\nSTA"), std::string("TUS\n")}) {
        for (unsigned char byte : chunk) {
            const auto result = reader.push(byte);
            if (result == Reader::Result::Pending) continue;
            assert(result == Reader::Result::Line);
            commands.emplace_back(reader.line());
            reader.reset();
        }
    }
    assert((commands == std::vector<std::string>{"INFER -1,-1", "INFER -1,0", "STATUS"}));
}
