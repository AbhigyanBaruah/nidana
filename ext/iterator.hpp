#pragma once

#include "types.hpp"

#include <string>
#include <unordered_map>
#include <vector>

class ESILFunctionIterator {
public:
    ESILFunctionIterator(std::string binary_path, std::string r2_executable_path);

    FunctionGraph next();

private:
    std::string binary_path_;
    std::string r2_executable_path_;
    std::vector<uint64_t> function_addresses_;
    std::unordered_map<uint64_t, std::string> function_names_;
};
