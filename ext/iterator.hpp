#pragma once

#include "types.hpp"

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

class ESILFunctionIterator {
public:
    ESILFunctionIterator(std::string binary_path, std::string r2_executable_path);
    ~ESILFunctionIterator();

    ESILFunctionIterator(const ESILFunctionIterator&) = delete;
    ESILFunctionIterator& operator=(const ESILFunctionIterator&) = delete;

    FunctionGraph next();

private:
    struct R2Session;

    std::string binary_path_;
    std::string r2_executable_path_;
    std::unique_ptr<R2Session> session_;
    std::vector<uint64_t> function_addresses_;
    std::unordered_map<uint64_t, std::string> function_names_;
};
