#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct BasicBlock {
    uint64_t addr = 0;
    std::vector<std::string> esil_ops;
    std::vector<uint64_t> outgoing_edges;
};

struct FunctionGraph {
    std::string name;
    uint64_t addr = 0;
    std::vector<BasicBlock> blocks;
    bool analysis_incomplete = false;
};
