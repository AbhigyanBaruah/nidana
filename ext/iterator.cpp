#include "iterator.hpp"

#include <pybind11/pybind11.h>

#include <string>

namespace py = pybind11;

ESILFunctionIterator::ESILFunctionIterator(std::size_t count)
    : count_(count) {}

FunctionGraph ESILFunctionIterator::next() {
    if (index_ >= count_) {
        throw py::stop_iteration();
    }

    const auto current_index = index_++;
    const auto function_addr = static_cast<uint64_t>(0x1000 + current_index * 0x100);

    BasicBlock block;
    block.addr = function_addr;
    block.esil_ops = {"nop"};

    FunctionGraph graph;
    graph.name = "dummy_function_" + std::to_string(current_index);
    graph.addr = function_addr;
    graph.blocks = {std::move(block)};
    graph.analysis_incomplete = false;
    return graph;
}
