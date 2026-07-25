#pragma once

#include "types.hpp"

#include <cstddef>

class ESILFunctionIterator {
public:
    explicit ESILFunctionIterator(std::size_t count);

    FunctionGraph next();

private:
    std::size_t count_;
    std::size_t index_ = 0;
};
