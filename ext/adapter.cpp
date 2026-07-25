#include <pybind11/pybind11.h>

namespace py = pybind11;

PYBIND11_MODULE(_core, module) {
    module.def("hello_nidana", []() { return "Bridge Active"; });
}
