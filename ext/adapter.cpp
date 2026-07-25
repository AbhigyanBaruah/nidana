#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "iterator.hpp"
#include "types.hpp"

namespace py = pybind11;

PYBIND11_MODULE(_core, module) {
    module.def("hello_nidana", []() { return "Bridge Active"; });

    py::class_<BasicBlock>(module, "BasicBlock")
        .def(py::init<>())
        .def_readwrite("addr", &BasicBlock::addr)
        .def_readwrite("esil_ops", &BasicBlock::esil_ops)
        .def_readwrite("outgoing_edges", &BasicBlock::outgoing_edges);

    py::class_<FunctionGraph>(module, "FunctionGraph")
        .def(py::init<>())
        .def_readwrite("name", &FunctionGraph::name)
        .def_readwrite("addr", &FunctionGraph::addr)
        .def_readwrite("blocks", &FunctionGraph::blocks)
        .def_readwrite("analysis_incomplete", &FunctionGraph::analysis_incomplete);

    py::class_<ESILFunctionIterator>(module, "ESILFunctionIterator")
        .def(
            py::init<std::string, std::string>(),
            py::arg("binary_path"),
            py::arg("r2_executable_path"))
        .def("__iter__", [](ESILFunctionIterator &self) -> ESILFunctionIterator & {
            return self;
        }, py::return_value_policy::reference_internal)
        .def("__next__", &ESILFunctionIterator::next);
}
