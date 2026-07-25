cmake_minimum_required(VERSION 3.15)
project(nidana_core LANGUAGES CXX)

find_package(pybind11 CONFIG REQUIRED)

pybind11_add_module(_core adapter.cpp iterator.cpp)

install(TARGETS _core DESTINATION nidana)
