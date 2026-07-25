cmake_minimum_required(VERSION 3.15)
project(nidana_core LANGUAGES CXX)

find_package(pybind11 CONFIG REQUIRED)

include(FetchContent)

FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(nlohmann_json)

pybind11_add_module(_core adapter.cpp iterator.cpp)
target_link_libraries(_core PRIVATE nlohmann_json::nlohmann_json)

install(TARGETS _core DESTINATION nidana)
