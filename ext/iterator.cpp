#include "iterator.hpp"

#include <nlohmann/json.hpp>
#include <pybind11/pybind11.h>

#include <cctype>
#include <cstdio>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace py = pybind11;
using json = nlohmann::json;

namespace {

// Safely quotes paths and parameters for shell execution
std::string shell_quote(const std::string& value) {
#ifdef _WIN32
    std::string quoted = "\"";
    for (char character : value) {
        if (character == '"') {
            quoted += "\\\"";
        } else {
            quoted += character;
        }
    }
    quoted += "\"";
    return quoted;
#else
    std::string quoted = "'";
    for (char character : value) {
        if (character == '\'') {
            quoted += "'\\''";
        } else {
            quoted += character;
        }
    }
    quoted += "'";
    return quoted;
#endif
}

// Constructs cross-platform shell commands compatible with popen/_popen
std::string make_command(const std::string& raw_cmd) {
#ifdef _WIN32
    // Windows cmd.exe strips outermost quotes when multiple quoted arguments exist
    return "\"" + raw_cmd + "\"";
#else
    return raw_cmd;
#endif
}

// Executes a shell command and captures standard output
std::string run_command(const std::string& command) {
#ifdef _WIN32
    FILE* pipe = _popen(command.c_str(), "r");
#else
    FILE* pipe = popen(command.c_str(), "r");
#endif

    if (pipe == nullptr) {
        throw std::runtime_error("Failed to start radare2 subprocess");
    }

    std::string output;
    char buffer[4096];
    while (std::fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }

#ifdef _WIN32
    const int exit_code = _pclose(pipe);
#else
    const int exit_code = pclose(pipe);
#endif

    if (exit_code != 0) {
        throw std::runtime_error(
            "radare2 subprocess failed with exit code " + std::to_string(exit_code));
    }

    return output;
}

// Flexibly extracts an address from JSON field variations
bool get_address(const json& object, uint64_t& address) {
    for (const char* key : {"offset", "addr", "address", "jump", "target", "to"}) {
        if (!object.contains(key) || object[key].is_null()) {
            continue;
        }

        const json& value = object[key];
        if (value.is_number_unsigned()) {
            address = value.get<uint64_t>();
            return true;
        }
        if (value.is_number_integer() && value.get<int64_t>() >= 0) {
            address = static_cast<uint64_t>(value.get<int64_t>());
            return true;
        }
        if (value.is_string()) {
            try {
                address = std::stoull(value.get<std::string>(), nullptr, 0);
                return true;
            } catch (const std::exception&) {
                // Ignore parse failures and continue searching
            }
        }
    }
    return false;
}

void add_edge(const json& value, std::vector<uint64_t>& edges) {
    uint64_t address = 0;
    if (value.is_object()) {
        if (get_address(value, address)) {
            edges.push_back(address);
        }
    } else if (value.is_number_unsigned()) {
        edges.push_back(value.get<uint64_t>());
    } else if (value.is_string()) {
        try {
            edges.push_back(std::stoull(value.get<std::string>(), nullptr, 0));
        } catch (const std::exception&) {
            // Ignore invalid string edge conversions
        }
    }
}

void parse_edges(const json& block, std::vector<uint64_t>& edges) {
    for (const char* key : {"jump", "fail", "true", "false"}) {
        if (block.contains(key) && !block[key].is_null()) {
            add_edge(block[key], edges);
        }
    }
    for (const char* key : {"edges", "outgoing_edges"}) {
        if (block.contains(key) && block[key].is_array()) {
            for (const auto& edge : block[key]) {
                add_edge(edge, edges);
            }
        }
    }
}

void parse_esil(const json& block, std::vector<std::string>& esil_ops) {
    if (block.contains("esil") && block["esil"].is_string()) {
        esil_ops.push_back(block["esil"].get<std::string>());
    }
    if (!block.contains("ops") || !block["ops"].is_array()) {
        return;
    }
    for (const auto& operation : block["ops"]) {
        if (operation.is_object() && operation.contains("esil") &&
            operation["esil"].is_string()) {
            esil_ops.push_back(operation["esil"].get<std::string>());
        } else if (operation.is_string()) {
            esil_ops.push_back(operation.get<std::string>());
        }
    }
}

}  // namespace

ESILFunctionIterator::ESILFunctionIterator(
    std::string binary_path,
    std::string r2_executable_path)
    : binary_path_(std::move(binary_path)),
      r2_executable_path_(std::move(r2_executable_path)) {

    const std::string raw_cmd = shell_quote(r2_executable_path_) + " -Aqc aflj " + shell_quote(binary_path_);
    const std::string cmd = make_command(raw_cmd);

    const json functions = json::parse(run_command(cmd));
    if (!functions.is_array()) {
        throw std::runtime_error("radare2 aflj output was not a JSON array");
    }

    for (const auto& function : functions) {
        uint64_t address = 0;
        if (!function.is_object() || !get_address(function, address)) {
            continue;
        }
        function_addresses_.push_back(address);
        if (function.contains("name") && function["name"].is_string()) {
            function_names_[address] = function["name"].get<std::string>();
        }
    }
}

FunctionGraph ESILFunctionIterator::next() {
    if (function_addresses_.empty()) {
        throw py::stop_iteration();
    }

    const uint64_t function_addr = function_addresses_.back();
    function_addresses_.pop_back();

    const std::string address_string = std::to_string(function_addr);

    // Analyze function ('af') before dumping graph ('agj') so r2 resolves local control flow
    const std::string raw_cmd = shell_quote(r2_executable_path_) +
                                " -qc \"af @ " + address_string +
                                "; agj @ " + address_string + "\" " +
                                shell_quote(binary_path_);
    const std::string cmd = make_command(raw_cmd);

    const std::string output = run_command(cmd);

    // Safety net: handle empty or whitespace-only radare2 output gracefully
    if (output.empty() || output.find_first_not_of(" \t\r\n") == std::string::npos) {
        FunctionGraph graph_result;
        graph_result.name = function_names_[function_addr];
        graph_result.addr = function_addr;
        graph_result.analysis_incomplete = true;
        return graph_result;
    }

    const json graph_output = json::parse(output);
    const json* graph = &graph_output;

    if (graph_output.is_array()) {
        if (graph_output.empty()) {
            FunctionGraph graph_result;
            graph_result.name = function_names_[function_addr];
            graph_result.addr = function_addr;
            graph_result.analysis_incomplete = true;
            return graph_result;
        }
        graph = &graph_output.front();
    }

    FunctionGraph graph_result;
    graph_result.name = function_names_[function_addr];
    graph_result.addr = function_addr;

    if (graph->is_object()) {
        if (graph->contains("name") && (*graph)["name"].is_string()) {
            graph_result.name = (*graph)["name"].get<std::string>();
        }
        if (graph->contains("blocks") && (*graph)["blocks"].is_array()) {
            for (const auto& block_json : (*graph)["blocks"]) {
                if (graph_result.blocks.size() >= 1000) {
                    graph_result.analysis_incomplete = true;
                    break;
                }
                if (!block_json.is_object()) {
                    continue;
                }
                BasicBlock block;
                if (!get_address(block_json, block.addr)) {
                    continue;
                }
                parse_esil(block_json, block.esil_ops);
                parse_edges(block_json, block.outgoing_edges);
                graph_result.blocks.push_back(std::move(block));
            }
            if ((*graph)["blocks"].size() > 1000) {
                graph_result.analysis_incomplete = true;
            }
        }
    }
    return graph_result;
}