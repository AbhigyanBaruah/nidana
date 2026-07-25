#include "iterator.hpp"

#include <nlohmann/json.hpp>
#include <pybind11/pybind11.h>

#include <cerrno>
#include <cstring>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

extern char** environ;
#endif

namespace py = pybind11;
using json = nlohmann::json;

struct ESILFunctionIterator::R2Session {
#ifdef _WIN32
    HANDLE process = nullptr;
    HANDLE stdin_write = nullptr;
    HANDLE stdout_read = nullptr;

    static std::string quote_windows_argument(const std::string& value) {
        std::string quoted = "\"";
        std::size_t backslashes = 0;

        for (char character : value) {
            if (character == '\\') {
                ++backslashes;
                continue;
            }

            if (character == '"') {
                quoted.append(backslashes * 2 + 1, '\\');
                quoted += '"';
            } else {
                quoted.append(backslashes, '\\');
                quoted += character;
            }
            backslashes = 0;
        }

        quoted.append(backslashes * 2, '\\');
        quoted += '"';
        return quoted;
    }

    R2Session(
        const std::string& executable,
        const std::string& binary_path) {
        SECURITY_ATTRIBUTES security_attributes{};
        security_attributes.nLength = sizeof(security_attributes);
        security_attributes.bInheritHandle = TRUE;

        HANDLE child_stdin_read = nullptr;
        HANDLE child_stdout_write = nullptr;
        HANDLE child_stderr = nullptr;
        HANDLE stdin_write_local = nullptr;
        HANDLE stdout_read_local = nullptr;

        if (!CreatePipe(
                &child_stdin_read,
                &stdin_write_local,
                &security_attributes,
                0
            )) {
            throw std::runtime_error("failed to create radare2 pipes");
        }
        if (!CreatePipe(
                &stdout_read_local,
                &child_stdout_write,
                &security_attributes,
                0
            )) {
            CloseHandle(child_stdin_read);
            CloseHandle(stdin_write_local);
            throw std::runtime_error("failed to create radare2 pipes");
        }

        SetHandleInformation(
            stdin_write_local,
            HANDLE_FLAG_INHERIT,
            0
        );

        child_stderr = CreateFileA(
            "NUL",
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &security_attributes,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );
        if (child_stderr == INVALID_HANDLE_VALUE) {
            CloseHandle(child_stdin_read);
            CloseHandle(child_stdout_write);
            CloseHandle(stdin_write_local);
            CloseHandle(stdout_read_local);
            throw std::runtime_error("failed to open radare2 stderr sink");
        }
        SetHandleInformation(
            stdout_read_local,
            HANDLE_FLAG_INHERIT,
            0
        );

        std::string command_line =
            quote_windows_argument(executable) +
            " -q0 -A " +
            quote_windows_argument(binary_path);

        STARTUPINFOA startup_info{};
        startup_info.cb = sizeof(startup_info);
        startup_info.dwFlags = STARTF_USESTDHANDLES;
        startup_info.hStdInput = child_stdin_read;
        startup_info.hStdOutput = child_stdout_write;
        startup_info.hStdError = child_stderr;

        PROCESS_INFORMATION process_info{};
        if (
            !CreateProcessA(
                nullptr,
                command_line.data(),
                nullptr,
                nullptr,
                TRUE,
                CREATE_NO_WINDOW,
                nullptr,
                nullptr,
                &startup_info,
                &process_info
            )
        ) {
            CloseHandle(child_stdin_read);
            CloseHandle(child_stdout_write);
            CloseHandle(child_stderr);
            CloseHandle(stdin_write_local);
            CloseHandle(stdout_read_local);
            throw std::runtime_error(
                "failed to start persistent radare2 session"
            );
        }

        CloseHandle(process_info.hThread);
        CloseHandle(child_stdin_read);
        CloseHandle(child_stdout_write);
        CloseHandle(child_stderr);
        process = process_info.hProcess;
        stdin_write = stdin_write_local;
        stdout_read = stdout_read_local;
    }

    ~R2Session() {
        if (stdin_write != nullptr) {
            CloseHandle(stdin_write);
        }
        if (stdout_read != nullptr) {
            CloseHandle(stdout_read);
        }
        if (process != nullptr) {
            TerminateProcess(process, 0);
            WaitForSingleObject(process, 5000);
            CloseHandle(process);
        }
    }

    std::string command(const std::string& value) {
        // radare2 reads stdin line-by-line: it needs '\n' to know the
        // command is complete and ready to execute. Do NOT send '\0'
        // here -- that's the OUTPUT delimiter for -0 mode, not the input
        // terminator, and radare2 will never run the command without it.
        const char terminator = '\n';
        DWORD written = 0;
        if (
            !WriteFile(
                stdin_write,
                value.data(),
                static_cast<DWORD>(value.size()),
                &written,
                nullptr
            ) ||
            written != value.size() ||
            !WriteFile(
                stdin_write,
                &terminator,
                1,
                &written,
                nullptr
            )
        ) {
            throw std::runtime_error(
                "failed to write command to persistent radare2 session"
            );
        }

        std::string output;
        char character = 0;
        DWORD read = 0;
        while (true) {
            if (
                !ReadFile(
                    stdout_read,
                    &character,
                    1,
                    &read,
                    nullptr
                ) ||
                read == 0
            ) {
                throw std::runtime_error(
                    "persistent radare2 session closed unexpectedly"
                );
            }
            if (character == '\0') {
                return output;
            }
            output += character;
        }
    }
#else
    pid_t pid = -1;
    int stdin_write = -1;
    int stdout_read = -1;

    R2Session(
        const std::string& executable,
        const std::string& binary_path) {
        int stdin_pipe[2]{};
        int stdout_pipe[2]{};

        if (pipe(stdin_pipe) != 0) {
            throw std::runtime_error("failed to create radare2 pipes");
        }
        if (pipe(stdout_pipe) != 0) {
            close(stdin_pipe[0]);
            close(stdin_pipe[1]);
            throw std::runtime_error("failed to create radare2 pipes");
        }

        posix_spawn_file_actions_t actions;
        const int stderr_fd = open("/dev/null", O_WRONLY);
        if (stderr_fd < 0) {
            close(stdin_pipe[0]);
            close(stdin_pipe[1]);
            close(stdout_pipe[0]);
            close(stdout_pipe[1]);
            throw std::runtime_error("failed to open radare2 stderr sink");
        }

        posix_spawn_file_actions_init(&actions);
        posix_spawn_file_actions_adddup2(
            &actions,
            stdin_pipe[0],
            STDIN_FILENO
        );
        posix_spawn_file_actions_adddup2(
            &actions,
            stdout_pipe[1],
            STDOUT_FILENO
        );
        posix_spawn_file_actions_adddup2(
            &actions,
            stderr_fd,
            STDERR_FILENO
        );
        posix_spawn_file_actions_addclose(&actions, stdin_pipe[0]);
        posix_spawn_file_actions_addclose(&actions, stdin_pipe[1]);
        posix_spawn_file_actions_addclose(&actions, stdout_pipe[0]);
        posix_spawn_file_actions_addclose(&actions, stdout_pipe[1]);
        posix_spawn_file_actions_addclose(&actions, stderr_fd);

        std::vector<char*> arguments;
        arguments.push_back(const_cast<char*>(executable.c_str()));
        arguments.push_back(const_cast<char*>("-q0"));
        arguments.push_back(const_cast<char*>("-A"));
        arguments.push_back(const_cast<char*>(binary_path.c_str()));
        arguments.push_back(nullptr);

        const int result = posix_spawnp(
            &pid,
            executable.c_str(),
            &actions,
            nullptr,
            arguments.data(),
            environ
        );
        posix_spawn_file_actions_destroy(&actions);
        close(stdin_pipe[0]);
        close(stdout_pipe[1]);
        close(stderr_fd);

        if (result != 0) {
            close(stdin_pipe[1]);
            close(stdout_pipe[0]);
            throw std::runtime_error(
                "failed to start persistent radare2 session: " +
                std::string(std::strerror(result))
            );
        }

        stdin_write = stdin_pipe[1];
        stdout_read = stdout_pipe[0];
    }

    ~R2Session() {
        if (stdin_write >= 0) {
            close(stdin_write);
        }
        if (stdout_read >= 0) {
            close(stdout_read);
        }
        if (pid > 0) {
            kill(pid, SIGTERM);
            waitpid(pid, nullptr, 0);
        }
    }

    std::string command(const std::string& value) {
        const char* data = value.data();
        std::size_t remaining = value.size();
        while (remaining > 0) {
            const ssize_t written = write(
                stdin_write,
                data,
                remaining
            );
            if (written < 0 && errno == EINTR) {
                continue;
            }
            if (written <= 0) {
                throw std::runtime_error(
                    "failed to write command to persistent radare2 session"
                );
            }
            data += written;
            remaining -= static_cast<std::size_t>(written);
        }

        // radare2 reads stdin line-by-line: it needs '\n' to know the
        // command is complete and ready to execute. Do NOT send '\0'
        // here -- that's the OUTPUT delimiter for -0 mode, not the input
        // terminator, and radare2 will never run the command without it.
        const char terminator = '\n';
        while (write(stdin_write, &terminator, 1) < 0) {
            if (errno != EINTR) {
                throw std::runtime_error(
                    "failed to terminate command for radare2 session"
                );
            }
        }

        std::string output;
        char character = 0;
        while (true) {
            const ssize_t read_count = read(
                stdout_read,
                &character,
                1
            );
            if (read_count < 0 && errno == EINTR) {
                continue;
            }
            if (read_count <= 0) {
                throw std::runtime_error(
                    "persistent radare2 session closed unexpectedly"
                );
            }
            if (character == '\0') {
                return output;
            }
            output += character;
        }
    }
#endif
};

namespace {

bool get_address(const json& object, uint64_t& address) {
    for (const char* key : {
        "offset",
        "addr",
        "address",
        "jump",
        "target",
        "to"
    }) {
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
                address = std::stoull(
                    value.get<std::string>(),
                    nullptr,
                    0
                );
                return true;
            } catch (const std::exception&) {
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
            edges.push_back(std::stoull(
                value.get<std::string>(),
                nullptr,
                0
            ));
        } catch (const std::exception&) {
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
            esil_ops.push_back(
                operation["esil"].get<std::string>()
            );
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
      r2_executable_path_(std::move(r2_executable_path)),
      session_(std::make_unique<R2Session>(
          r2_executable_path_,
          binary_path_)) {
    const json functions = json::parse(session_->command("aflj"));
    if (!functions.is_array()) {
        throw std::runtime_error(
            "radare2 aflj output was not a JSON array"
        );
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

ESILFunctionIterator::~ESILFunctionIterator() = default;

FunctionGraph ESILFunctionIterator::next() {
    if (function_addresses_.empty()) {
        throw py::stop_iteration();
    }

    const uint64_t function_addr = function_addresses_.back();
    function_addresses_.pop_back();

    const std::string address = std::to_string(function_addr);
    session_->command("af @ " + address);
    const std::string output = session_->command("agj @ " + address);

    FunctionGraph graph_result;
    graph_result.name = function_names_[function_addr];
    graph_result.addr = function_addr;

    if (
        output.empty() ||
        output.find_first_not_of(" \t\r\n") == std::string::npos
    ) {
        graph_result.analysis_incomplete = true;
        return graph_result;
    }

    const json graph_output = json::parse(output);
    const json* graph = &graph_output;
    if (graph_output.is_array()) {
        if (graph_output.empty()) {
            graph_result.analysis_incomplete = true;
            return graph_result;
        }
        graph = &graph_output.front();
    }

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