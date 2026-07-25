from ._core import (
    BasicBlock,
    ESILFunctionIterator,
    FunctionGraph,
)


def stream_functions(
    binary_path: str,
    r2_executable_path: str = "radare2",
) -> ESILFunctionIterator:
    return ESILFunctionIterator(binary_path, r2_executable_path)

__all__ = [
    "BasicBlock",
    "ESILFunctionIterator",
    "FunctionGraph",
    "stream_functions",
]
