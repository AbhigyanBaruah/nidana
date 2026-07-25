from ._core import ESILFunctionIterator, FunctionGraph, BasicBlock, hello_nidana


def stream_functions(count):
    return ESILFunctionIterator(count)

__all__ = [
    "BasicBlock",
    "ESILFunctionIterator",
    "FunctionGraph",
    "hello_nidana",
    "stream_functions",
]
