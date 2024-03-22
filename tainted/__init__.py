from .logging import init_logger
from .runtime import function_sink as _function_sink
from .runtime import is_taintable as _is_taintable
from .runtime import is_tainted as _is_tainted
from .runtime import make_taintable as _make_taintable
from .runtime import raise_if_tainted as _raise_if_tainted
from .runtime import taint as _taint
from .runtime import untaint as _untaint

init_logger()

__all__ = [
    "_function_sink",
    "_is_taintable",
    "_is_tainted",
    "_make_taintable",
    "_raise_if_tainted",
    "_taint",
    "_untaint",
]
