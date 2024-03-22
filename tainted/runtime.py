from types import MethodType
from typing import Any, Callable

from .constants import (
    BUILTIN_TAINTABLE_TYPES,
    NON_PROPAGATING_METHODS,
    NON_TAINTABLE_TYPES,
    PROPAGATING_REFLECTED_METHODS,
)
from .logging import logger

taint_class_cache = {}
tainted_object_ids = set()  # Fallback for non-taintable objects


def taint(obj):
    """Helper function to taint an object even if it is not taintable."""
    if not is_taintable(obj):
        obj = make_taintable(obj)

    if is_directly_taintable(obj):
        obj.taint()
    else:
        tainted_object_ids.add(id(obj))

    return obj


def untaint(obj):
    """Helper function to remove taint from an object even if it is not taintable."""
    if not is_taintable(obj):
        obj = make_taintable(obj)

    if is_directly_taintable(obj):
        obj.untaint()
    else:
        tainted_object_ids.remove(id(obj))

    return obj


def is_tainted(obj):
    """Helper function to check if an object is tainted."""
    if is_directly_taintable(obj):
        return obj.is_tainted
    return id(obj) in tainted_object_ids


def raise_if_tainted(obj):
    """Raise an error if the object is tainted, otherwise return the object (no-op).

    This will be called at taint sinks and other sensitive operations.
    """
    if is_tainted(obj):
        raise RuntimeError(f"Object {obj} is tainted")
    return obj


def is_taintable(obj):
    """Helper function to check if an object is taintable (e.g., has been passed through
    `make_taintable`)."""
    return is_directly_taintable(obj) or id(obj) in tainted_object_ids


def is_directly_taintable(obj):
    """Helper function to check if an object is directly taintable (e.g., has been passed
    through `make_taintable` and we were able to directly modify the object)."""
    return hasattr(obj, "is_tainted")


def function_sink(fn: Callable, *args, **kwargs) -> Any:
    """Interpose on a function call to verify that the arguments are not tainted.

    Parameters
    ----------
    fn : Callable
        The function to be called
    *args : Any
        The arguments to be verified and passed to the function
    **kwargs : Any
        The keyword arguments to be verified and passed to the function

    Returns
    -------
    Any
        The result of the function call

    Raises
    ------
    TaintedError
        If the function was called with a tainted argument
    """
    for arg in args:
        raise_if_tainted(arg)
    for kwarg in kwargs.values():
        raise_if_tainted(kwarg)
    return fn(*args, **kwargs)


def make_taintable(obj: Any) -> Any:
    """Basic conversion of a basic object to a taintable object.

    This is the fundamental building block for our dynamic taint analysis. This function
    will create a new tainted version of the object's class, add an additional attribute
    to the class to track taint, and set hooks for all methods to propagate taint.
    """
    _type = type(obj)

    # If the object is not taintable, we can just return it as is
    if _type in NON_TAINTABLE_TYPES:
        return obj

    if _type in taint_class_cache:
        return taint_class_cache[_type](obj)

    # Build a new class that inherits from the original
    if _type in BUILTIN_TAINTABLE_TYPES:
        taint_class = create_taintable_class(_type)
        taint_class_cache[_type] = taint_class
        return taint_class(obj)

    # Otherwise, initialize the hooks directly on the object
    try:
        create_taintable_object(obj)
    except AttributeError as e:
        logger.debug(
            f"Falling back to tainted object id tracking for object of type {_type}: {e}"
        )
        tainted_object_ids.add(id(obj))
    return obj


def create_taintable_class(kls):
    """Create a new class that inherits from the original class, adds taint tracking to
    the class, and inserts hooks to propagate taint.

    Reflected methods are also modified to propagate taint from the object to the other
    object in the operation. For example, if we have a taintable object `x` and a
    non-taintable object `y`, we should propagate the taintedness of `x` to `y` when we
    call `y + x`. In this way, we can track taintedness across operations in third-party
    code that we did not instrument.

    We also store the new class in a cache to avoid creating the same class multiple
    times since we perform a lot of dynamic setup for each class.
    """

    OVERLOADED_METHODS = {
        "__iter__": propagate_iter,
        "items": propagate_dict_items,
        "keys": propagate_dict_keys,
        "values": propagate_dict_values,
    }

    class taintable_class(kls):
        def __new__(cls, *args, **kwargs):
            try:
                instance = super().__new__(cls, *args, **kwargs)
            except TypeError as e:
                instance = super().__new__(cls)
            instance.is_tainted = False
            return instance

        def taint(self):
            self.is_tainted = True

        def untaint(self):
            self.is_tainted = False

    for attr in dir(taintable_class):
        if attr in NON_PROPAGATING_METHODS:
            continue

        if attr in OVERLOADED_METHODS:
            method = OVERLOADED_METHODS[attr](getattr(taintable_class, attr))
            setattr(taintable_class, attr, method)
        elif callable(getattr(taintable_class, attr)):
            setattr(
                taintable_class, attr, propagate_taint(getattr(taintable_class, attr))
            )

    for attr in PROPAGATING_REFLECTED_METHODS:
        try:
            setattr(taintable_class, attr, propagate_reflected_taint(attr))
        except AttributeError as e:
            logger.debug(f"Unable to set reflected method {attr}: {e}")

    return taintable_class


def create_taintable_object(obj):
    """Add taint tracking to an object that is an instance of a user-defined class.

    Unfortunately, dunder methods on custom classes do not propagate taint because we
    cannot intercept them without modifying the class itself. Trying to modify the class
    definition would be especially challenging for classes defined in third-party
    libraries which we want to support without modification. So, calling `_make_taintable`
    on an instance of a class is our best option for now.
    """

    def taint(self):
        self.is_tainted = True

    def untaint(self):
        self.is_tainted = False

    for attr in dir(obj):
        if attr.startswith("__") and attr.endswith("__"):
            continue

        if callable(getattr(obj, attr)):
            class_method = getattr(obj, attr).__func__
            setattr(obj, attr, MethodType(propagate_taint(class_method), obj))

    setattr(obj, "is_tainted", False)
    setattr(obj, "taint", MethodType(taint, obj))
    setattr(obj, "untaint", MethodType(untaint, obj))


def propagate_taint(method):
    """Method hook to propagate taint from the current object and the arguments to the
    result of the method call."""

    def inner(self, *args, **kwargs):
        logger.debug(
            f"Propagating taint for method {method.__name__} with args {args} and kwargs {kwargs}"
        )

        result = make_taintable(method(self, *args, **kwargs))
        result_type = type(result)
        if result_type in NON_TAINTABLE_TYPES:
            return result

        # Propagate from current object
        if is_tainted(self):
            result = taint(result)

        for arg in args:
            if is_tainted(arg):
                return taint(result)
        for kwarg in kwargs.values():
            if is_tainted(kwarg):
                return taint(result)

        return result

    return inner


def propagate_reflected_taint(method):
    """Method hook for reflected operations to propagate taint from the tainted object in
    the operation to the other, potentially non-taintable, object."""

    def inner(self, other):
        logger.debug(f"Propagating taint for reflected method {method}")
        return propagate_taint(getattr(type(other), method.replace("r", "")))(
            other, self
        )

    return inner


def propagate_iter(_iter):
    """Method hook to propagate taint to elements of an iterable."""

    def inner(self):
        logger.debug(f"Propagating taint for iter method {_iter.__name__}")
        for el in _iter(self):
            yield taint(el) if is_tainted(self) else el

    return inner


def propagate_dict_items(items):
    """Method hook to propagate taint to keys and values of a dictionary."""

    def inner(self):
        logger.debug(f"Propagating taint for items method {items.__name__}")
        for k, v in items(self):
            yield taint(k), taint(v) if is_tainted(self) else (k, v)

    return inner


def propagate_dict_keys(keys):
    """Method hook to propagate taint to keys of a dictionary."""

    def inner(self):
        logger.debug(f"Propagating taint for keys method {keys.__name__}")
        for k in keys(self):
            yield taint(k) if is_tainted(self) else k

    return inner


def propagate_dict_values(values):
    """Method hook to propagate taint to values of a dictionary."""

    def inner(self):
        logger.debug(f"Propagating taint for values method {values.__name__}")
        for v in values(self):
            yield taint(v) if is_tainted(self) else v

    return inner
