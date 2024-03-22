NON_TAINTABLE_TYPES = {bool, type(None)}
BUILTIN_TAINTABLE_TYPES = {int, float, str, list, dict, set, tuple}

# Methods that should not propagate taint
NON_PROPAGATING_METHODS = {
    "__init__",
    "__new__",
    "__class__",
    "__bytes__",
    "__format__",
    "__getattribute__",
    "__getattr__",
    "__setattr__",
    "__delattr__",
    "__dir__",
    "__get__",
    "__set__",
    "__init_subclass__",
    "__set_name__",
    "__instancecheck__",
    "__subclasscheck__",
    "__class_getitem__",
    "__call__",
    "__delitem__",
    "__missing__",
    "__next__",
    "__reversed__",
    "__contains__",
}

# Reflected methods that should propagate taint
PROPAGATING_REFLECTED_METHODS = {
    "__radd__",
    "__rsub__",
    "__rmul__",
    "__rdiv__",
    "__rmod__",
    "__rpow__",
    "__rand__",
    "__rxor__",
    "__ror__",
}
