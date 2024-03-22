import pytest

from tainted import (
    _function_sink,
    _is_taintable,
    _is_tainted,
    _make_taintable,
    _raise_if_tainted,
    _taint,
    _untaint,
)


def assert_tainted(obj):
    assert _is_tainted(obj), f"{obj} is not tainted"


def assert_untainted(obj):
    assert not _is_tainted(obj), f"{obj} is tainted"


def test_basics():
    # Taint a value
    x = _taint(1)
    assert_tainted(x)

    # Assignment preserves taint (same object)
    y = x
    assert_tainted(y)

    # Untaint affects all references
    _untaint(x)
    assert_untainted(x)
    assert_untainted(y)

    # Round trip
    _taint(y)
    assert_tainted(x)
    assert_tainted(y)

    with pytest.raises(RuntimeError):
        _raise_if_tainted(y)


def test_literals():
    x = _taint(1)
    assert _is_tainted(x)

    x = _taint(1.0)
    assert _is_tainted(x)

    x = _taint("abc")
    assert _is_tainted(x)


def test_comparison():
    # Since booleans cannot be tainted, the result of comparisons is always untainted
    # but the comparison should still be correct
    x = _taint("abc")
    y = _taint("def")

    assert_untainted(x == y)
    assert not (x == y)

    assert_untainted(x != y)
    assert x != y

    assert_untainted(x < y)
    assert x < y

    assert_untainted(x <= y)
    assert x <= y

    assert_untainted(x > y)
    assert not (x > y)

    assert_untainted(x >= y)
    assert not (x >= y)


def test_arithmetic():
    x = _taint(1)
    y = _taint(2)

    z = x + y
    assert_tainted(z)
    assert z == 3

    z = x - y
    assert_tainted(z)
    assert z == -1

    z = x * y
    assert_tainted(z)
    assert z == 2

    z = x / y
    assert_tainted(z)
    assert z == 0.5

    x += y
    assert_tainted(x)
    assert x == 3

    # Commutative
    assert_tainted(2 + x)
    assert_tainted(x + 2)
    assert 2 + x == x + 2


def test_logical():
    x = _taint(1)
    y = _taint(2)

    z = x and y
    assert_tainted(z)
    assert z is y

    z = x or y
    assert_tainted(z)
    assert z is x

    # Booleans cannot be tainted
    z = not x
    assert_untainted(z)
    assert z is False


def test_string():
    x = _taint("abc")
    assert_tainted(x)

    # Methods preserve taint and do not affect functionality
    y = x.upper()
    assert_tainted(y)
    assert y == "ABC"

    y = x.replace("a", "z")
    assert_tainted(y)
    assert y == "zbc"

    y = x + "def"
    assert_tainted(y)
    assert y == "abcdef"

    y = "xyz" + x
    assert_tainted(y)
    assert y == "xyzabc"

    # Characters are also tainted
    c = x[0]
    assert_tainted(c)
    assert c == "a"

    # Unpacking preserves taint
    x = _taint("abc")
    a, c = x.split("b")
    assert_tainted(a)
    assert_tainted(c)


def test_list():
    # Basic list
    l = _taint([1, 2, 3])
    assert_tainted(l)

    # Indexing and slicing preserve taint because the whole list is tainted
    assert_tainted(l[0])
    assert_tainted(l[:2])

    # Commutative
    assert_tainted(_taint([1, 2]) + [3, 4])
    assert_tainted([1, 2] + _taint([3, 4]))

    # Tainted elements do not taint the whole list
    assert_untainted([_taint(1), 2, 3])

    # Even via assignment
    l = [1, 2, 3]
    l[0] = _taint(0)
    assert_untainted(l)
    assert_tainted(l[0])

    # Other methods do not affect taint
    l.sort(reverse=True)
    assert_untainted(l)
    assert_tainted(l[-1])

    el = l.pop()
    assert_untainted(l)
    assert_tainted(el)

    # Some built-in methods are not supported
    assert_untainted(len(_taint([1, 2, 3])))


def test_tuple():
    x = _taint((1, 2, 3))
    assert_tainted(x)

    # Tainted elements do not taint the entire tuple
    x = (_taint(1), 2, 3)
    assert_untainted(x)
    assert_tainted(x[0])

    # Unpacking does not affect taint
    a, b, c = x
    assert_tainted(a)
    assert_untainted(b)
    assert_untainted(c)

    # Commutative
    assert_tainted(_taint((1, 2)) + (3, 4))
    assert_tainted((1, 2) + _taint((3, 4)))

    # Double the tuple, and element taint is preserved
    y = x * 2
    assert_untainted(y)
    assert_tainted(y[0])
    assert_tainted(y[3])


def test_set():
    x = _taint({1, 2, 3})
    assert _is_tainted(x) and not _is_tainted({1, 2, 3})

    # Tainted elements do not taint the entire set
    x = {_taint(1), 2, 3}
    assert_untainted(x)

    # Adding a new element to the set, should not taint the set
    x.add(_taint(4))
    assert_untainted(x)

    x = _taint({1, 2}) | {3}
    assert_tainted(x)

    # A tainted set has its elements tainted if we iterate over it
    x.add(4)
    for el in x:
        assert_tainted(el)


def test_dict():
    x = _taint({"a": 1, "b": 2, "c": 3})
    assert_tainted(x)
    assert_tainted(x["a"])

    # Everthing in the dict is tainted
    for k, v in x.items():
        assert_tainted(k)
        assert_tainted(v)

    # Adding a new element to a tainted container should preserve the taint for both the
    # container and the value
    x["d"] = 4
    assert_tainted(x)
    assert_tainted(x["d"])

    x = {"a": _taint(1), "b": 2, "c": 3}
    assert_untainted(x)

    # Retrieving the element should not taint the container
    assert_tainted(x["a"])
    assert_untainted(x)

    x["d"] = _taint(4)
    assert_untainted(x)
    assert_tainted(x["d"])


def test_function_sink():
    def f(x):
        return x + 1

    x = _taint(1)

    # A tainted argument should raise an error before executing the function
    with pytest.raises(RuntimeError):
        _function_sink(f, x)

    # Untainted arguments should work as expected
    _untaint(x)
    f_x = _function_sink(f, x)
    assert_untainted(f_x)
    assert f_x == 2


def test_make_taintable():
    # Booleans cannot be made taintable
    x = _make_taintable(True)
    assert not _is_taintable(x)

    x = _make_taintable(1)
    assert _is_taintable(x)

    # If it walks like a duck and quaks like a duck, then it must be a duck
    assert x == 1

    # Since we are not overriding the built-in `type` function, `x` really does not have
    # type `int`, but rather `taintable_class`. Any user code that inspects the type of
    # `x` will see `taintable_class` instead of `int`.
    assert type(x) != int


def test_make_taintable_custom_class():
    class Int:
        def __init__(self, value):
            self.value = value

        def __add__(self, other):
            return Int(self.value + other.value)

        def __eq__(self, other):
            return self.value == other.value

        def add(self, other):
            return Int(self.value + other.value)

    x = _taint(Int(1))
    assert_tainted(x)

    y = _make_taintable(Int(2))
    assert_untainted(y)

    # # The taintable class should behave like the original class
    assert x == Int(1)
    assert x + y == Int(3)

    assert_untainted(x + y)
    assert_tainted(x.add(y))
