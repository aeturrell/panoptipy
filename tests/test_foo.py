from panoptipy.foo import foo
import pytest


def test_foo():
    assert foo("foo") == "foo"
