import importlib


def test_package_importable() -> None:
    assert importlib.import_module("gr9_refresh_token_rotation") is not None
