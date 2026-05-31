"""Package-import sanity check. Real coverage lands with the feature TDD commits."""

import gha_sec_feed


def test_version_is_set():
    assert gha_sec_feed.__version__ == "0.1.0"
