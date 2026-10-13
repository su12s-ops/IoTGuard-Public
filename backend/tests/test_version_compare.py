from app.utils.version_compare import compare_versions, is_version_less


def test_compare_simple_versions():
    assert compare_versions("1.0.1", "1.0.2") == -1
    assert compare_versions("2.4.57-1", "2.4.57-1") == 0
    assert compare_versions("3.0.2-0ubuntu1.18", "3.0.2-0ubuntu1.10") == 1


def test_compare_debian_revision_and_esm_suffix():
    assert compare_versions("1.14.0-0ubuntu1.11", "1.14.0-0ubuntu1.11+esm2") == -1
    assert compare_versions("1.14.0-0ubuntu1.11+esm2", "1.14.0-0ubuntu1.11") == 1


def test_compare_tilde_and_epoch():
    assert compare_versions("1.0~beta1", "1.0") == -1
    assert compare_versions("2:1.0-1", "1:9.9-9") == 1


def test_is_version_less():
    assert is_version_less("1.18.0-ubuntu1.3", "1.18.0-ubuntu1.6")
    assert not is_version_less("1.9.13p3-1", "1.9.9-ubuntu2.4")
    assert is_version_less("1.14.0-0ubuntu1.11", "1.14.0-0ubuntu1.11+esm2")
