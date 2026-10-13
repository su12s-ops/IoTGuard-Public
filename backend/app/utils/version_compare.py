from __future__ import annotations

from functools import lru_cache


def _split_version(version: str) -> tuple[int, str, str]:
    text = (version or "0").strip()
    epoch = 0
    remainder = text
    if ":" in remainder:
        maybe_epoch, tail = remainder.split(":", 1)
        if maybe_epoch.isdigit():
            epoch = int(maybe_epoch)
            remainder = tail
    if "-" in remainder:
        upstream, revision = remainder.rsplit("-", 1)
    else:
        upstream, revision = remainder, "0"
    return epoch, upstream or "0", revision or "0"


def _order(char: str) -> int:
    if char == "~":
        return -1
    if not char:
        return 0
    if char.isalpha():
        return ord(char)
    return ord(char) + 256


def _compare_part(left: str, right: str) -> int:
    left = left or ""
    right = right or ""
    left_index = 0
    right_index = 0

    while left_index < len(left) or right_index < len(right):
        while (
            (left_index < len(left) and not left[left_index].isdigit())
            or (right_index < len(right) and not right[right_index].isdigit())
        ):
            left_char = left[left_index] if left_index < len(left) and not left[left_index].isdigit() else ""
            right_char = right[right_index] if right_index < len(right) and not right[right_index].isdigit() else ""
            left_order = _order(left_char)
            right_order = _order(right_char)
            if left_order != right_order:
                return -1 if left_order < right_order else 1
            if left_char:
                left_index += 1
            if right_char:
                right_index += 1

        while left_index < len(left) and left[left_index] == "0":
            left_index += 1
        while right_index < len(right) and right[right_index] == "0":
            right_index += 1

        left_start = left_index
        right_start = right_index
        while left_index < len(left) and left[left_index].isdigit():
            left_index += 1
        while right_index < len(right) and right[right_index].isdigit():
            right_index += 1

        left_digits = left[left_start:left_index]
        right_digits = right[right_start:right_index]
        if len(left_digits) != len(right_digits):
            return -1 if len(left_digits) < len(right_digits) else 1
        if left_digits != right_digits:
            return -1 if left_digits < right_digits else 1

    return 0


@lru_cache(maxsize=4096)
def compare_versions(left: str, right: str) -> int:
    """Compare Debian/Ubuntu package versions using dpkg-compatible semantics."""
    left_epoch, left_upstream, left_revision = _split_version(left)
    right_epoch, right_upstream, right_revision = _split_version(right)

    if left_epoch != right_epoch:
        return -1 if left_epoch < right_epoch else 1

    upstream_result = _compare_part(left_upstream, right_upstream)
    if upstream_result:
        return upstream_result

    return _compare_part(left_revision, right_revision)


def is_version_less(current: str, fixed: str) -> bool:
    if not fixed:
        return False
    return compare_versions(current, fixed) < 0
