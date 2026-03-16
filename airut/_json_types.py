# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Shared JSON type aliases for structured typing.

Provides ``JsonValue`` and ``JsonDict`` as precise replacements for
``dict[str, Any]`` in JSON serialization/deserialization contexts.
"""

type JsonValue = (
    str | int | float | bool | None | list[JsonValue] | dict[str, JsonValue]
)

type JsonDict = dict[str, JsonValue]
