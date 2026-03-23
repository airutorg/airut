# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Declarative configuration layer.

Provides schema metadata, config snapshots, source abstraction,
schema migration, and config diffing utilities.

Submodules:

- ``schema`` — ``FieldMeta``, ``Scope``, ``meta()``, ``schema_for_ui()``
- ``snapshot`` — ``ConfigSnapshot`` (user-set value tracking)
- ``source`` — ``ConfigSource`` protocol, ``YamlConfigSource``
- ``migration`` — Schema version migration (``apply_migrations``)
- ``diff`` — Config diffing (``diff_configs``, ``diff_by_scope``)
- ``editor`` — Config editor logic (tag encoding, validation, diff, save)
"""
