"""Reference structural validator.

A hand-rolled JSON Schema 2020-12 subset validator covering only what
the envelope SCHEMA actually uses. Supported keywords, documented so
there is no implicit magic: ``type``, ``required``, ``properties``,
``additionalProperties: false``, ``enum``, ``minLength``, ``maxLength``,
``minItems``, ``minimum``, ``pattern``, ``items`` (schema form),
``$id``, ``$schema``, ``title``, ``description``.

The validator reports every structural fault at once rather than
stopping on the first - a reviewer sees the full defect surface in
one pass.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from .schema import SCHEMA
from .types import ValidationError


_META_KEYS = {"$schema", "$id", "title", "description"}


def validate(envelope: Any) -> None:
    """Validate ``envelope`` against the envelope SCHEMA.

    Raises ``ValidationError`` with every structural fault found;
    returns None on success.
    """
    errors: List[Tuple[str, str]] = []
    _validate_node(envelope, SCHEMA, "", errors)
    if errors:
        raise ValidationError(errors)


def _validate_node(
    value: Any,
    schema: Dict[str, Any],
    pointer: str,
    errors: List[Tuple[str, str]],
) -> None:
    expected_type = schema.get("type")
    if expected_type is not None and not _type_ok(value, expected_type):
        errors.append(
            (pointer or "/", f"expected type {expected_type}, "
             f"got {_py_type(value)}")
        )
        # If the type is wrong there is no point looking inside.
        return

    if expected_type == "object":
        _validate_object(value, schema, pointer, errors)
    elif expected_type == "array":
        _validate_array(value, schema, pointer, errors)
    elif expected_type == "string":
        _validate_string(value, schema, pointer, errors)
    elif expected_type == "integer":
        _validate_integer(value, schema, pointer, errors)
    elif expected_type == "boolean":
        pass  # type check above suffices

    if "enum" in schema and value not in schema["enum"]:
        errors.append(
            (pointer or "/", f"value is not one of enum: {schema['enum']!r}")
        )


def _validate_object(
    value: Dict[str, Any],
    schema: Dict[str, Any],
    pointer: str,
    errors: List[Tuple[str, str]],
) -> None:
    required = schema.get("required", [])
    for key in required:
        if key not in value:
            errors.append(
                (pointer or "/", f"missing required property '{key}'")
            )

    props = schema.get("properties", {})

    if schema.get("additionalProperties") is False:
        allowed = set(props.keys())
        for key in value.keys():
            if key not in allowed:
                errors.append(
                    (pointer or "/",
                     f"additional property '{key}' not permitted")
                )

    for key, sub in props.items():
        if key in value:
            _validate_node(value[key], sub,
                           f"{pointer}/{key}", errors)


def _validate_array(
    value: List[Any],
    schema: Dict[str, Any],
    pointer: str,
    errors: List[Tuple[str, str]],
) -> None:
    min_items = schema.get("minItems")
    if min_items is not None and len(value) < min_items:
        errors.append(
            (pointer or "/",
             f"array has {len(value)} items, needs minItems={min_items}")
        )

    item_schema = schema.get("items")
    if item_schema is not None:
        for i, item in enumerate(value):
            _validate_node(item, item_schema,
                           f"{pointer}/{i}", errors)


def _validate_string(
    value: str,
    schema: Dict[str, Any],
    pointer: str,
    errors: List[Tuple[str, str]],
) -> None:
    min_len = schema.get("minLength")
    if min_len is not None and len(value) < min_len:
        errors.append(
            (pointer or "/",
             f"string length {len(value)} below minLength={min_len}")
        )

    max_len = schema.get("maxLength")
    if max_len is not None and len(value) > max_len:
        errors.append(
            (pointer or "/",
             f"string length {len(value)} above maxLength={max_len}")
        )

    pattern = schema.get("pattern")
    if pattern is not None and not re.search(pattern, value):
        errors.append(
            (pointer or "/",
             f"string does not match pattern {pattern!r}")
        )


def _validate_integer(
    value: int,
    schema: Dict[str, Any],
    pointer: str,
    errors: List[Tuple[str, str]],
) -> None:
    minimum = schema.get("minimum")
    if minimum is not None and value < minimum:
        errors.append(
            (pointer or "/",
             f"integer value {value} below minimum={minimum}")
        )


def _type_ok(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        # bool is a subclass of int in Python; exclude it explicitly.
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return (isinstance(value, (int, float))
                and not isinstance(value, bool))
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    return False


def _py_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__
