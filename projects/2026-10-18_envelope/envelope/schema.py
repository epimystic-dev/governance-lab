"""The envelope JSON Schema.

The schema is JSON Schema 2020-12-shaped so that standard tooling
consumes it; the reference validator in structural.py implements the
subset the schema actually uses, documented in docs rather than left
as implicit magic.
"""

from __future__ import annotations

# Status values a worker is allowed to return.
STATUS_VALUES = ("ok", "partial", "failed", "blocked")

# Reasoning-depth tag values. "normal" is single-pass; "reasoning" is
# extended deliberation; "iterated" is a maker-checker pass that was
# actually executed. The compound "reasoning-iterated" is both.
REASONING_TAG_VALUES = (
    "normal",
    "reasoning",
    "iterated",
    "reasoning-iterated",
)

# Finding severity values. Mirrors Severity in types.py.
SEVERITY_VALUES = ("HIGH", "MEDIUM", "LOW", "INFO")

# Evidence kind values. "cite" is a bibliographic reference; "file" is
# an on-disk artifact; "measure" is a numeric result the worker took;
# "external" is any other named source.
EVIDENCE_KIND_VALUES = ("cite", "file", "measure", "external")


SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://epimystic.dev/governance-lab/envelope-v0.1.0.json",
    "title": "Worker Output Envelope",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "envelope_version",
        "task_id",
        "status",
        "scope",
        "findings",
        "evidence",
        "reasoning_tag",
        "self_audit",
        "timestamp",
    ],
    "properties": {
        "envelope_version": {
            "type": "string",
            "pattern": r"^\d+\.\d+\.\d+$",
            "description": "Semantic version of the envelope schema the worker is claiming to emit.",
        },
        "task_id": {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "description": "Identifier the host assigned to this unit of work.",
        },
        "status": {
            "type": "string",
            "enum": list(STATUS_VALUES),
            "description": "Worker-reported outcome. ok: clean completion. partial: completion with declared caveats. failed: completion attempted and did not succeed. blocked: completion not attempted because a precondition was not met.",
        },
        "scope": {
            "type": "object",
            "additionalProperties": False,
            "required": ["in", "out"],
            "properties": {
                "in": {
                    "type": "array",
                    "items": {"type": "string", "minLength": 1},
                    "minItems": 1,
                },
                "out": {
                    "type": "array",
                    "items": {"type": "string", "minLength": 1},
                    "minItems": 1,
                },
            },
        },
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["id", "severity", "message"],
                "properties": {
                    "id": {"type": "string", "minLength": 1},
                    "severity": {
                        "type": "string",
                        "enum": list(SEVERITY_VALUES),
                    },
                    "message": {"type": "string", "minLength": 1},
                    "where": {"type": "string"},
                    "evidence_refs": {
                        "type": "array",
                        "items": {"type": "integer", "minimum": 0},
                    },
                },
            },
        },
        "evidence": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["claim", "kind", "ref"],
                "properties": {
                    "claim": {"type": "string", "minLength": 1},
                    "kind": {
                        "type": "string",
                        "enum": list(EVIDENCE_KIND_VALUES),
                    },
                    "ref": {"type": "string", "minLength": 1},
                    "hash": {"type": "string"},
                },
            },
        },
        "reasoning_tag": {
            "type": "string",
            "enum": list(REASONING_TAG_VALUES),
            "description": "Reasoning-depth claim. normal is single pass; reasoning is extended deliberation; iterated is a maker-checker pass that was actually executed.",
        },
        "self_audit": {
            "type": "object",
            "additionalProperties": False,
            "required": ["checker_run", "verdict"],
            "properties": {
                "checker_run": {
                    "type": "boolean",
                    "description": "Whether a role separate from the maker verified this output. True if the checker actually ran, false otherwise. The schema cannot verify truthfulness; cross-field rules enforce the discipline that follows from the value.",
                },
                "checker_role": {
                    "type": "string",
                    "description": "Named role of the checker (e.g. 'reviewer', 'auditor'). Required by cross-field rule when checker_run is true.",
                },
                "verdict": {
                    "type": "string",
                    "enum": ["ok", "fail", "unknown"],
                },
                "reasons": {
                    "type": "array",
                    "items": {"type": "string", "minLength": 1},
                },
            },
        },
        "timestamp": {
            "type": "string",
            "description": "RFC3339-shaped timestamp of worker completion. Enforced by cross-field rule rather than regex to allow a reviewer to loosen the format once without rewriting the schema.",
            "minLength": 10,
        },
    },
}
