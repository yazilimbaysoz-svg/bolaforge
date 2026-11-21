"""OpenAPI document ingestion, validation and safe reference resolution.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import _yaml
from .errors import SpecError

MAX_DOCUMENT_BYTES = 4 * 1024 * 1024
MAX_REF_DEPTH = 32


@dataclass(frozen=True, slots=True)
class LoadedSpec:
    """A parsed document with its canonical content digest."""

    source: str
    document: dict[str, Any]
    digest: str


def canonical_digest(document: Any) -> str:
    """Return a stable SHA-256 digest of any JSON-compatible value."""

    payload = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _read_document(path: Path, label: str) -> tuple[Any, str]:
    try:
        stat = path.stat()
    except OSError as exc:
        raise SpecError(f"cannot read {label} {path}: {exc}") from exc
    if not path.is_file():
        raise SpecError(f"{label} {path} is not a regular file")
    if stat.st_size > MAX_DOCUMENT_BYTES:
        raise SpecError(f"{label} {path} exceeds the {MAX_DOCUMENT_BYTES} byte safety limit")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SpecError(f"cannot read {label} {path}: {exc}") from exc
    text = raw.decode("utf-8-sig", errors="strict") if _looks_textual(raw) else ""
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            return json.loads(text), text
        except json.JSONDecodeError as exc:
            raise SpecError(
                f"invalid JSON in {label} {path}: {exc.msg} at line {exc.lineno}"
            ) from exc
    try:
        return _yaml.loads(text), text
    except _yaml.YamlSubsetError as exc:
        raise SpecError(f"invalid YAML in {label} {path}: {exc}") from exc


def _looks_textual(raw: bytes) -> bool:
    if b"\x00" in raw:
        return False
    try:
        raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return False
    return True


def load_document(path: str | Path, label: str = "document") -> tuple[Any, str]:
    """Read a JSON or safe-YAML document from disk."""

    return _read_document(Path(path), label)


def load_json_object(path: str | Path, label: str) -> tuple[dict[str, Any], str]:
    """Read a document that must be a JSON/YAML mapping."""

    document, text = _read_document(Path(path), label)
    if not isinstance(document, dict):
        raise SpecError(f"{label} {path} must contain a mapping at the top level")
    return document, text


def load_spec(path: str | Path) -> LoadedSpec:
    """Load and validate the structural envelope of an OpenAPI document."""

    document, _ = load_json_object(path, "OpenAPI document")
    version = str(document.get("openapi", ""))
    if not version.startswith("3.1"):
        raise SpecError(f"unsupported OpenAPI version {version!r}; bolaforge requires OpenAPI 3.1")
    if not isinstance(document.get("paths"), dict):
        raise SpecError("OpenAPI document must contain a 'paths' mapping")
    return LoadedSpec(str(path), document, canonical_digest(document))


def _pointer_value(root: Any, pointer: str) -> Any:
    normalized = pointer[1:] if pointer.startswith("#") else pointer
    if not normalized.startswith("/"):
        raise SpecError(f"unsupported $ref {pointer!r}: expected a local JSON Pointer")
    pointer = normalized
    current = root
    for token in pointer[1:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if token not in current:
                raise SpecError(f"unresolved $ref {pointer!r}: missing key {token!r}")
            current = current[token]
        elif isinstance(current, list):
            if not token.isdigit() or int(token) >= len(current):
                raise SpecError(f"unresolved $ref {pointer!r}: invalid list index {token!r}")
            current = current[int(token)]
        else:
            raise SpecError(f"unresolved $ref {pointer!r}: cannot traverse scalar")
    return current


def resolve_refs(
    document: dict[str, Any], sections: tuple[str, ...] = ("paths",)
) -> dict[str, Any]:
    """Resolve local ``$ref`` pointers with cycle and depth protection.

    Only the requested top-level sections are expanded, which keeps recursive
    schemas harmless. External references are rejected so that audits never
    trigger network or file-system access from an untrusted specification.
    """

    def walk(value: Any, depth: int, active: frozenset[str]) -> Any:
        if depth > MAX_REF_DEPTH:
            raise SpecError(f"$ref nesting exceeds {MAX_REF_DEPTH} levels")
        if isinstance(value, list):
            return [walk(item, depth + 1, active) for item in value]
        if not isinstance(value, dict):
            return value
        reference = value.get("$ref")
        if reference is not None:
            if not isinstance(reference, str):
                raise SpecError("$ref must be a string")
            if not reference.startswith("#/"):
                raise SpecError(f"external or unsupported $ref {reference!r} is not allowed")
            if reference in active:
                return {"$refCycle": reference}
            target = _pointer_value(document, reference)
            resolved = walk(target, depth + 1, active | {reference})
            if not isinstance(resolved, dict):
                if len(value) == 1:
                    return resolved
                raise SpecError(f"$ref {reference!r} resolves to a scalar but has siblings")
            merged = dict(resolved)
            merged.update({key: item for key, item in value.items() if key != "$ref"})
            return merged
        return {key: walk(item, depth + 1, active) for key, item in value.items()}

    expanded = dict(document)
    for section in sections:
        if section in expanded:
            expanded[section] = walk(expanded[section], 0, frozenset())
    return expanded
