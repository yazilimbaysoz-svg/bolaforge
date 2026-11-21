"""OpenAPI ingestion and reference-resolution tests.

Baysöz Labs <baysozlabs@proton.me>
"""

import json

import pytest

from bolaforge.errors import SpecError
from bolaforge.spec import canonical_digest, load_spec, resolve_refs


def _write(tmp_path, name, payload):
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_load_spec_accepts_openapi_31_json(tmp_path) -> None:
    path = _write(
        tmp_path,
        "spec.json",
        {
            "openapi": "3.1.0",
            "info": {"title": "Demo", "version": "1.0"},
            "paths": {"/x": {"get": {"responses": {"200": {"description": "ok"}}}}},
        },
    )
    loaded = load_spec(path)
    assert loaded.digest == canonical_digest(loaded.document)
    assert len(loaded.digest) == 64


def test_load_spec_accepts_safe_yaml(tmp_path) -> None:
    path = tmp_path / "spec.yaml"
    path.write_text(
        "openapi: 3.1.0\n"
        "info:\n  title: Demo\n  version: '1.0'\n"
        "paths:\n  /x:\n    get:\n      responses:\n        '200':\n          description: ok\n",
        encoding="utf-8",
    )
    loaded = load_spec(path)
    assert loaded.document["paths"]["/x"]["get"]["responses"]["200"]["description"] == "ok"


def test_load_spec_rejects_wrong_version_and_missing_paths(tmp_path) -> None:
    with pytest.raises(SpecError, match="OpenAPI version"):
        load_spec(_write(tmp_path, "old.json", {"openapi": "3.0.3", "paths": {}}))
    with pytest.raises(SpecError, match="paths"):
        load_spec(_write(tmp_path, "nop.json", {"openapi": "3.1.0"}))


def test_local_refs_resolve_and_cycles_are_contained() -> None:
    document = {
        "openapi": "3.1.0",
        "paths": {
            "/items": {
                "get": {
                    "parameters": [{"$ref": "#/components/parameters/ItemId"}],
                    "responses": {"200": {"$ref": "#/components/responses/Ok"}},
                }
            }
        },
        "components": {
            "parameters": {
                "ItemId": {"name": "item_id", "in": "query", "schema": {"type": "string"}}
            },
            "responses": {"Ok": {"description": "ok"}},
            "schemas": {
                "Node": {
                    "type": "object",
                    "properties": {"next": {"$ref": "#/components/schemas/Node"}},
                }
            },
        },
    }
    resolved = resolve_refs(document)
    assert resolved["paths"]["/items"]["get"]["parameters"][0]["name"] == "item_id"
    assert resolved["paths"]["/items"]["get"]["responses"]["200"]["description"] == "ok"
    assert document["paths"]["/items"]["get"]["parameters"][0] == {
        "$ref": "#/components/parameters/ItemId"
    }
    expanded = resolve_refs(document, sections=("components",))
    nested = expanded["components"]["schemas"]["Node"]["properties"]["next"]
    assert nested["properties"]["next"] == {"$refCycle": "#/components/schemas/Node"}


def test_external_and_unresolved_refs_are_rejected() -> None:
    with pytest.raises(SpecError, match="external"):
        resolve_refs({"paths": {"/x": {"$ref": "https://example.invalid/spec.json"}}})
    with pytest.raises(SpecError, match="unresolved"):
        resolve_refs({"paths": {"/x": {"$ref": "#/components/missing"}}})


def test_oversized_document_is_rejected(tmp_path) -> None:
    path = tmp_path / "huge.json"
    path.write_bytes(b"x" * (4 * 1024 * 1024 + 1))
    with pytest.raises(SpecError, match="safety limit"):
        load_spec(path)
