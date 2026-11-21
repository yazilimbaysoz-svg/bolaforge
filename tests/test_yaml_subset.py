"""Tests for the safe YAML subset reader.

Baysöz Labs <baysozlabs@proton.me>
"""

import pytest

from bolaforge._yaml import YamlSubsetError, loads


def test_block_mappings_and_sequences() -> None:
    document = loads(
        """
openapi: 3.1.0
paths:
  /v1/items/{item_id}:
    get:
      tags:
        - alpha
        - beta
      parameters:
        - name: item_id
          in: path
          schema:
            type: string
            format: uuid
        - name: limit
          in: query
          schema:
            type: integer
"""
    )
    assert document["openapi"] == "3.1.0"
    operation = document["paths"]["/v1/items/{item_id}"]["get"]
    assert operation["tags"] == ["alpha", "beta"]
    assert operation["parameters"][0]["schema"]["format"] == "uuid"
    assert operation["parameters"][1]["name"] == "limit"


def test_flow_collections_and_scalars() -> None:
    document = loads(
        """
enabled: true
disabled: false
missing: null
quoted: "line\\nbreak"
literal: 'a''b'
flow_list: [one, 2, true, null]
flow_map: {roles: [admin, user], priority: 10}
"""
    )
    assert document["enabled"] is True
    assert document["disabled"] is False
    assert document["missing"] is None
    assert document["quoted"] == "line\nbreak"
    assert document["literal"] == "a'b"
    assert document["flow_list"] == ["one", 2, True, None]
    assert document["flow_map"]["roles"] == ["admin", "user"]
    assert document["flow_map"]["priority"] == 10


def test_comments_document_markers_and_block_scalars() -> None:
    document = loads(
        """
---
description: |
  first line
  second line
summary: >-
  folded text
  continues
...
"""
    )
    assert document["description"] == "first line\nsecond line\n"
    assert document["summary"] == "folded text continues"


def test_unsafe_constructs_are_rejected() -> None:
    with pytest.raises(YamlSubsetError, match="anchors"):
        loads("value: &anchor hello\nother: *anchor\n")
    with pytest.raises(YamlSubsetError, match="custom tags"):
        loads("value: !!python/object/apply:os.system\n")
    with pytest.raises(YamlSubsetError, match="tabs"):
        loads("value:\n\tindented: true\n")
    with pytest.raises(YamlSubsetError, match="duplicate"):
        loads("value: one\nvalue: two\n")
    with pytest.raises(YamlSubsetError, match="directives"):
        loads("%YAML 1.2\n---\nvalue: one\n")
    with pytest.raises(YamlSubsetError, match="multiple YAML documents"):
        loads("---\na: 1\n---\nb: 2\n")


def test_empty_document_and_empty_sequence_item() -> None:
    assert loads("") is None
    assert loads("items:\n  -\n  - value\n") == {"items": [None, "value"]}
