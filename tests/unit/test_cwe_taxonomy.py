"""
tests/unit/test_cwe_taxonomy.py — Unit tests for CWE Taxonomy 1-to-1 Mapping Integrity.
"""

import pytest
from src.data.cwe_taxonomy import (
    CWE_SEMANTIC_GROUPS,
    CLASS_NAMES,
    CWE_TO_GROUP,
    CWE_METADATA,
    DEFAULT_GROUP_REPRESENTATIVE,
)


def test_fifteen_semantic_groups_exist():
    """Verify exactly 15 MITRE semantic groups are registered in strict order."""
    assert len(CLASS_NAMES) == 15
    assert len(CWE_SEMANTIC_GROUPS) == 15


def test_strict_one_to_one_mapping_no_duplicates():
    """Verify no CWE-id is assigned to more than one semantic group."""
    seen = {}
    duplicates = []
    for group, cwes in CWE_SEMANTIC_GROUPS.items():
        for cwe in cwes:
            if cwe in seen:
                duplicates.append((cwe, seen[cwe], group))
            seen[cwe] = group
    assert not duplicates, f"Duplicate CWE mappings found across groups: {duplicates}"


def test_oob_read_write_separation():
    """Verify CWE-125 is OOB-Read and CWE-787 / CWE-124 are OOB-Write."""
    assert CWE_TO_GROUP.get("CWE-125") == "OOB-Read"
    assert CWE_TO_GROUP.get("CWE-787") == "OOB-Write"
    assert CWE_TO_GROUP.get("CWE-124") == "OOB-Write"


def test_group_representatives_valid():
    """Verify every semantic group has an authoritative representative in that group."""
    for group, rep_cwe in DEFAULT_GROUP_REPRESENTATIVE.items():
        assert group in CWE_SEMANTIC_GROUPS
        assert rep_cwe in CWE_SEMANTIC_GROUPS[group]
        assert rep_cwe in CWE_METADATA


def test_cwe_metadata_integrity():
    """Verify all metadata entries contain required semantic fields."""
    required_keys = {"name", "category", "semantic_group", "description"}
    for cwe_id, meta in CWE_METADATA.items():
        assert required_keys.issubset(meta.keys()), f"{cwe_id} missing required keys"
        assert meta["semantic_group"] in CWE_SEMANTIC_GROUPS

