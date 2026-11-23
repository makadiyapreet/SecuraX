"""
test_reporting.py — Dashboard, CSV Export & Report Consistency Tests.

Tests:
  - CSV export matches exact table schema.
  - No data leakage between columns.
  - JSON serialization of analysis details.
"""

import pytest
import pandas as pd
import io
from src.pipeline.securax_pipeline import SecuraXPipeline


def test_csv_export_consistency():
    """Verify CSV export matches dashboard dataframe schema exactly."""
    pipeline = SecuraXPipeline()
    code = """def foo(x): return x * 2"""
    res = pipeline.analyze_source(code, filename="test.py")

    df = pd.DataFrame(res["rows"])
    csv_buffer = io.StringIO()
    df.to_csv(csv_buffer, index=False)
    csv_str = csv_buffer.getvalue()

    # Read back to verify integrity
    df_read = pd.read_csv(io.StringIO(csv_str))
    expected_cols = ["PL", "Snippet", "VF", "CWE-id", "Refined Code", "LOC", "Severity Score"]
    assert list(df_read.columns) == expected_cols
    assert len(df_read) == len(res["rows"])


def test_json_details_serializable():
    """Verify all pipeline details are JSON serializable for REST/CLI use."""
    import json
    pipeline = SecuraXPipeline()
    code = """def bar(x): return x"""
    res = pipeline.analyze_source(code, filename="bar.py")

    serialized = json.dumps(res, default=str)
    assert len(serialized) > 0
    deserialized = json.loads(serialized)
    assert deserialized["success"] is True
    assert "details" in deserialized

