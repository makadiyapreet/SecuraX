"""
test_function_extraction.py — Unit & Regression Tests for Chunker & Function Extraction.

Tests:
  - Python AST parsing with line number preservation.
  - C/C++ brace-delimited parsing with comments and string literal isolation.
  - PHP, JS/TS, and Go extraction.
  - Whole-file single-snippet fallback.
  - Non-empty LOC counting.
"""

import pytest
from src.pipeline.chunker import (
    split_code_into_functions,
    extract_python_functions,
    extract_c_cpp_functions,
    extract_php_functions,
    extract_js_functions,
    extract_go_functions,
    count_loc,
)


def test_python_ast_extraction():
    """Verify Python AST extraction preserves function names, line numbers, and count."""
    code = """# File header comment
import os

def helper(a, b):
    # Sum values
    return a + b

def process_data(items):
    total = 0
    for i in items:
        total += i
    return total
"""
    chunks = extract_python_functions(code)
    assert len(chunks) == 2
    assert chunks[0]["name"] == "helper"
    assert chunks[0]["start_line"] == 4
    assert chunks[0]["loc"] == 2
    assert chunks[1]["name"] == "process_data"
    assert chunks[1]["start_line"] == 8


def test_c_cpp_extraction_with_braces():
    """Verify C function extractor correctly skips braces in strings and comments."""
    code = """
#include <stdio.h>

/* Block comment with { braces } inside */
void safe_func(int x) {
    printf("String with { fake braces } %d\\n", x);
}

int calculate(int a, int b) {
    if (a > 0) {
        return a + b;
    }
    return b;
}
"""
    chunks = extract_c_cpp_functions(code)
    assert len(chunks) == 2
    names = [c["name"] for c in chunks]
    assert "safe_func" in names
    assert "calculate" in names


def test_php_extraction():
    """Verify PHP function declaration extraction."""
    code = """<?php
function test_one($arg) {
    return $arg * 2;
}

public function test_two($name) {
    echo $name;
}
?>"""
    chunks = extract_php_functions(code)
    assert len(chunks) >= 1
    assert any(c["name"] == "test_one" for c in chunks)


def test_javascript_extraction():
    """Verify JS function and arrow function extraction."""
    code = """
function greet(user) {
    return "Hello " + user;
}

const add = (x, y) => {
    return x + y;
};
"""
    chunks = extract_js_functions(code)
    assert len(chunks) == 2
    names = [c["name"] for c in chunks]
    assert "greet" in names
    assert "add" in names


def test_loc_counting():
    """Verify count_loc ignores empty lines and comments."""
    snippet = """
    // Single line C comment
    # Single line Python comment
    int x = 10;

    int y = 20;
    """
    assert count_loc(snippet) == 2


def test_fallback_on_unstructured_code():
    """Verify single-snippet fallback if code has no function boundary."""
    snippet = "x = 10\ny = 20\nprint(x + y)"
    chunks = split_code_into_functions(snippet, "Python")
    assert len(chunks) == 1
    assert chunks[0]["loc"] == 3

