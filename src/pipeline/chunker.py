"""
chunker.py — Phase 5: Code Splitting into Functions / Snippets.

Parses source code files into discrete functions/methods for granular analysis:
  - Python: AST-based parsing (ast.FunctionDef, ast.AsyncFunctionDef) with regex fallback.
  - C / C++: Regex signature detection + brace matching parser.
  - PHP: Function definition regex + brace matching.
  - JavaScript / TypeScript: Function declarations, arrow functions, and method definitions.
  - Go / Java: Function/method pattern matchers.
  - Fallback: Treats whole snippet as 1 chunk if no boundaries are detected.
"""

import ast
import re
from typing import List, Dict, Any


def count_loc(code_snippet: str) -> int:
    """Calculate non-empty Lines of Code (LOC)."""
    if not code_snippet:
        return 0
    lines = [line.strip() for line in code_snippet.splitlines()]
    return sum(1 for line in lines if line and not line.startswith("//") and not line.startswith("#"))


def extract_python_functions(code: str) -> List[Dict[str, Any]]:
    """Extract functions from Python code using AST parsing with regex fallback."""
    chunks = []
    lines = code.splitlines(keepends=True)

    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start_line = node.lineno - 1
                end_line = getattr(node, "end_lineno", len(lines))
                func_code = "".join(lines[start_line:end_line])
                chunks.append({
                    "name": node.name,
                    "code": func_code.strip(),
                    "start_line": node.lineno,
                    "end_line": end_line,
                    "loc": count_loc(func_code),
                })
        if chunks:
            # Sort by appearance order
            chunks.sort(key=lambda x: x["start_line"])
            return chunks
    except Exception:
        pass

    # Regex fallback for Python if AST fails (e.g. syntax error in raw snippet)
    pattern = re.compile(r"^([ \t]*def\s+([a-zA-Z0-9_]+)\s*\([^)]*\)\s*(?:->[^:]+)?:)", re.MULTILINE)
    matches = list(pattern.finditer(code))
    if not matches:
        return []

    for i, m in enumerate(matches):
        start_idx = m.start()
        end_idx = matches[i + 1].start() if i + 1 < len(matches) else len(code)
        func_code = code[start_idx:end_idx].strip()
        func_name = m.group(2)
        start_line = code[:start_idx].count("\n") + 1
        end_line = code[:end_idx].count("\n") + 1
        chunks.append({
            "name": func_name,
            "code": func_code,
            "start_line": start_line,
            "end_line": end_line,
            "loc": count_loc(func_code),
        })

    return chunks


def extract_brace_delimited_functions(code: str, func_pattern: re.Pattern) -> List[Dict[str, Any]]:
    """Extract functions using regex header matching and counting nested braces."""
    chunks = []
    for match in func_pattern.finditer(code):
        start_pos = match.start()
        # Find first non-None matched group as function name
        func_name = next((g for g in match.groups() if g), "anonymous")

        # Find the opening brace '{'
        brace_start = code.find("{", match.end() - 1)
        if brace_start == -1:
            continue

        brace_depth = 1
        curr_pos = brace_start + 1
        n = len(code)
        in_string = False
        string_char = ""
        in_line_comment = False
        in_block_comment = False

        while curr_pos < n and brace_depth > 0:
            char = code[curr_pos]

            if in_line_comment:
                if char == "\n":
                    in_line_comment = False
            elif in_block_comment:
                if char == "*" and curr_pos + 1 < n and code[curr_pos + 1] == "/":
                    in_block_comment = False
                    curr_pos += 1
            elif in_string:
                if char == "\\" and curr_pos + 1 < n:
                    curr_pos += 1  # Skip escaped char
                elif char == string_char:
                    in_string = False
            else:
                if char == "/" and curr_pos + 1 < n and code[curr_pos + 1] == "/":
                    in_line_comment = True
                    curr_pos += 1
                elif char == "/" and curr_pos + 1 < n and code[curr_pos + 1] == "*":
                    in_block_comment = True
                    curr_pos += 1
                elif char in ('"', "'", "`"):
                    in_string = True
                    string_char = char
                elif char == "{":
                    brace_depth += 1
                elif char == "}":
                    brace_depth -= 1

            curr_pos += 1

        if brace_depth == 0:
            func_code = code[start_pos:curr_pos].strip()
            start_line = code[:start_pos].count("\n") + 1
            end_line = code[:curr_pos].count("\n") + 1
            chunks.append({
                "name": func_name,
                "code": func_code,
                "start_line": start_line,
                "end_line": end_line,
                "loc": count_loc(func_code),
            })

    return chunks


def extract_c_cpp_functions(code: str) -> List[Dict[str, Any]]:
    """Extract C/C++ function definitions."""
    # Matches return_type func_name(params) {
    pattern = re.compile(
        r"(?:(?:inline|static|extern|const|unsigned|signed|virtual|void|int|char|long|float|double|bool|struct\s+\w+)\s+)+"
        r"([\w:~]+)\s*\([^;{}]*\)\s*(?:const)?\s*\{",
        re.MULTILINE
    )
    return extract_brace_delimited_functions(code, pattern)


def extract_php_functions(code: str) -> List[Dict[str, Any]]:
    """Extract PHP functions."""
    pattern = re.compile(
        r"(?:(?:public|protected|private|static)\s+)*function\s+([a-zA-Z0-9_]+)\s*\([^)]*\)\s*(?::\s*[a-zA-Z0-9_\\]+)?\s*\{",
        re.MULTILINE
    )
    return extract_brace_delimited_functions(code, pattern)


def extract_js_functions(code: str) -> List[Dict[str, Any]]:
    """Extract JavaScript/TypeScript functions."""
    pattern = re.compile(
        r"(?:(?:async\s+)?function\s+([a-zA-Z0-9_$]+)\s*\([^)]*\)|(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>)\s*\{",
        re.MULTILINE
    )
    chunks = extract_brace_delimited_functions(code, pattern)
    for c in chunks:
        if c["name"] == "anonymous":
            # Disambiguate name from code header
            m = re.search(r"([a-zA-Z0-9_$]+)\s*=", c["code"][:60])
            if m:
                c["name"] = m.group(1)
    return chunks


def extract_go_functions(code: str) -> List[Dict[str, Any]]:
    """Extract Go functions."""
    pattern = re.compile(r"func\s+(?:\([^)]+\)\s+)?([a-zA-Z0-9_]+)\s*\([^)]*\)[^{]*\{", re.MULTILINE)
    return extract_brace_delimited_functions(code, pattern)


def extract_java_functions(code: str) -> List[Dict[str, Any]]:
    """Extract Java class methods and functions."""
    pattern = re.compile(
        r"(?:(?:public|protected|private|static|final|synchronized|abstract|native)\s+)*"
        r"(?:[\w<>\[\],\s]+)\s+([a-zA-Z0-9_]+)\s*\([^;{}]*\)\s*(?:throws\s+[\w\s,]+)?\s*\{",
        re.MULTILINE
    )
    # Filter out class declarations that might have been matched
    raw_chunks = extract_brace_delimited_functions(code, pattern)
    return [c for c in raw_chunks if not c["name"] in ("class", "interface", "enum")]


def extract_ruby_functions(code: str) -> List[Dict[str, Any]]:
    """Extract Ruby method definitions."""
    chunks = []
    lines = code.splitlines()
    in_func = False
    start_line = 0
    func_name = ""
    current_lines = []
    indent_level = 0

    for i, line in enumerate(lines):
        line_num = i + 1
        m = re.match(r"^\s*def\s+([a-zA-Z0-9_!?]+)", line)
        if m and not in_func:
            in_func = True
            func_name = m.group(1)
            start_line = line_num
            current_lines = [line]
            indent_level = 1
            continue

        if in_func:
            current_lines.append(line)
            # Match block open keywords
            if re.search(r"\b(?:def|class|module|if|unless|while|until|for|case|begin|do)\b", line):
                indent_level += 1
            if re.search(r"^\s*end\b", line):
                indent_level -= 1
                if indent_level <= 0:
                    func_code = "\n".join(current_lines)
                    chunks.append({
                        "name": func_name,
                        "code": func_code,
                        "start_line": start_line,
                        "end_line": line_num,
                        "loc": count_loc(func_code),
                    })
                    in_func = False
                    current_lines = []

    return chunks


def split_code_into_functions(code: str, language: str) -> List[Dict[str, Any]]:
    """
    Split source code into functions based on language.
    If no sub-functions are found, returns the entire input as 1 chunk.
    """
    clean_code = (code or "").strip()
    if not clean_code:
        return []

    lang_lower = (language or "").strip().lower()

    extracted: List[Dict[str, Any]] = []

    if lang_lower == "python":
        extracted = extract_python_functions(clean_code)
    elif lang_lower in ("c", "c++", "cpp"):
        extracted = extract_c_cpp_functions(clean_code)
    elif lang_lower == "php":
        extracted = extract_php_functions(clean_code)
    elif lang_lower in ("javascript", "typescript", "js", "ts"):
        extracted = extract_js_functions(clean_code)
    elif lang_lower == "go":
        extracted = extract_go_functions(clean_code)
    elif lang_lower == "java":
        extracted = extract_java_functions(clean_code)
    elif lang_lower in ("ruby", "rb"):
        extracted = extract_ruby_functions(clean_code)

    # Fallback: if no functions were extracted, treat the whole code as a single snippet
    if not extracted:
        loc = count_loc(clean_code)
        # Attempt to find a function or method name across languages
        m = re.search(
            r"(?:(?:public|protected|private|static|def|function|func|fn|void|int|char|bool|[\w<>\[\]]+)\s+)+"
            r"([a-zA-Z0-9_]+)\s*\(",
            clean_code
        )
        # Avoid picking up language keywords as names
        candidate = m.group(1) if m else "main_snippet"
        if candidate in ("if", "for", "while", "switch", "catch", "return", "class", "new"):
            candidate = "main_snippet"

        extracted = [{
            "name": candidate,
            "code": clean_code,
            "start_line": 1,
            "end_line": len(clean_code.splitlines()),
            "loc": loc,
        }]

    return extracted

