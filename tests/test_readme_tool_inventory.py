#!/usr/bin/env python3
from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
EXECUTOR = ROOT / "executor_v2_1.py"
START = "<!-- ACTIVE_TOOL_CATALOGUE_START -->"
END = "<!-- ACTIVE_TOOL_CATALOGUE_END -->"


def annotation_contract_names() -> list[str]:
    tree = ast.parse(EXECUTOR.read_text(encoding="utf-8"), filename=str(EXECUTOR))
    for node in tree.body:
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id == "TOOL_ANNOTATION_CONTRACT":
                value = ast.literal_eval(node.value)
                if not isinstance(value, dict):
                    raise AssertionError("TOOL_ANNOTATION_CONTRACT is not a dict")
                return list(value.keys())
        if isinstance(node, ast.Assign):
            if any(isinstance(t, ast.Name) and t.id == "TOOL_ANNOTATION_CONTRACT" for t in node.targets):
                value = ast.literal_eval(node.value)
                if not isinstance(value, dict):
                    raise AssertionError("TOOL_ANNOTATION_CONTRACT is not a dict")
                return list(value.keys())
    raise AssertionError("TOOL_ANNOTATION_CONTRACT not found")


def documented_rows() -> list[tuple[str, list[str]]]:
    text = README.read_text(encoding="utf-8")
    if text.count(START) != 1 or text.count(END) != 1:
        raise AssertionError("README must contain exactly one active-tool catalogue marker pair")
    section = text.split(START, 1)[1].split(END, 1)[0]
    rows: list[tuple[str, list[str]]] = []
    for line in section.splitlines():
        m = re.match(r"^\| `([a-z0-9_]+)` \| (.*) \|$", line)
        if not m:
            continue
        columns = [part.strip() for part in m.group(2).split(" | ")]
        rows.append((m.group(1), columns))
    return rows


class ReadmeToolInventoryTests(unittest.TestCase):
    def test_catalogue_exactly_matches_registered_tools(self) -> None:
        contract = annotation_contract_names()
        rows = documented_rows()
        names = [name for name, _ in rows]

        self.assertEqual(55, len(contract), "Toolset Revision 9 must contain 55 annotated tools")
        self.assertEqual(len(names), len(set(names)), "README contains a duplicate documented tool")
        self.assertEqual(set(contract), set(names), "README tool set drifted from TOOL_ANNOTATION_CONTRACT")
        self.assertEqual(len(contract), len(names), "README must document every active tool exactly once")

    def test_each_tool_row_has_complete_human_metadata(self) -> None:
        for name, columns in documented_rows():
            self.assertEqual(5, len(columns), f"{name}: expected description/access/effect/lease/boundary")
            description, access, effect, lease, boundary = columns
            self.assertTrue(description, f"{name}: missing description")
            self.assertIn(access, {"Normal", "Admin-only"}, f"{name}: invalid access classification")
            self.assertTrue(effect, f"{name}: missing effect classification")
            self.assertTrue(lease, f"{name}: missing lease classification")
            self.assertTrue(boundary, f"{name}: missing safety boundary")


if __name__ == "__main__":
    unittest.main()
