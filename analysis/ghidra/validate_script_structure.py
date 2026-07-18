#!/usr/bin/env python3

import ast
import pathlib
import sys


ALLOWED_TOP_LEVEL = (
	ast.Assign,
	ast.Expr,
	ast.FunctionDef,
	ast.Import,
	ast.ImportFrom,
)


def fail(path, message):
	print("%s: %s" % (path, message), file=sys.stderr)
	return 1


def validate(path):
	try:
		source = path.read_text(encoding="ascii")
	except UnicodeDecodeError:
		return fail(path, "script must contain ASCII only")

	lines = source.splitlines()
	if len(lines) < 2 or lines[0] != "# @category Analysis" or not lines[1].startswith("# @description "):
		return fail(path, "missing standard Ghidra script header")

	for line_number, line in enumerate(lines, 1):
		prefix = line[: len(line) - len(line.lstrip(" \t"))]
		if " " in prefix:
			return fail(path, "line %d uses spaces in indentation" % line_number)

	try:
		tree = ast.parse(source, filename=str(path))
	except SyntaxError as error:
		return fail(path, "CPython syntax check failed: %s" % error)

	function_names = set()
	for node in tree.body:
		if not isinstance(node, ALLOWED_TOP_LEVEL):
			return fail(path, "line %d has forbidden module-scope %s" % (node.lineno, type(node).__name__))
		if isinstance(node, ast.FunctionDef):
			function_names.add(node.name)
			if node.name in ("main", "run"):
				return fail(path, "line %d uses a forbidden whole-script wrapper named %s" % (node.lineno, node.name))

	for helper in ("decompile_at", "find_refs_to", "find_and_print_calls_from"):
		if helper not in function_names:
			return fail(path, "missing standard helper %s" % helper)

	if "decomp.dispose()" not in source:
		return fail(path, "missing final decomp.dispose()")
	if "analysis/ghidra/output/" not in source:
		return fail(path, "missing analysis/ghidra/output path")

	print("%s: structural checks passed" % path)
	print("Ghidra Jython execution is still the final compatibility proof")
	return 0


def main():
	if len(sys.argv) != 2:
		print("usage: validate_script_structure.py SCRIPT.py", file=sys.stderr)
		return 2
	return validate(pathlib.Path(sys.argv[1]))


if __name__ == "__main__":
	sys.exit(main())
