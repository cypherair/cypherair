#!/usr/bin/env python3
"""Fail closed when a device-only test class is missing from the unit test plan.

Tests/DeviceSecurityTests/ holds the Secure Enclave, biometric, and MIE classes
that must never run in the unit lane: on a machine with a real Secure Enclave
they reach LocalAuthentication and stop the run on a Face ID / Touch ID prompt.
CypherAir-UnitTests.xctestplan keeps them out through a hand-maintained
`skippedTests` list, which is fail-open by construction -- a new class that
nobody adds to the list simply runs.

This check inverts that default: every XCTestCase-derived class under
Tests/DeviceSecurityTests/ that declares test methods must be skipped by name in
the plan, and the run fails with the missing class names when one is not.

The class graph is built from all of Tests/**, not just the device directory,
because device classes routinely extend bases declared elsewhere
(KeyManagementServiceTestCase, TutorialSandboxDefaultsSerializedTestCase,
ProtectedDataFrameworkTestCase, ContactServiceTestCase). Scanning only the
device directory would leave those subclasses unresolvable, and unresolvable
used to mean "not a test class" -- a fail-open hole.

Ambiguity now resolves toward failing: a class declared under
Tests/DeviceSecurityTests/ whose superclass cannot be resolved is treated as
XCTestCase-derived. That can over-report a helper class whose first conformance
is a protocol declared in Sources/ *and* which declares a method literally named
`test...`; the failure names the class, and the fix is to rename the method or
list the class.

Base classes that declare no test methods of their own (DeviceSecurityTestCase,
SecureEnclaveCustodyDeviceTestCase) contribute no runnable tests and are exempt;
the moment such a base declares a `test...` method it becomes a required entry.
Test methods added to a class through `extension DeviceFooTests { ... }` count
toward that class.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = "Tests"
DEVICE_TESTS_DIR = "Tests/DeviceSecurityTests"
TEST_PLAN = "CypherAir-UnitTests.xctestplan"
TEST_TARGET_NAME = "CypherAirTests"
XCTEST_BASES = frozenset({"XCTestCase", "XCTest.XCTestCase"})

MODIFIERS = r"(?:(?:public|internal|fileprivate|private|final|open|package)(?:\([\w ]*\))?\s+)*"
ATTRIBUTES = r"(?:@[\w.]+(?:\([^)]*\))?\s+)*"
# `\s` rather than `[ \t]` throughout: a declaration's inheritance clause and
# its opening brace are routinely wrapped onto later lines.
CLASS_DECLARATION = re.compile(
    r"(?:^|\n)[ \t]*" + ATTRIBUTES + MODIFIERS + r"class\s+(?P<name>\w+)\s*"
    r"(?:<[^>{]*>\s*)?"
    r"(?::\s*(?P<inherits>[^{]*?))?\s*\{",
    re.MULTILINE,
)
EXTENSION_DECLARATION = re.compile(
    r"(?:^|\n)[ \t]*" + ATTRIBUTES + MODIFIERS + r"extension\s+(?P<name>[\w.]+)\s*"
    r"(?:<[^>{]*>\s*)?"
    r"(?::\s*[^{]*?)?\s*\{",
    re.MULTILINE,
)
TEST_METHOD = re.compile(
    r"(?:^|\n)[ \t]*" + ATTRIBUTES
    + r"(?:(?:public|internal|fileprivate|private|final|open|override|static|class|nonisolated|package)\s+)*"
    r"func\s+(?P<name>test\w*)\s*\(",
    re.MULTILINE,
)


class SkipListError(RuntimeError):
    """The device-test skip list could not be read or is incomplete."""


def strip_swift_noise(source: str) -> str:
    """Remove comments and string literal contents so brace counting is sane."""
    output: list[str] = []
    index = 0
    length = len(source)
    block_depth = 0

    while index < length:
        character = source[index]
        pair = source[index : index + 2]

        if block_depth:
            if pair == "/*":
                block_depth += 1
                index += 2
                continue
            if pair == "*/":
                block_depth -= 1
                index += 2
                continue
            output.append("\n" if character == "\n" else " ")
            index += 1
            continue

        if pair == "/*":
            block_depth = 1
            index += 2
            continue
        if pair == "//":
            while index < length and source[index] != "\n":
                index += 1
            continue
        if character == '"':
            # Collapse the literal to an empty string; braces and `func test`
            # inside string content must not influence the scan.
            output.append('""')
            index += 1
            if source[index - 1 : index + 2] == '"""':
                index += 2
                terminator = '"""'
            else:
                terminator = '"'
            while index < length:
                if source[index] == "\\":
                    index += 2
                    continue
                if source[index : index + len(terminator)] == terminator:
                    index += len(terminator)
                    break
                if source[index] == "\n":
                    output.append("\n")
                index += 1
            continue

        output.append(character)
        index += 1

    return "".join(output)


def superclass_of(inherits: str | None) -> str | None:
    """Return the first inherited type, which is the superclass when it is one."""
    if not inherits:
        return None
    first = inherits.split(",")[0].strip()
    first = re.split(r"\bwhere\b", first)[0].strip()
    first = re.sub(r"<.*", "", first).strip()
    return first or None


def _body_end(text: str, open_brace: int) -> int:
    """Index just past the `}` matching the `{` at open_brace."""
    depth = 0
    for index in range(open_brace, len(text)):
        character = text[index]
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return index + 1
    return len(text)


def parse_swift_classes(source: str) -> dict[str, dict]:
    """Map class name -> {superclass, declaresTestMethods} for one Swift file.

    Scoping is offset-based rather than line-based so a declaration whose brace
    sits on a later line is still recognised, and so a test method is credited
    to the innermost type that encloses it.
    """
    cleaned = strip_swift_noise(source)
    classes: dict[str, dict] = {}
    # (name, body start, body end) for every class and every extension body.
    scopes: list[tuple[str, int, int]] = []

    for match in CLASS_DECLARATION.finditer(cleaned):
        name = match.group("name")
        classes.setdefault(
            name,
            {
                "superclass": superclass_of(match.group("inherits")),
                "declaresTestMethods": False,
            },
        )
        open_brace = cleaned.index("{", match.end() - 1)
        scopes.append((name, open_brace, _body_end(cleaned, open_brace)))

    # `extension DeviceFooTests { func testX() }` adds runnable tests to the
    # class without declaring anything inside the class body.
    extension_scopes: list[tuple[str, int, int]] = []
    for match in EXTENSION_DECLARATION.finditer(cleaned):
        name = match.group("name").split(".")[-1]
        open_brace = cleaned.index("{", match.end() - 1)
        extension_scopes.append((name, open_brace, _body_end(cleaned, open_brace)))

    for match in TEST_METHOD.finditer(cleaned):
        position = match.start("name")
        enclosing = [
            (start, name)
            for name, start, end in scopes + extension_scopes
            if start < position < end
        ]
        if not enclosing:
            continue
        # Innermost wins: the scope that opened last still containing this func.
        _, owner = max(enclosing)
        if owner in classes:
            classes[owner]["declaresTestMethods"] = True
        else:
            # An extension of a class declared in another file.
            classes[owner] = {"superclass": None, "declaresTestMethods": True, "extensionOnly": True}

    return classes


def collect_test_classes(repo_root: Path) -> dict[str, dict]:
    """Build the class graph from every Swift file under Tests/**.

    Device classes extend bases declared elsewhere in Tests/, so the graph has
    to span the whole test tree even though the requirement applies only to
    classes declared under Tests/DeviceSecurityTests/.
    """
    tests_root = repo_root / TESTS_DIR
    if not tests_root.is_dir():
        raise SkipListError(f"test directory is missing: {TESTS_DIR}")
    if not (repo_root / DEVICE_TESTS_DIR).is_dir():
        raise SkipListError(f"device test directory is missing: {DEVICE_TESTS_DIR}")

    device_prefix = f"{DEVICE_TESTS_DIR}/"
    classes: dict[str, dict] = {}
    for path in sorted(tests_root.rglob("*.swift")):
        relative = path.relative_to(repo_root).as_posix()
        in_device_dir = relative.startswith(device_prefix)
        for name, parsed in parse_swift_classes(path.read_text(encoding="utf-8")).items():
            entry = classes.setdefault(
                name,
                {
                    "superclass": None,
                    "declaresTestMethods": False,
                    "declaredInDeviceDir": False,
                    "file": None,
                },
            )
            entry["declaresTestMethods"] = entry["declaresTestMethods"] or parsed["declaresTestMethods"]
            if parsed.get("extensionOnly"):
                continue
            entry["superclass"] = parsed["superclass"]
            entry["file"] = relative
            if in_device_dir:
                entry["declaredInDeviceDir"] = True
    return classes


def is_xctest_case(name: str, classes: dict[str, dict]) -> bool:
    """Follow the superclass chain to XCTestCase, failing closed on unknowns.

    A superclass the graph cannot resolve -- declared outside Tests/**, or a
    protocol -- counts as XCTestCase-derived. Guessing "not a test" there is
    what let a device class extending a base from Tests/ServiceTests/ slip past
    the gate.
    """
    seen: set[str] = set()
    current: str | None = name
    while current is not None and current not in seen:
        seen.add(current)
        info = classes.get(current)
        if info is None:
            return True
        superclass = info.get("superclass")
        if superclass is None:
            return False
        if superclass in XCTEST_BASES:
            return True
        current = superclass
    return False


def required_class_names(repo_root: Path) -> list[str]:
    classes = collect_test_classes(repo_root)
    return sorted(
        name
        for name, info in classes.items()
        if info["declaredInDeviceDir"]
        and info["declaresTestMethods"]
        and is_xctest_case(name, classes)
    )


def skipped_class_names(repo_root: Path) -> set[str]:
    plan_path = repo_root / TEST_PLAN
    if not plan_path.is_file():
        raise SkipListError(f"test plan is missing: {TEST_PLAN}")

    try:
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
    except ValueError as error:
        raise SkipListError(f"test plan is not valid JSON: {TEST_PLAN} ({error})") from error

    for test_target in plan.get("testTargets", []):
        if test_target.get("target", {}).get("name") != TEST_TARGET_NAME:
            continue
        # Only whole-class entries count. "Class/testMethod()" leaves the rest of
        # the class running, which is exactly the prompt this gate prevents.
        return {entry for entry in test_target.get("skippedTests", []) if "/" not in entry}

    raise SkipListError(f"{TEST_PLAN} has no test target named {TEST_TARGET_NAME}")


def check(repo_root: Path) -> None:
    required = required_class_names(repo_root)
    if not required:
        raise SkipListError(
            f"no device test classes were found under {DEVICE_TESTS_DIR}; "
            "the parser or the directory layout changed"
        )

    skipped = skipped_class_names(repo_root)
    missing = [name for name in required if name not in skipped]
    if missing:
        listed = "\n".join(f"         - {name}" for name in missing)
        raise SkipListError(
            f"device-only test classes are not skipped by {TEST_PLAN}:\n{listed}\n"
            f"       They would run in the unit lane and stop it on a biometric prompt.\n"
            f'       Add each name to the "skippedTests" array of the {TEST_TARGET_NAME} '
            f"target in {TEST_PLAN}."
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    args = parser.parse_args(argv)

    try:
        check(args.repo_root.resolve())
    except SkipListError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    print(f"every device test class under {DEVICE_TESTS_DIR} is skipped by {TEST_PLAN}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
