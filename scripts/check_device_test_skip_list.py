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

Base classes that declare no test methods of their own (DeviceSecurityTestCase,
SecureEnclaveCustodyDeviceTestCase) contribute no runnable tests and are exempt;
the moment such a base declares a `test...` method it becomes a required entry.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
DEVICE_TESTS_DIR = "Tests/DeviceSecurityTests"
TEST_PLAN = "CypherAir-UnitTests.xctestplan"
TEST_TARGET_NAME = "CypherAirTests"
XCTEST_BASE = "XCTestCase"

CLASS_DECLARATION = re.compile(
    r"^[ \t]*(?:@[\w.]+(?:\([^)]*\))?[ \t]+)*"
    r"(?:(?:public|internal|fileprivate|private|final|open)[ \t]+)*"
    r"class[ \t]+(?P<name>\w+)[ \t]*"
    r"(?:<[^>]*>[ \t]*)?"
    r"(?::[ \t]*(?P<inherits>[^{]*?))?[ \t]*\{"
)
TEST_METHOD = re.compile(
    r"^[ \t]*(?:@[\w.]+(?:\([^)]*\))?[ \t]+)*"
    r"(?:(?:public|internal|fileprivate|private|final|open|override|static|class|nonisolated)[ \t]+)*"
    r"func[ \t]+(?P<name>test\w*)[ \t]*\("
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
    first = re.sub(r"<.*", "", first).strip()
    return first or None


def parse_swift_classes(source: str) -> dict[str, dict]:
    """Map class name -> {superclass, declaresTestMethods} for one Swift file."""
    cleaned = strip_swift_noise(source)
    classes: dict[str, dict] = {}
    # Stack of (class name, brace depth at which the class body opened).
    open_classes: list[tuple[str, int]] = []
    depth = 0

    for line in cleaned.splitlines():
        declaration = CLASS_DECLARATION.match(line)
        if declaration:
            name = declaration.group("name")
            classes.setdefault(
                name,
                {
                    "superclass": superclass_of(declaration.group("inherits")),
                    "declaresTestMethods": False,
                },
            )
            open_classes.append((name, depth))
        elif open_classes:
            method = TEST_METHOD.match(line)
            if method:
                classes[open_classes[-1][0]]["declaresTestMethods"] = True

        depth += line.count("{") - line.count("}")
        while open_classes and depth <= open_classes[-1][1]:
            open_classes.pop()

    return classes


def collect_device_test_classes(repo_root: Path) -> dict[str, dict]:
    directory = repo_root / DEVICE_TESTS_DIR
    if not directory.is_dir():
        raise SkipListError(f"device test directory is missing: {DEVICE_TESTS_DIR}")

    classes: dict[str, dict] = {}
    for path in sorted(directory.rglob("*.swift")):
        for name, info in parse_swift_classes(path.read_text(encoding="utf-8")).items():
            info = dict(info)
            info["file"] = path.relative_to(repo_root).as_posix()
            classes[name] = info
    return classes


def is_xctest_case(name: str, classes: dict[str, dict]) -> bool:
    """Follow the superclass chain to XCTestCase, tolerating cycles."""
    seen: set[str] = set()
    current: str | None = name
    while current and current not in seen:
        seen.add(current)
        superclass = classes.get(current, {}).get("superclass")
        if superclass == XCTEST_BASE:
            return True
        current = superclass
    return False


def required_class_names(repo_root: Path) -> list[str]:
    classes = collect_device_test_classes(repo_root)
    return sorted(
        name
        for name, info in classes.items()
        if info["declaresTestMethods"] and is_xctest_case(name, classes)
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
