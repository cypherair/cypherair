from __future__ import annotations

import unittest

from support import load_script_module


module = load_script_module("asc_start_build", "scripts/asc_start_build.py")


class AscStartBuildTests(unittest.TestCase):
    def test_select_tag_reference_returns_matching_tag_id(self) -> None:
        references = [
            {"id": "branch1", "attributes": {"kind": "BRANCH", "name": "main"}},
            {"id": "tag1", "attributes": {"kind": "TAG", "name": "cypherair-v1.2.9-build3"}},
            {"id": "tag2", "attributes": {"kind": "TAG", "name": "cypherair-v1.2.9-build4"}},
        ]
        self.assertEqual(
            module.select_tag_reference(references, "cypherair-v1.2.9-build4"),
            "tag2",
        )

    def test_select_tag_reference_ignores_branch_with_same_name(self) -> None:
        references = [
            {"id": "branchX", "attributes": {"kind": "BRANCH", "name": "cypherair-v1.2.9-build4"}},
        ]
        with self.assertRaises(module.AscError):
            module.select_tag_reference(references, "cypherair-v1.2.9-build4")

    def test_select_tag_reference_missing_raises(self) -> None:
        with self.assertRaises(module.AscError):
            module.select_tag_reference([], "cypherair-v1.2.9-build4")

    def test_build_ci_build_run_payload_shape(self) -> None:
        payload = module.build_ci_build_run_payload("wf123", "ref456")
        self.assertEqual(
            payload,
            {
                "data": {
                    "type": "ciBuildRuns",
                    "relationships": {
                        "workflow": {"data": {"type": "ciWorkflows", "id": "wf123"}},
                        "sourceBranchOrTag": {
                            "data": {"type": "scmGitReferences", "id": "ref456"}
                        },
                    },
                }
            },
        )


if __name__ == "__main__":
    unittest.main()
