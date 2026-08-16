import unittest
from unittest.mock import AsyncMock, patch

import harness.server as server
from harness.server import (
    cleanup_ephemeral,
    evidence_hash,
    exact_command,
    enforce_command_policy,
    normalize_changed_paths,
    parse_broker_target,
    policy_revision,
    select_validation_commands,
    validate_evidence_identity,
)


class PolicyTest(unittest.TestCase):
    def test_revision_matches_go_canonical_json(self) -> None:
        self.assertEqual(
            policy_revision({"governance": {"displayName": "R&D café"}}),
            "sha256:727b8796285e041589a366e4085dd86d28e4ab4d236c947296108cb097ed00ef",
        )

    def test_exact_command_policy(self) -> None:
        bundle = {
            "spec": {
                "harness": {
                    "commandPolicy": [
                        {
                            "pattern": "^uname -a && python --version$",
                            "decision": "allow",
                        }
                    ]
                }
            }
        }
        enforce_command_policy(bundle, "")
        enforce_command_policy(bundle, "uname -a && python --version")
        with self.assertRaises(PermissionError):
            enforce_command_policy(bundle, "id")

    def test_non_exact_regex_is_rejected(self) -> None:
        self.assertIsNone(exact_command("^(a+)+$"))
        bundle = {
            "spec": {
                "harness": {
                    "commandPolicy": [
                        {"pattern": "^(a+)+$", "decision": "allow"}
                    ]
                }
            }
        }
        with self.assertRaises(ValueError):
            enforce_command_policy(bundle, "")

    def test_validation_selection_is_exact_and_deduplicated(self) -> None:
        command = "python -m unittest discover -s /workspace/tests"
        bundle = {
            "spec": {
                "harness": {
                    "commandPolicy": [
                        {
                            "pattern": "^python -m unittest discover -s /workspace/tests$",
                            "decision": "allow",
                        }
                    ],
                    "validationRules": [
                        {"pathPrefix": "src/", "command": command},
                        {"pathPrefix": "tests/", "command": command},
                    ],
                }
            }
        }
        self.assertEqual(
            select_validation_commands(bundle, ["src/main.py", "tests/test_main.py"]),
            [command],
        )
        with self.assertRaises(PermissionError):
            select_validation_commands(bundle, ["docs/readme.md"])

    def test_evidence_inputs_and_hashes_are_bounded(self) -> None:
        validate_evidence_identity(
            "task-123", "https://example.test/repo", "0123456789abcdef"
        )
        self.assertEqual(
            evidence_hash("ok\n"),
            "sha256:dc51b8c96c2d745df3bd5590d990230a482fd247123599548e0632fdbf97fc22",
        )
        self.assertEqual(
            normalize_changed_paths(["src/a.py", "src/a.py"]), ["src/a.py"]
        )
        with self.assertRaises(ValueError):
            normalize_changed_paths(["../secret"])

    def test_broker_target_is_exact(self) -> None:
        self.assertEqual(
            parse_broker_target("https://example.com/docs"),
            ("example.com", "/docs"),
        )
        for value in (
            "http://example.com/docs",
            "https://example.com:8443/docs",
            "https://example.com/docs?token=x",
        ):
            with self.assertRaises(ValueError):
                parse_broker_target(value)


class CleanupTest(unittest.IsolatedAsyncioTestCase):
    async def test_cleanup_confirms_deletion_after_close_error(self) -> None:
        sandbox = AsyncMock()
        sandbox.close.side_effect = RuntimeError("connection lost")
        with (
            patch.object(server, "delete_sandbox", new=AsyncMock()),
            patch.object(
                server, "wait_for_cleanup", new=AsyncMock(return_value=True)
            ),
        ):
            cleaned_up, error = await cleanup_ephemeral(
                sandbox, "sandbox-a", "pod-a"
            )
        self.assertTrue(cleaned_up)
        self.assertEqual(error, "")

    async def test_cleanup_reports_unconfirmed_state(self) -> None:
        with (
            patch.object(
                server,
                "delete_sandbox",
                new=AsyncMock(side_effect=RuntimeError("delete failed")),
            ),
            patch.object(
                server,
                "wait_for_cleanup",
                new=AsyncMock(side_effect=RuntimeError("lookup failed")),
            ),
        ):
            cleaned_up, error = await cleanup_ephemeral(
                None, "sandbox-a", "pod-a"
            )
        self.assertFalse(cleaned_up)
        self.assertIn("delete failed", error)
        self.assertIn("cleanup verification failed", error)


if __name__ == "__main__":
    unittest.main()
