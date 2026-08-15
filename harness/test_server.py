import unittest

from harness.server import exact_command, enforce_command_policy, policy_revision


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


if __name__ == "__main__":
    unittest.main()
